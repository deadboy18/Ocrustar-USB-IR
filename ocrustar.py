#!/usr/bin/env python3
"""
ocrustar.py — Open-source driver for the Ocrustar USB IR Blaster

Reverse-engineered protocol implementation for the Ocrustar / ElkSmart
family of USB IR blasters (VID 0x045C, PID 0x02AA).

Supports both D226 (Huffman-compressed) and D552 (legacy) device variants.

Usage:
    python ocrustar.py --learn                          # Capture IR signal
    python ocrustar.py --send-test                      # Send NEC test pattern
    python ocrustar.py --send-raw "9000,4500,560,..."   # Send raw timings (µs)
    python ocrustar.py --freq 40000 --send-raw "..."    # Custom carrier frequency

Requirements:
    pip install pyusb libusb-package

Protocol details: see docs/PROTOCOL.md and README.md

License: MIT
"""

import sys
import time
import argparse
from collections import Counter

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
try:
    import usb.core
    import usb.util
    try:
        import libusb_package
        _backend = libusb_package.get_libusb1_backend()
        print("[OK] Using libusb-package backend")
    except ImportError:
        _backend = None
        print("[OK] Using system libusb")
except ImportError:
    print("ERROR: Missing dependencies. Install with:")
    print("  pip install pyusb libusb-package")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
USB_VID = 0x045C  # Renesas/NEC (borrowed by device)
USB_PID = 0x02AA  # Ocrustar IR Blaster

# Handshake tokens
TOKEN_HELLO     = bytes([0xFC] * 4)
TOKEN_ACK       = bytes([0xFA] * 4)
TOKEN_LEARN_ON  = bytes([0xFE] * 4)
TOKEN_LEARN_OFF = bytes([0xFD] * 4)
TOKEN_PREAMBLE  = bytes([0xFF] * 4)

# Device type identifiers (from handshake response bytes 4-5)
DEVICE_D226 = "d226"   # Newer variant: pulse compression + Huffman
DEVICE_D552 = "d552"   # Older variant: pulse compression only


# ===========================================================================
# Java PriorityQueue Emulator
# ===========================================================================
# The D226 firmware builds its Huffman tree using java.util.PriorityQueue.
# Python's heapq has different tie-breaking behavior, which produces
# different tree shapes and incompatible Huffman codes. This class is a
# faithful port of OpenJDK's PriorityQueue implementation.
# ===========================================================================

class JavaPriorityQueue:
    """Emulates java.util.PriorityQueue with identical tie-breaking."""

    def __init__(self):
        self._queue = []

    def offer(self, item):
        """Insert an item (must have a .weight attribute for comparison)."""
        self._queue.append(item)
        self._sift_up(len(self._queue) - 1, item)

    def poll(self):
        """Remove and return the minimum item, or None if empty."""
        if not self._queue:
            return None
        result = self._queue[0]
        last = self._queue.pop()
        if self._queue:
            self._sift_down(0, last)
        return result

    def _sift_up(self, k, x):
        while k > 0:
            parent = (k - 1) >> 1
            e = self._queue[parent]
            if x.weight >= e.weight:
                break
            self._queue[k] = e
            k = parent
        self._queue[k] = x

    def _sift_down(self, k, x):
        half = len(self._queue) >> 1
        while k < half:
            child = (k << 1) + 1
            c = self._queue[child]
            right = child + 1
            if right < len(self._queue) and c.weight > self._queue[right].weight:
                child = right
                c = self._queue[child]
            if x.weight <= c.weight:
                break
            self._queue[k] = c
            k = child
        self._queue[k] = x

    def __len__(self):
        return len(self._queue)


# ===========================================================================
# Protocol Encoding
# ===========================================================================

def mangle_byte(value):
    """
    Bit-reverse then bitwise-invert a byte.

    Every protocol byte (frequency, length, checksum) passes through this
    transformation before transmission. The firmware applies the inverse
    on reception.

    Example: 0x38 → reverse bits → 0x1C → invert → 0xE3
    """
    v = value & 0xFF
    reversed_bits = 0
    for _ in range(8):
        reversed_bits = (reversed_bits << 1) | (v & 1)
        v >>= 1
    return (~reversed_bits) & 0xFF


def frame_checksum(frame_bytes):
    """
    Compute the checksum for a 62-byte frame.

    Algorithm: sum all 62 bytes, take (low_nibble_of_high_byte | high_nibble),
    then mangle. Only applied to full 62-byte frames; the final short
    frame has no checksum.
    """
    s = sum(b & 0xFF for b in frame_bytes[:62])
    raw = (s & 0xF0) | ((s >> 8) & 0x0F)
    return mangle_byte(raw)


def leb128_encode(value):
    """
    LEB128 encode a timing value WITH mandatory ÷16 prescaling.

    The device hardware operates on 16µs ticks. All timing values (in
    microseconds) must be divided by 16 before encoding. This prescaling
    step is not obvious from the code and is the #1 cause of encoding bugs.

    Special cases:
    - Values ≤ 1 are returned as-is (used for dictionary indices 0x00/0x01)
    - The byte 0xFF is reserved as a separator; any LEB128 output byte
      that would be 0xFF is clamped to 0xFE
    """
    if value <= 1:
        return [value]

    # Prescale: convert µs to 16µs ticks (with rounding)
    scaled = int(value / 16.0 + 0.5)

    result = []
    while True:
        byte = scaled & 0x7F
        scaled >>= 7
        if scaled:
            byte |= 0x80  # set continuation bit
        if (byte & 0xFF) == 0xFF:
            byte = 0xFE   # escape 0xFF (reserved separator)
        result.append(byte & 0xFF)
        if not scaled:
            break
    return result


def compress_pulses(timings):
    """
    Compress IR timing array using pulse-pair dictionary encoding.

    Takes a flat array of [mark, space, mark, space, ...] timing values
    (in microseconds) and compresses it by:

    1. Pairing consecutive mark/space values
    2. Finding the 2 most frequent pairs
    3. Sorting them by total duration (shorter = index 0x00)
    4. Encoding matching pairs as single bytes (0x00 or 0x01)
    5. Encoding non-matching pairs inline with LEB128

    Output format:
        [pair1_mark] [pair1_space]     ← longer pair (index 0x01)
        [pair0_mark] [pair0_space]     ← shorter pair (index 0x00)
        FF FF FF                       ← dictionary/data separator
        [encoded pulse data...]

    Note: pair1 is emitted BEFORE pair0 in the header, despite pair0
    having the lower index. This counter-intuitive ordering matches
    the firmware's expectations.
    """
    # Pair up mark/space values
    pairs = []
    i = 0
    while i < len(timings):
        mark = max(0, timings[i])
        space = max(0, timings[i + 1]) if i + 1 < len(timings) else 10000
        pairs.append((mark, space))
        i += 2

    if not pairs:
        return bytes()

    # Find the 2 most frequent pairs
    freq = Counter(pairs)
    top2 = [p for p, _ in freq.most_common(2)]
    if len(top2) == 1:
        top2.append(top2[0])  # only one unique pair

    # Sort by total duration: shorter pair = index 0, longer = index 1
    top2.sort(key=lambda p: p[0] + p[1])
    pair0, pair1 = top2[0], top2[1]

    # Build output: dictionary header + separator + encoded data
    out = []

    # Dictionary: pair1 first (longer), then pair0 (shorter)
    out.extend(leb128_encode(pair1[0]))
    out.extend(leb128_encode(pair1[1]))
    out.extend(leb128_encode(pair0[0]))
    out.extend(leb128_encode(pair0[1]))

    # Separator
    out.extend([0xFF, 0xFF, 0xFF])

    # Encode each pulse pair
    for pair in pairs:
        if pair == pair0:
            out.append(0x00)
        elif pair == pair1:
            out.append(0x01)
        else:
            # Inline encoding for non-dictionary pairs
            out.extend(leb128_encode(pair[0]))
            out.extend(leb128_encode(pair[1]))

    return bytes(out)


def huffman_encode(data):
    """
    Huffman-encode a byte stream (used by D226 devices only).

    Builds a Huffman tree from byte frequencies using a Java-compatible
    priority queue, serializes the symbol table, and emits the compressed
    bitstream.

    Output format:
        [symbol_count_hi] [symbol_count_lo]    ← 2 bytes
        [sym] [weight_hi] [weight_lo]          ← 3 bytes per symbol
        ...
        [padding_bits]                          ← 1 byte
        [bitstream...]                          ← Huffman-coded data

    The symbol table is sorted by symbol value (ascending). The receiver
    reconstructs the Huffman tree from weights and decompresses the
    bitstream accordingly.
    """
    if not data:
        return data

    # Count byte frequencies
    freq = [0] * 256
    for b in data:
        freq[b & 0xFF] += 1

    # Huffman tree nodes
    class Node:
        def __init__(self, weight):
            self.weight = weight

    class Leaf(Node):
        def __init__(self, weight, symbol):
            super().__init__(weight)
            self.symbol = symbol

    class Branch(Node):
        def __init__(self, left, right):
            super().__init__(left.weight + right.weight)
            self.left = left
            self.right = right

    # Build tree using Java-compatible priority queue
    pq = JavaPriorityQueue()
    for i in range(256):
        if freq[i] > 0:
            pq.offer(Leaf(freq[i], i))

    if len(pq) == 0:
        return data

    while len(pq) > 1:
        left = pq.poll()
        right = pq.poll()
        pq.offer(Branch(left, right))

    # Extract codes via tree traversal
    codes = []

    def walk(node, path=""):
        if isinstance(node, Leaf):
            codes.append((node.symbol, node.weight, path or "0"))
        elif isinstance(node, Branch):
            walk(node.left, path + "0")
            walk(node.right, path + "1")

    walk(pq.poll(), "")

    # Sort by symbol value for serialization
    codes.sort(key=lambda entry: entry[0])
    code_map = {sym: bits for sym, _, bits in codes}

    # Serialize: symbol count + symbol table
    out = [
        (len(codes) >> 8) & 0xFF,
        len(codes) & 0xFF,
    ]
    for sym, weight, _ in codes:
        out.extend([sym & 0xFF, (weight >> 8) & 0xFF, weight & 0xFF])

    # Encode data as bitstream
    bitstring = "".join(code_map[b & 0xFF] for b in data)

    # Pad to byte boundary
    remainder = len(bitstring) % 8
    pad_count = (8 - remainder) % 8
    if pad_count > 0:
        bitstring += "0" * pad_count
    out.append(pad_count & 0xFF)

    # Convert bitstream to bytes
    for i in range(0, len(bitstring), 8):
        out.append(int(bitstring[i:i + 8], 2))

    return bytes(out)


def encode_ir(freq_hz, timings, device_type=DEVICE_D226):
    """
    Full encoding pipeline: timings → compressed → framed USB packets.

    Pipeline:
        1. Pulse compression (dictionary encoding)
        2. Huffman coding (D226 only)
        3. Header prepend (preamble + frequency + length)
        4. Frame splitting (62-byte chunks + checksum)

    Args:
        freq_hz: Carrier frequency in Hz (typically 38000)
        timings: List of mark/space timing values in microseconds
        device_type: "d226" (Huffman) or "d552" (no Huffman)

    Returns:
        List of byte-strings, each a complete USB frame ready to send
    """
    # Stage 1-2: Compress
    compressed = compress_pulses(timings)
    if device_type == DEVICE_D226:
        payload = huffman_encode(compressed)
    else:
        payload = compressed

    # Stage 3: Build header
    f = freq_hz + 0x7FFFF
    message = bytearray([0xFF] * 4)                      # Preamble
    message.append(mangle_byte(f >> 8))                   # Freq byte 1 (bits 15:8)
    message.append(mangle_byte(f >> 16))                  # Freq byte 2 (bits 23:16)
    message.append(mangle_byte(f))                        # Freq byte 3 (bits 7:0)
    message.append(mangle_byte(len(payload) >> 8))        # Length high
    message.append(mangle_byte(len(payload)))             # Length low
    message.extend(payload)

    # Stage 4: Frame splitting
    frames = []
    offset = 0
    while offset < len(message):
        chunk_size = min(62, len(message) - offset)
        if chunk_size == 62:
            # Full frame: 62 data bytes + 1 checksum byte
            buf = bytearray(63)
            buf[:62] = message[offset:offset + 62]
            buf[62] = frame_checksum(buf)
            frames.append(bytes(buf))
        else:
            # Final short frame: no checksum
            frames.append(bytes(message[offset:offset + chunk_size]))
        offset += chunk_size

    return frames


def decode_learned_signal(raw_bytes):
    """
    Decode raw bytes from learn mode into timing values (µs).

    The device encodes timings as single bytes with overflow handling:
    - Byte < 0xFF: timing = byte × 16 + accumulated_carry
    - Byte == 0xFF: carry += 0xFF0 (acts as 4080µs overflow accumulator)
    """
    timings = []
    carry = 0
    for b in raw_bytes:
        v = b & 0xFF
        if v < 0xFF:
            timings.append(v * 16 + carry)
            carry = 0
        else:
            carry += 0xFF0
    return timings


# ===========================================================================
# USB Device Interface
# ===========================================================================

class OcrustarDevice:
    """Interface to the Ocrustar USB IR Blaster."""

    def __init__(self):
        self.device = None
        self.ep_in = None
        self.ep_out = None
        self.device_type = DEVICE_D226  # default, updated during handshake

    def connect(self):
        """Find and claim the USB device. Returns True on success."""
        self.device = usb.core.find(
            idVendor=USB_VID,
            idProduct=USB_PID,
            backend=_backend,
        )
        if not self.device:
            print(f"Device not found (VID=0x{USB_VID:04X} PID=0x{USB_PID:04X})")
            print("  - Is the device plugged in?")
            print("  - On Linux, you may need: sudo or a udev rule")
            print("  - On Windows, install libusb via Zadig")
            return False

        print(f"Found device: VID=0x{USB_VID:04X} PID=0x{USB_PID:04X}")

        # Detach kernel driver if necessary (Linux)
        try:
            if self.device.is_kernel_driver_active(0):
                self.device.detach_kernel_driver(0)
        except (usb.core.USBError, NotImplementedError):
            pass

        try:
            self.device.set_configuration()
        except usb.core.USBError:
            pass

        # Find bulk endpoints
        for ep in self.device.get_active_configuration()[(0, 0)]:
            direction = usb.util.endpoint_direction(ep.bEndpointAddress)
            if direction == usb.util.ENDPOINT_IN:
                self.ep_in = ep
            elif direction == usb.util.ENDPOINT_OUT:
                self.ep_out = ep

        if not self.ep_in or not self.ep_out:
            print("ERROR: Could not find bulk IN/OUT endpoints")
            return False

        print(f"  Endpoints: IN=0x{self.ep_in.bEndpointAddress:02X}"
              f"  OUT=0x{self.ep_out.bEndpointAddress:02X}")
        return True

    def _flush(self):
        """Drain any stale data from the IN endpoint."""
        while True:
            try:
                self.ep_in.read(16384, timeout=10)
            except usb.core.USBError:
                break

    def _write(self, data):
        """Send data to the device."""
        try:
            self.ep_out.write(data, timeout=500)
            return True
        except usb.core.USBError:
            return False

    def _read(self, timeout=150):
        """Read data from the device. Returns bytes or None on timeout."""
        try:
            return bytes(self.ep_in.read(16384, timeout=timeout))
        except usb.core.USBError:
            return None

    def handshake(self):
        """
        Perform the 3-step handshake sequence.

        1. Send FC FC FC FC
        2. Wait for FC FC FC FC XX YY (identifies device type)
        3. Send FA FA FA FA (acknowledge)

        Returns True on success, sets self.device_type.
        """
        print("\n── Handshake ──")
        self._flush()

        for attempt in range(1, 4):
            self._write(TOKEN_HELLO)
            print(f"  → FC FC FC FC (attempt {attempt}/3)")

            for _ in range(5):
                resp = self._read(200)
                if resp and len(resp) >= 6:
                    hex_str = " ".join(f"{b:02X}" for b in resp)
                    print(f"  ← ({len(resp)}B) {hex_str}")

                    if resp[:4] == TOKEN_HELLO:
                        self._write(TOKEN_ACK)
                        print("  → FA FA FA FA (ACK)")
                        time.sleep(0.05)

                        hi, lo = resp[4] & 0xFF, resp[5] & 0xFF
                        if hi == 0x70 and lo == 0x01:
                            self.device_type = DEVICE_D552
                            print("  ✓ Device type: D552 (legacy, no Huffman)")
                        elif hi == 0x02 and lo == 0xAA:
                            self.device_type = DEVICE_D226
                            print("  ✓ Device type: D226 (Huffman compression)")
                        else:
                            print(f"  ✗ Unknown device type: 0x{hi:02X}{lo:02X}")
                            return False
                        return True

        print("  ✗ Handshake timed out")
        return False

    def transmit(self, timings, freq_hz=38000, force_type=None):
        """
        Encode and transmit an IR signal.

        Args:
            timings: List of mark/space values in microseconds
            freq_hz: Carrier frequency (default 38000 Hz)
            force_type: Override device type ("d226" or "d552")
        """
        dtype = force_type or self.device_type
        print(f"\n── Transmit ({dtype}, {freq_hz} Hz, {len(timings)} values) ──")

        frames = encode_ir(freq_hz, timings, dtype)
        print(f"  {len(frames)} frame(s)")

        for i, frame in enumerate(frames):
            hex_str = " ".join(f"{b:02X}" for b in frame)
            print(f"  [{i + 1}] {hex_str}")
            self._write(frame)
            time.sleep(0.002)  # inter-frame delay

        time.sleep(0.05)
        resp = self._read(200)
        if resp:
            hex_str = " ".join(f"{b:02X}" for b in resp)
            print(f"  ← {hex_str}")

        print("  ✓ Done")

    def learn(self, timeout=15):
        """
        Enter learning mode and capture an IR signal.

        Point a remote at the device and press a button. The device
        will capture the signal and return the raw timing data.

        Args:
            timeout: Maximum wait time in seconds (default 15)

        Returns:
            List of timing values in microseconds, or None on failure
        """
        print(f"\n── Learn Mode ({timeout}s timeout) ──")
        print("  Point your remote at the device and press a button...")
        self._flush()

        self._write(TOKEN_LEARN_ON)
        print("  → FE FE FE FE (start learning)")

        expected_len = None
        buf = bytearray()
        t0 = time.time()

        while time.time() - t0 < timeout:
            resp = self._read(300)
            if not resp:
                continue

            if expected_len is not None:
                # Continuation: accumulate data
                buf.extend(resp)
                if len(buf) >= expected_len:
                    break
                continue

            # Look for learn response header
            if (len(resp) > 7
                    and resp[:4] == TOKEN_LEARN_ON):
                expected_len = ((resp[4] & 0xFF) << 8) | (resp[5] & 0xFF)
                buf = bytearray(resp[6:])
                print(f"  ← Header: expecting {expected_len} bytes"
                      f" (got {len(buf)} so far)")
                if len(buf) >= expected_len:
                    break

        # Stop learning mode
        self._write(TOKEN_LEARN_OFF)

        if expected_len and len(buf) >= expected_len:
            timings = decode_learned_signal(buf[:expected_len])
            total_ms = sum(timings) / 1000
            print(f"  ✓ Captured {len(timings)} timing values"
                  f" ({total_ms:.0f} ms total)")
            return timings

        print("  ✗ No signal captured")
        return None

    def close(self):
        """Release the USB device."""
        if self.device:
            usb.util.dispose_resources(self.device)


# ===========================================================================
# CLI
# ===========================================================================

# Standard NEC test pattern (address=0x00, command=0x02)
NEC_TEST_SIGNAL = [
    9000, 4500,
    560, 560, 560, 560, 560, 560, 560, 560,     # address: 0x00
    560, 560, 560, 560, 560, 560, 560, 560,
    560, 1690, 560, 1690, 560, 1690, 560, 1690,  # ~address: 0xFF
    560, 1690, 560, 1690, 560, 1690, 560, 1690,
    560, 560, 560, 1690, 560, 560, 560, 560,     # command: 0x02 (bit 1 set)
    560, 560, 560, 560, 560, 560, 560, 560,
    560, 1690, 560, 560, 560, 1690, 560, 1690,   # ~command: 0xFD
    560, 1690, 560, 1690, 560, 1690, 560, 1690,
    560, 40000,                                    # stop bit + gap
]


def main():
    parser = argparse.ArgumentParser(
        description="Ocrustar USB IR Blaster — open-source driver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s --learn                               Capture IR signal from remote
  %(prog)s --send-test                            Transmit NEC test pattern
  %(prog)s --send-raw "9000,4500,560,560,..."     Transmit custom signal
  %(prog)s --freq 40000 --send-raw "2400,600,..." Custom carrier frequency
  %(prog)s --send-raw "..." --force-d552          Force legacy D552 encoding
        """,
    )
    parser.add_argument(
        "--learn", action="store_true",
        help="Enter learning mode (capture IR signal from a remote)",
    )
    parser.add_argument(
        "--send-test", action="store_true",
        help="Send a standard NEC test signal",
    )
    parser.add_argument(
        "--send-raw", type=str, metavar="TIMINGS",
        help="Send raw IR timings (comma-separated µs values)",
    )
    parser.add_argument(
        "--freq", type=int, default=38000,
        help="Carrier frequency in Hz (default: 38000)",
    )
    parser.add_argument(
        "--force-d552", action="store_true",
        help="Force D552 encoding (skip Huffman stage)",
    )
    args = parser.parse_args()

    print("Ocrustar USB IR Blaster — Open Source Driver")
    print("=" * 46)

    dev = OcrustarDevice()
    if not dev.connect():
        sys.exit(1)

    try:
        if not dev.handshake():
            sys.exit(1)
        print(f"\n✓ Ready (device type: {dev.device_type})")

        force_type = DEVICE_D552 if args.force_d552 else None

        if args.learn:
            timings = dev.learn()
            if timings:
                print("\nCaptured signal (paste this into --send-raw):")
                print(",".join(str(v) for v in timings))

        if args.send_test:
            dev.transmit(NEC_TEST_SIGNAL, args.freq, force_type)

        if args.send_raw:
            timings = [int(x.strip()) for x in args.send_raw.split(",")]
            dev.transmit(timings, args.freq, force_type)

        if not any([args.learn, args.send_test, args.send_raw]):
            print("\nNo action specified. Use one of:")
            print("  --learn       Capture IR signal from a remote")
            print("  --send-test   Send NEC test pattern")
            print("  --send-raw    Send custom IR signal")
            print("\nRun with --help for full usage.")

    finally:
        dev.close()


if __name__ == "__main__":
    main()
