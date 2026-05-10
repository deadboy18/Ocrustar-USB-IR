# Ocrustar USB IR Blaster — Protocol Reference

Byte-level specification for the Ocrustar / ElkSmart D226 USB IR blaster protocol.

For the reverse engineering narrative, see the main [README](../README.md).

---

## 1. Transport Layer

| Property | Value |
|---|---|
| Bus | USB 2.0 Full Speed |
| Transfer type | Bulk |
| Endpoint OUT | 0x01 |
| Endpoint IN | 0x81 |
| Max packet | 64 bytes |
| VID | 0x045C |
| PID | 0x02AA |

All communication is initiated by the host. The device only sends data in response to host commands.

---

## 2. Byte Mangling

Several protocol fields are **mangled** before transmission: each byte is bit-reversed then bitwise-inverted.

```
mangle(0x38):
  0x38 = 0011 1000
  reverse = 0001 1100 = 0x1C
  invert  = 1110 0011 = 0xE3
```

Fields that are mangled: frequency bytes, payload length bytes, frame checksum.

Fields that are NOT mangled: preamble (0xFF), handshake tokens (0xFC/FA/FE/FD), payload data.

---

## 3. Command Summary

All commands are sent via bulk OUT endpoint. Responses arrive on bulk IN endpoint.

| Command | Bytes (hex) | Direction | Purpose |
|---|---|---|---|
| AUTH | `FC FC FC FC` | OUT | Identify/authenticate device |
| AUTH_ACK | `FA FA FA FA` | OUT | Acknowledge device identity |
| TRANSMIT | `FF FF FF FF ...` | OUT | Send IR data (header + payload) |
| START_LEARN | `FE FE FE FE` | OUT | Enter IR learn mode |
| STOP_LEARN | `FD FD FD FD` | OUT | Exit IR learn mode |
| GET_SN | `FB FB FB FB` | OUT | Request device serial number |

---

## 4. Handshake

```
┌──────┐                      ┌────────┐
│ Host │                      │ Device │
└──┬───┘                      └───┬────┘
   │   FC FC FC FC                │
   │─────────────────────────────>│
   │                              │
   │   FC FC FC FC 02 AA          │
   │<─────────────────────────────│
   │                              │
   │   FA FA FA FA                │
   │─────────────────────────────>│
   │                              │
   │   (ready for commands)       │
```

### Request (host → device)
| Offset | Length | Value | Description |
|---|---|---|---|
| 0 | 4 | `FC FC FC FC` | Hello token |

### Response (device → host)
| Offset | Length | Value | Description |
|---|---|---|---|
| 0 | 4 | `FC FC FC FC` | Echo |
| 4 | 1 | `XX` | Device ID high byte |
| 5 | 1 | `YY` | Device ID low byte |

### Device types
| XX | YY | Type | Notes |
|---|---|---|---|
| `02` | `AA` | D226 | Huffman + pulse compression |
| `70` | `01` | D552 | Pulse compression only |

### Acknowledgment (host → device)
| Offset | Length | Value | Description |
|---|---|---|---|
| 0 | 4 | `FA FA FA FA` | ACK token |

Timing: retry up to 3 times with 200ms timeout per attempt. Flush IN endpoint before first attempt.

---

## 5. IR Transmission

### Message format (before framing)

```
Offset  Length  Description
──────  ──────  ────────────────────────────────
0       4       Preamble: FF FF FF FF
4       1       mangle( (freq + 0x7FFFF) >> 8 )     ← bits 15:8
5       1       mangle( (freq + 0x7FFFF) >> 16 )    ← bits 23:16
6       1       mangle( (freq + 0x7FFFF) )           ← bits 7:0
7       1       mangle( payload_length >> 8 )
8       1       mangle( payload_length )
9       N       Encoded payload
```

### Frequency encoding example

```
freq = 38000 Hz
f = 38000 + 0x7FFFF = 38000 + 524287 = 562287
  = 0x08946F

byte[4] = mangle(0x94)    ← bits 15:8
byte[5] = mangle(0x08)    ← bits 23:16
byte[6] = mangle(0x6F)    ← bits 7:0
```

### Framing

Large messages are split into frames of up to 63 bytes:

```
Frame N (full):     [62 bytes data] [1 byte checksum]  = 63 bytes
Frame N+1 (final):  [remaining bytes, no checksum]     ≤ 62 bytes
```

Checksum for a 62-byte frame:
```
s = sum of all 62 bytes (unsigned)
raw = (s & 0xF0) | ((s >> 8) & 0x0F)
checksum = mangle(raw)
```

### Device response

| Value | Meaning |
|---|---|
| `FF FF FF FF` | Success |
| (no response) | Timeout or error |

---

## 6. Payload Encoding Pipeline

```
Raw timings (µs)
       │
       ▼
┌─────────────────────┐
│  Pulse Compression   │  Dictionary encode top-2 pairs
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Huffman Encoding    │  D226 only (skipped for D552)
└──────────┬──────────┘
           │
           ▼
     Final payload
```

### 5.1 Pulse Compression

**Input**: Array of timing values `[mark₀, space₀, mark₁, space₁, ...]` in µs

**Process**:
1. Group into pairs: `(markₙ, spaceₙ)`
2. Count frequency of each unique pair
3. Select top 2 most frequent pairs
4. Sort by total duration (mark + space): shorter = pair₀, longer = pair₁

**Output format**:
```
[LEB128(pair₁.mark)] [LEB128(pair₁.space)]    ← longer pair first!
[LEB128(pair₀.mark)] [LEB128(pair₀.space)]    ← shorter pair second
[FF] [FF] [FF]                                  ← separator
[encoded_data...]                               ← 00=pair₀, 01=pair₁, else inline
```

**Encoded data bytes**:
| Byte | Meaning |
|---|---|
| `0x00` | Shorthand for pair₀ (shorter pair) |
| `0x01` | Shorthand for pair₁ (longer pair) |
| Other | Start of an inline LEB128-encoded (mark, space) pair |

### 5.2 LEB128 with ÷16 Prescaling

All timing values are prescaled before LEB128 encoding:

```
encoded = LEB128( round(value_µs / 16) )
```

**Exception**: Values ≤ 1 are emitted as-is (these are dictionary indices, not timing values).

**LEB128 encoding**:
```
While value > 0:
  byte = value & 0x7F
  value >>= 7
  if value > 0: byte |= 0x80   (continuation bit)
  if byte == 0xFF: byte = 0xFE  (escape reserved separator)
  emit(byte)
```

**Prescaling examples**:
| Raw (µs) | ÷16 (rounded) | LEB128 |
|---|---|---|
| 560 | 35 | `0x23` |
| 1690 | 106 | `0x6A` |
| 4500 | 281 | `0x99 0x02` |
| 9000 | 563 | `0xB3 0x04` |
| 40000 | 2500 | `0xC4 0x13` |

### 5.3 Huffman Encoding (D226 only)

Applied to the entire pulse-compressed byte stream.

**Tree construction**:
1. Count byte frequencies in compressed data
2. Create leaf node per unique byte
3. Build min-heap using Java `PriorityQueue` semantics
4. Merge two lightest nodes repeatedly until one root remains

**Serialized format**:
```
Offset  Length  Description
──────  ──────  ────────────────────────
0       2       Symbol count (big-endian)
2       3×N     Symbol table: [byte] [weight_hi] [weight_lo]
2+3N    1       Padding bit count (0-7)
3+3N    ...     Huffman-coded bitstream
```

Symbol table is sorted by symbol value (ascending byte order).

**Padding**: The bitstream is padded with zero bits to reach a byte boundary. The padding count byte indicates how many trailing bits to discard during decompression.

---

## 7. IR Learning

### Start learning (host → device)
| Offset | Length | Value |
|---|---|---|
| 0 | 4 | `FE FE FE FE` |

### Captured signal (device → host)
| Offset | Length | Description |
|---|---|---|
| 0 | 4 | `FE FE FE FE` (echo) |
| 4 | 2 | Raw data length (big-endian) |
| 6 | N | Raw timing data |

Data may arrive in multiple USB transfers. Accumulate until `N` bytes received.

### Stop learning (host → device)
| Offset | Length | Value |
|---|---|---|
| 0 | 4 | `FD FD FD FD` |

### Raw timing decoding

```
carry = 0
for each byte b:
    if b < 0xFF:
        timing_µs = b × 16 + carry
        carry = 0
    else:  # b == 0xFF
        carry += 0xFF0  (4080)
```

The carry mechanism allows encoding values larger than 4064µs (254 × 16). Multiple consecutive `0xFF` bytes accumulate before a final value byte resolves the timing.

---

## 8. Serial Number Query

### Request (host → device)
| Offset | Length | Value |
|---|---|---|
| 0 | 4 | `FB FB FB FB` |

### Response (device → host)
| Offset | Length | Description |
|---|---|---|
| 0 | 4 | `FB FB FB FB` (echo) |
| 4 | 6 | ASCII characters (serial prefix) |
| 10 | 3 | Integer values (serial middle) |
| 13 | 1 | ASCII character (serial suffix part 1) |
| 14 | 1 | Integer value (serial suffix part 2) |

Serial string = concatenation of chars[4-9] + int[10] + int[11] + int[12] + char[13] + int[14].

Response is exactly 15 bytes when a serial is available.

---

## 9. Worked Example: NEC Power Command

**Input signal** (NEC, address=0x20, command=0x40):

```
9000, 4500, 560, 1690, 560, 560, 560, 560, 560, 560, 560, 560,
560, 1690, 560, 560, 560, 560, 560, 1690, 560, 1690, 560, 1690,
560, 1690, 560, 1690, 560, 560, 560, 1690, 560, 1690, 560, 560,
560, 560, 560, 560, 560, 560, 560, 1690, 560, 560, 560, 560,
560, 1690, 560, 1690, 560, 1690, 560, 1690, 560, 560, 560, 1690,
560, 1690, 560, 1690, 560, 40000
```

**Stage 1 — Pulse compression**:
- Top pairs: `(560, 560)` count=18, `(560, 1690)` count=14
- pair₀ = (560, 560) — shorter total
- pair₁ = (560, 1690) — longer total
- Header: LEB128(560/16) LEB128(1690/16) LEB128(560/16) LEB128(560/16) FF FF FF
- Header: `23 6A 23 23 FF FF FF`
- Body: `(9000,4500)` inline, then 0x01 0x00 0x00 0x00 0x00 0x01 0x00 ...

**Stage 2 — Huffman**: Byte frequencies counted, tree built, bitstream emitted.

**Stage 3 — Framing**: Preamble + mangled freq + mangled length + payload, split at 62-byte boundaries.

---

## 10. Error Handling

| Situation | Behavior |
|---|---|
| Device not found | Check USB connection, driver (Zadig on Windows) |
| Handshake timeout | Retry up to 3×, check if another process has the device |
| No learn response | Ensure remote is pointed at device, try a different remote |
| Garbled output | Verify device type matches encoding (D226 vs D552) |
| `FF FF FF FF` response to TX | Success (device echoes preamble as ACK) |
