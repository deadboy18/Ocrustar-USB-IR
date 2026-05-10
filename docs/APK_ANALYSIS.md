# Ocrustar APK Reverse Engineering — Complete Protocol Analysis

**App:** Ocrustar Remote Control v6.2.9 (com.payne.okux)
**APK Package:** com.payne.okux.apk (split APK/XAPK from APKPure)
**Decompiler:** JADX 1.5.1
**IR Library:** ELKOTG_release (com.esmart.ir)
**Date:** 2026-05-10

---

## 1. Architecture Overview

The Ocrustar app supports three IR output paths:

1. **USB OTG** — External USB IR blaster dongle (ElkSmart hardware). Managed by `com.esmart.ir.otg.UsbHostManager` and `com.esmart.ir.IROTG`.
2. **BLE** — Bluetooth Low Energy IR blasters. Managed by `yc.bluetooth.androidble.ELKBLEManager`.
3. **Built-in IR** — Phones with a `ConsumerIrManager` hardware IR emitter (e.g. older Samsung, Xiaomi, Huawei). Uses Android's built-in `ConsumerIrManager.transmit()`.

The USB OTG path is the focus of this analysis.

### Key Source Files (Decompiled)

| File | Purpose |
|---|---|
| `com.esmart.ir.otg.UsbHostManager` | USB connection lifecycle, bulk I/O, auth, learn data reception |
| `com.esmart.ir.IROTG` | IR send/learn API, WAVZip+Huffman transmit encoding, bit manipulation |
| `com.esmart.ir.otg.b` (WAVZip.kt) | WAVZip compression — pair deduplication + variable-length encoding |
| `b.a` through `b.f` (HufMZip.java) | Huffman tree builder, encoder, dictionary, comparators |
| `a.a` and `a.b` (IROTG.kt inner) | Timer tasks for chunked USB transmission |
| `com.payne.okux.model.OtgHelper` | High-level OTG send wrapper |
| `com.payne.okux.model.OtgModel` | OTG state/config singleton |
| `com.payne.okux.utils.ArrayUtils` | byte↔int array conversions for IR timing data |
| `com.payne.okux.view.home.HomeActivityKotlin` | USB device validation (VID/PID whitelist) |
| `com.payne.okux.view.newlearn.KeyLearningActivity` | Learn mode UI + test playback |
| `com.payne.okux.model.enu.Magic` | BLE protocol magic byte constants |

---

## 2. USB Device Identification

### VID/PID Whitelist

All supported ElkSmart dongles use **VID = 0x045C** (decimal 1116). The following PIDs are whitelisted in `HomeActivityKotlin.getCheckInterface()`:

| PID (hex) | PID (dec) | Label | Device Tag | Notes |
|---|---|---|---|---|
| 0x02AA | 682 | "old" | `"old"` | Primary target device |
| 0x014A | 330 | "old (229)" | `"old"` | Variant |
| 0x0134 | 308 | "5s" | `"308"` | |
| 0x0195 | 405 | "4s" | `"405"` | |
| 0x0184 | 388 | "foreign trade" | `"388"` | Export/international version |
| 0x0130 | 304 | "304" | `"304"` | |
| 0x0189 | 393 | "393" | `"393"` | |
| 0x018F | 399 | "399" | `"393"` | (shares tag with 393) |
| 0x0131 | 305 | "305" | `"305"` | |
| 0x0132 | 306 | "306" | `"306"` | |
| 0x0133 | 307 | "307" | `"307"` | |

Additionally, VID=0x4348 PID=0x55E0 is explicitly **rejected** (returns false).

Any device not matching the whitelist shows a toast: "PID {pid}, 非合适设备" (illegal device).

### USB Descriptor (from Windows PnP)

```
InstanceId:   USB\VID_045C&PID_02AA\5&33432EA&0&6
FriendlyName: SMART
Manufacturer: SMTCTL
Product:      SMART
Status:       OK
```

### UsbHostManager Setup

The USB host manager is built with these parameters (from `HomeActivityKotlin.initOTG()`):

```kotlin
UsbHostManager.Builder(applicationContext)
    .setIndentify("quandoo", "Android2AndroidAccessory1",
                   "showcasing android2android USB communication",
                   "0.1", "http://quandoo.de", "42")
    .setConnectionListener(getConnectListener())
    .setUsbValidCheckInterface(getCheckInterface())
    .setNeedOrgReadData(true)
    .setReadWriteRate(5)
    .create()
```

Key config values:
- **Read/write rate:** 5 (sleep = 1000/5 - 10 = 190ms between read cycles)
- **Read buffer:** 16384 bytes
- **Bulk transfer timeout:** 100ms
- **Max permission retry:** 2
- **Interface:** 0 (first USB interface)
- **Endpoints:** Bulk IN (direction 0x80) and Bulk OUT (direction 0x00)

---

## 3. USB Protocol — Commands

All commands are sent via bulk OUT endpoint. Responses arrive on bulk IN endpoint.

### Command Table

| Command | Bytes (hex) | Bytes (dec) | Direction | Purpose |
|---|---|---|---|---|
| AUTH | `FC FC FC FC` | 252 252 252 252 | OUT | Identify/authenticate device |
| AUTH_ACK | `FA FA FA FA` | 250 250 250 250 | OUT | Acknowledge device identity |
| START_LEARN | `FE FE FE FE` | 254 254 254 254 | OUT | Enter IR learn mode |
| STOP_LEARN | `FD FD FD FD` | 253 253 253 253 | OUT | Exit IR learn mode |
| GET_SN | `FB FB FB FB` | 251 251 251 251 | OUT | Request device serial number |
| TRANSMIT | `FF FF FF FF ...` | 255 255 255 255 ... | OUT | Send IR data (header + payload) |

### Internal Marker Constants (CommunicationRunnable)

| Field | Value (dec) | Value (hex) | Usage |
|---|---|---|---|
| `e` | 252 | 0xFC | Auth/identify marker |
| `f` | 251 | 0xFB | Serial number marker |
| `g` | 254 | 0xFE | Learn data marker |

---

## 4. Authentication Handshake

### Sequence

```
Host  → Device:  FC FC FC FC
Device → Host:   FC FC FC FC XX YY        (6 bytes)
Host  → Device:  FA FA FA FA              (acknowledge)
```

### Device Type Identification

Bytes XX YY in the response determine the device type:

| Byte 4 (XX) | Byte 5 (YY) | DeviceIdentify Enum | Description |
|---|---|---|---|
| 0x02 | 0xAA | `d571` | Uses Huffman-compressed transmit |
| 0x70 | 0x01 | `d552` | Uses raw WAVZip transmit |

If the response has first 4 bytes = `FA FA FA FA` instead of `FC FC FC FC`, bytes 4-5 contain version data (stored as `originaldeviceIdentify`).

### Auth Retry Logic

The `CommunicationRunnable.run()` loop handles auth:
1. On startup, `access$author()` sends `FC FC FC FC`
2. Sets `v = true` (waiting for auth response)
3. If no response and retry count < 3, resends auth
4. On response, sends `FA FA FA FA` and clears wait flag

---

## 5. Learn Mode Protocol

### Enter Learn Mode

```
Host  → Device:  FE FE FE FE       (start learning)
Host sets: isLearning = true
```

### Learn Data Reception

When `isLearning` is true, the CommunicationRunnable processes incoming data:

**Header packet** (length > 7, first 4 bytes = `FE FE FE FE`):
```
FE FE FE FE [len_hi] [len_lo] [data...]
```
- `expected_length = byte[4] * 256 + byte[5]`
- Data starts at byte[6]

If all data fits in one transfer, parsing happens immediately. Otherwise, `isParseLearing` flag is set and subsequent transfers are accumulated until `expected_length` bytes are collected.

### Learn Data Parsing (CommunicationRunnable.a())

Raw bytes are converted to timing values using run-length encoding:

```
For each byte in raw data:
    if byte < 255:
        timing_µs = (byte × 16) + carry
        emit timing_µs as little-endian 32-bit int
        carry = 0
    else (byte == 255):
        carry += 4080
        (no output — this is a continuation marker for long timings)
```

**Result:** 4 bytes per timing value, little-endian. The byte array is delivered to `onReadLearnedIrData(byte[] mode)`.

### Timing Conversion Back to Integers

`ArrayUtils.byteArrayToIntArray()` converts the byte array back to Integer[] for storage/replay:

```java
// Little-endian 32-bit integers
numArr[i] = ((bArr[i2+3] & 255) << 24) | ((bArr[i2+2] & 255) << 16) 
          | ((bArr[i2+1] & 255) << 8) | (bArr[i2] & 255);
```

### Stop Learn Mode

```
Host  → Device:  FD FD FD FD       (stop learning)
Host sets: isLearning = false
```

---

## 6. Transmit Protocol

### Overview

Transmitting IR data involves a multi-stage encoding pipeline, then chunked USB delivery:

```
Integer[] ir_timings
    → WAVZip compression (com.esmart.ir.otg.b.a())
    → [d571 only] Huffman encoding (b.a HufMZip)
    → Header prepend (FF FF FF FF + freq + length)
    → 62-byte chunking with checksums
    → Sequential bulk USB writes at 2ms intervals
```

### Pre-checks

Before encoding:
1. Data must not be empty
2. Data length must be even (mark/space pairs)
3. Total duration must be < 1,000,000 µs (1 second)
4. No concurrent transmit allowed (`tempIndex` must be 0)

### Default Frequency

`OtgModel.keyIRFreq = 38000` Hz (default for OTG)
`OtgModel.innerFreq = 68000` Hz (default for built-in IR)

---

## 7. WAVZip Encoding (com.esmart.ir.otg.b / WAVZip.kt)

WAVZip is a custom compression scheme that exploits the repetitive nature of IR signals.

### Algorithm

**Step 1: Pair Analysis**

Group consecutive timing values into (mark, space) pairs and count frequencies of each unique pair.

**Step 2: Pair Deduplication** (if ≥ 2 unique pairs)

Find the 2 most frequent pairs (sorted by count descending via comparator `com.esmart.ir.otg.c`). If tied in frequency, sort by total duration ascending (mark + space). Replace occurrences:
- Most frequent shorter pair → integer `0`
- Most frequent longer pair → integer `1`
- All other pairs → leave as raw mark, space values

**Step 3: Value Encoding**

Each integer value is encoded to bytes:

| Value Range | Encoding |
|---|---|
| 0 or 1 | Literal: `0x00` or `0x01` |
| 2 – 2032 | Single byte: `round(value / 16.0 + 0.5)` |
| > 2032 | Variable-length (LEB128-like): 7 data bits per byte, MSB=1 for continuation. If result byte = 0xFF, replaced with 0xFE. |

**Step 4: Output Assembly**

```
[encoded pair1.mark] [encoded pair1.space]    ← longer pair definition
[encoded pair0.mark] [encoded pair0.space]    ← shorter pair definition
FF FF FF                                       ← separator
[encoded data stream]                          ← the compressed IR data
```

The pair definitions let the decoder know what values 0 and 1 represent.

---

## 8. Huffman Encoding (b.* / HufMZip.java) — d571 Only

The d571 device type requires Huffman compression on top of WAVZip. The d552 path skips this step.

### Class Structure

| Class | Role |
|---|---|
| `b.e` | Abstract base node. `f408a` = frequency. Implements `Comparable<e>` (compare by frequency). |
| `b.b` | Leaf node. Extends `e`. Has `f404b` = character value (0-255). |
| `b.c` | Internal node. Extends `e`. Has `f405b` = left child, `c` = right child. Frequency = sum of children. |
| `b.d` | Dictionary entry. `f406a` = frequency, `f407b` = character, `c` = code string. |
| `b.a` | Static tree traversal. Builds dictionary from tree (left=0, right=1). |
| `b.f` | Comparator. Sorts dictionary entries by character value ascending. |

### Tree Construction

```java
PriorityQueue<e> heap = new PriorityQueue<>();
for (int i = 0; i < 256; i++) {
    if (freq[i] > 0) {
        heap.offer(new b(freq[i], (char) i));  // leaf node
    }
}
while (heap.size() > 1) {
    heap.offer(new c(heap.poll(), heap.poll()));  // merge two lowest
}
e root = heap.poll();
```

### Code Generation

Depth-first traversal: left child appends `'0'`, right child appends `'1'`.

### Output Format (Critical for firmware compatibility)

```
[dict_size_hi] [dict_size_lo]     ← number of unique characters (16-bit BE)
[char_0] [freq_hi_0] [freq_lo_0] ← character value + its FREQUENCY (not code length!)
[char_1] [freq_hi_1] [freq_lo_1]
...
[padding_bits]                     ← number of padding bits added to fill last byte
[compressed_byte_0]                ← Huffman-coded bitstream
[compressed_byte_1]
...
```

**CRITICAL:** The dictionary stores the **frequency count** of each character (from the original `e.f408a` node frequency), NOT the Huffman code length. The device firmware uses these frequencies to reconstruct the identical Huffman tree for decoding.

**Dictionary sort order:** Entries are sorted by character value ascending (comparator `b.f` compares `d.f407b`).

### Bitstream Construction

```java
StringBuilder sb = new StringBuilder();
for (Character ch : inputChars) {
    sb.append(codes.get(ch));  // append Huffman code string
}
// Pad to byte boundary
int padding = (8 - sb.length() % 8) % 8;
sb.append("0".repeat(padding));
// Convert to bytes
for (int i = 0; i < sb.length(); i += 8) {
    result.add((byte) Integer.parseInt(sb.substring(i, i+8), 2));
}
```

---

## 9. Transmit Frame Construction

### Header

After encoding (WAVZip + optional Huffman), the payload gets a header prepended. Values are inserted at position 0 (reversed order):

```java
// Frequency encoding: freq + 524287 (0x7FFFF offset)
int freq_adj = frequency + 524287;
int freq_b0 = freq_adj & 0xFF;
int freq_b1 = (freq_adj >> 8) & 0xFF;
int freq_b2 = (freq_adj >> 16) & 0xFF;

// Length of payload
int len_hi = (payload.length >> 8) & 0xFF;
int len_lo = payload.length & 0xFF;
```

### Bit Manipulation

The `IROTG.a(byte)` method reverses bit order of a byte:

```java
static byte reverseBits(byte b) {
    byte result = 0;
    for (int i = 0; i < 8; i++) {
        if (((b >> i) & 1) == 1)
            result |= (1 << (7 - i));
    }
    return result;
}
```

Header bytes are encoded as `~reverseBits(value)` (reverse bits, then bitwise NOT).

### Final Header Layout

After all `add(0, ...)` insertions, the byte order is:

```
Offset  Content
0-3     FF FF FF FF                    (transmit marker)
4       encode(freq_b1)                (~reverseBits of freq byte 1)
5       encode(freq_b2)                (~reverseBits of freq byte 2)
6       encode(freq_b0)                (~reverseBits of freq byte 0)
7       encode(len_hi)                 (~reverseBits of length high byte)
8       encode(len_lo)                 (~reverseBits of length low byte)
9+      [payload data]                 (Huffman-compressed or raw WAVZip)
```

### Chunking

The full frame is split into 62-byte chunks:

```
total_chunks = ceil(data_length / 62)
for each chunk:
    if chunk is exactly 62 bytes:
        append checksum byte (63 bytes total)
    else (last partial chunk):
        no checksum (send as-is)
```

### Checksum Calculation

For a 62-byte chunk:

```java
int sum = sum_of_all_62_bytes;
int combined = (sum & 0xF0) | ((sum >> 8) & 0x0F);
byte checksum = ~reverseBits(combined);
```

### Transmission

Each chunk is sent via `UsbHostManager.write()`, which calls `bulkTransfer()` on the OUT endpoint. A Timer fires every 2ms to send the next chunk:

```java
timer.schedule(new TimerTask() {
    public void run() {
        usbHostManager.write(chunks.get(index));
        index++;
        if (index == chunks.size()) {
            timer.cancel();
            index = 0;
        }
    }
}, 0L, 2L);  // 0ms initial delay, 2ms period
```

---

## 10. Serial Number Protocol

### Request

```
Host → Device:  FB FB FB FB
```

### Response

Response has header `FB FB FB FB` followed by data. If exactly 15 bytes:

```
Offset  Content
0-3     FB FB FB FB       (header)
4-9     6 ASCII chars     (serial prefix)
10-12   3 integer values  (serial middle)
13      1 ASCII char      (serial suffix part 1)
14      1 integer value   (serial suffix part 2)
```

Serial string = `chars[4-9] + int[10] + int[11] + int[12] + char[13] + int[14]`

---

## 11. BLE Protocol (Summary)

The BLE path uses different command bytes:

| Command | Bytes (hex) | Purpose |
|---|---|---|
| BLE Learn | `EC EC EC EC` | Enter learn mode via BLE |
| BLE Stop Learn | `ED ED ED ED` | Stop learn mode via BLE |

BLE data encoding uses `IROTG.getZipDataForBLE()` which is a simplified WAVZip without Huffman:
- Mark values: biased by +2056, divided by 16. Value 0xFF becomes 0xFE. For values ≥ 2024: multiple 0xFF bytes + remainder.
- Space values: divided by 16. Value 0x7F becomes 0x7E. For values ≥ 2032: multiple 0x7F bytes + remainder.

### BLE Magic Constants (from Magic enum)

| Enum | Hex | Dec | Purpose |
|---|---|---|---|
| IR_SINGLE_HEADER | 0xFF | -1 | Single key IR header |
| IR_SINGLE_HEADER_ADDITION | 0xFE | -2 | Header continuation |
| IR_SINGLE_DATA | 0xF0 | -16 | Single key IR data |
| AIR_COND_WHOLE_HEADER | 0xEF | -17 | AC whole frame header |
| TV_WHOLE_HEADER | 0xDF | -33 | TV whole frame header |
| IPTV_WHOLE_HEADER | 0xCF | -49 | IPTV whole frame header |
| TEMP_HUMIDITY_CMD | 0xAA | -86 | Temperature/humidity |
| DIY_LEARN | 0x73 | 115 | DIY learn mode |
| VERSION | 0x76 | 118 | Firmware version query |

---

## 12. Data Storage Format

### Learned IR Data

Learned data is stored as `byte[]` where every 4 bytes represent one little-endian 32-bit integer timing value in microseconds.

**Storage → Replay conversion:**
```java
// byte[] → Integer[] (ArrayUtils.byteArrayToIntArray)
Integer[] timings = new Integer[bytes.length / 4];
for (int i = 0; i < bytes.length; i += 4) {
    timings[i/4] = (bytes[i+3] << 24) | (bytes[i+2] << 16) 
                 | (bytes[i+1] << 8) | bytes[i];
}
```

**Replay → byte[] conversion:**
```java
// Integer[] → byte[] (ArrayUtils.intArrayToByteArray)
byte[] bytes = new byte[timings.length * 4];
for (int i = 0; i < timings.length; i++) {
    bytes[i*4]   = (byte)(timings[i] & 0xFF);
    bytes[i*4+1] = (byte)((timings[i] >> 8) & 0xFF);
    bytes[i*4+2] = (byte)((timings[i] >> 16) & 0xFF);
    bytes[i*4+3] = (byte)((timings[i] >> 24) & 0xFF);
}
```

### Alternate Format (E312 devices)

`byteArrayToIntArrayForE312` uses variable-length integers (varint, 7 bits per byte, MSB continuation) and multiplies each decoded value by 16.

---

## 13. Configuration Defaults (OtgModel)

| Parameter | Value | Source |
|---|---|---|
| `keyIRFreq` | 38000 Hz | OTG IR carrier frequency |
| `innerFreq` | 68000 Hz | Built-in IR carrier frequency |
| `TIMEOUT` | 20000 ms | General operation timeout |
| `readWriteRate` | 5 | USB read cycle rate |
| `maxRequestPermissionTryCount` | 2 | USB permission retry limit |

---

## 14. USB Host Manager Identify Strings

The Builder sets these USB accessory identification strings (used for Android USB accessory protocol):

| Field | Value |
|---|---|
| Manufacturer | "quandoo" |
| Model | "Android2AndroidAccessory1" |
| Description | "showcasing android2android USB communication" |
| Version | "0.1" |
| URI | "http://quandoo.de" |
| Serial | "42" |

These appear to be leftover from a demo/template project.

---

## 15. Complete Transmit Pipeline Example

For a NEC power button signal at 38000 Hz on a d571 device:

```
Input: [9000, 4500, 560, 560, 560, 1690, ...]  (68 timing values)

Step 1 — WAVZip:
  - Pairs: (9000,4500), (560,560), (560,1690), ...
  - Most frequent: (560,560)=16×, (560,1690)=16×
  - Shorter pair (560,560) → 0, Longer pair (560,1690) → 1
  - Output: [encoded_pair1_mark, encoded_pair1_space,
             encoded_pair0_mark, encoded_pair0_space,
             FF, FF, FF,
             encoded_leader, 0, 0, 1, 1, ..., encoded_trail]

Step 2 — Huffman (d571 only):
  - Count byte frequencies in WAVZip output
  - Build Huffman tree
  - Output: [dict_count_hi, dict_count_lo,
             char0, freq_hi0, freq_lo0,
             char1, freq_hi1, freq_lo1,
             ...,
             padding_bits,
             compressed_bitstream_bytes...]

Step 3 — Header:
  - freq_adj = 38000 + 524287 = 562287 = 0x89A6F
  - freq_b0 = 0x6F, freq_b1 = 0x9A, freq_b2 = 0x08
  - FF FF FF FF [enc(b1)] [enc(b2)] [enc(b0)] [enc(len_hi)] [enc(len_lo)] [payload]

Step 4 — Chunk into 62-byte segments with checksums

Step 5 — Send each chunk via bulkTransfer with 2ms interval
```

---

## 16. Debugging Recommendations

### USB Traffic Capture

For debugging USB communication on Windows:
1. Install **USBPcap** (https://desowin.org/usbpcap/)
2. Capture traffic while using the Ocrustar Android app via USB OTG
3. Open capture in **Wireshark** with USB dissector
4. Filter by device address or endpoint

### Driver Notes

- The Zadig tool can replace the default Windows driver with **WinUSB**, which is compatible with libusb/pyusb
- The device presents as a generic USB device with bulk endpoints (not HID, not CDC)
- Interface 0, Endpoint 0x81 (IN), Endpoint 0x01 (OUT)

### Common Issues

1. **Wrong VID/PID:** Earlier scripts used VID=0x10C4 (Silicon Labs). The correct VID is **0x045C**.
2. **Device not found after power cycle:** `pnputil` disable/enable may cause the device to re-enumerate at a different address. Wait 2+ seconds after re-enable.
3. **Auth timeout:** The device may need up to 3 auth attempts (`FC FC FC FC`) before responding.
4. **Transmit not working:** The Huffman dictionary must store **character frequencies**, not code lengths. The device firmware reconstructs the tree from frequencies.

---

## 17. Known Device Models

From APK references and device type enum:

| DeviceIdentify Enum | Description |
|---|---|
| `unkown` | Default/unidentified |
| `d552_old` | Legacy d552 |
| `d552` | Current d552 (PID response 0x70 0x01) |
| `d571` | Current d571 (PID response 0x02 0xAA) |
| `d32X035` | Other model |

---

## 18. App Dependencies

The Ocrustar APK bundles these notable libraries:
- **Realm DB** — Local database for remote configurations
- **Hawk** — SharedPreferences wrapper (stores device type, auth tokens)
- **RxJava / RxAndroid** — Reactive programming for BLE
- **XPopup** — Dialog/popup library
- **UMeng Analytics** — Usage analytics (Chinese market)
- **Jackson** — JSON serialization
- **OkHttp** — HTTP client for cloud IR database

---

## 19. Cloud IR Database — Kookong SDK

The Ocrustar app uses the **Kookong (库控) SDK** as its cloud IR code library. Kookong is a major Chinese IR database provider used by many remote control apps. The app also has its own ElkSmart backend for user account management, DIY remote storage, and OTA updates.

### Hardcoded Credentials

| Credential | Value | Source |
|---|---|---|
| Kookong API Key | `E5B72D808C79E3FB129D6C4EF3B22482` | `App.KooKongKey` |
| Initialization | `KookongSDK.init(context, KooKongKey)` | `App.java:238` |

### API Hosts

| Service | URL | Purpose |
|---|---|---|
| Kookong SDK | `https://sdk2.kookong.com` | IR code database (brands, models, remotes, IR data) |
| ElkSmart API v4.1 | `https://api.elksmart.com/codeLibrary` | User accounts, DIY remotes, OTA updates |
| ElkSmart API v2 | `https://elkapi.elksmart.com/codeLibrary` | Ads, DIY keys, UIR upload |
| Legacy console | `http://console.elksmart.com` | Legacy backend |
| Forum/BBS | `https://bbs.elksmart.com` | User community |
| Support chatbot | `https://www.chatbase.co/chatbot-iframe/VXIZRX-y6vE2sSB6kxwx2` | AI support chat |
| Feedback form | `https://www.wenjuan.com/s/Ibeu6nr/` | User feedback survey |
| Support email | `Alice@ELKsmart.com` | Direct support |

### Kookong SDK IR Database Endpoints

All under `https://sdk2.kookong.com`:

| Endpoint | Purpose |
|---|---|
| `/m/brands` | List appliance brands by category |
| `/m/models` | List remote models for a brand |
| `/m/remotes` | Get remote control layouts |
| `/m/irs` | Get IR data for multiple keys |
| `/m/ir` | Get IR data for a single key |
| `/m/irsinglekey` | Get single key IR code |
| `/m/decodeir` | Decode raw IR signal to protocol |
| `/m/saveir` | Save/upload IR code |
| `/m/rctestkey` | Get test keys for remote matching |
| `/m/samekeyremotes` | Find remotes with matching keys |
| `/m/filterrc` | Filter remote controls |
| `/m/tvboxir` | Set-top box IR codes |
| `/m/stb` | Set-top box database |
| `/m/device` | Device information |
| `/m/address` | Location/region data |
| `/m/sps` | Service provider list |
| `/m/areas` | Area/region list |
| `/m/lineups` | Channel lineup data |
| `/m/lineupid` | Lookup lineup by ID |
| `/m/stbs` | Set-top box list |
| `/m/dvbsremotes` | DVB-S satellite remotes |
| `/m/countrylist` | Supported countries |
| `/m/manuallineup` | Manual lineup matching |
| `/m/programdata` | TV program data |
| `/m/programguide` | Program guide |
| `/m/appver` | App version check |

### ElkSmart Backend Endpoints

All under `https://api.elksmart.com/codeLibrary` or `https://elkapi.elksmart.com/codeLibrary`:

| Endpoint | Auth | Purpose |
|---|---|---|
| `/Oauth/login?mobile=X&code=Y` | None | Phone login (SMS code) |
| `/Oauth/emailLogin?email=X&password=Y` | None | Email login |
| `/Oauth/register?email=X&password=Y&code=Z` | None | Email registration |
| `/Oauth/reset?email=X&password=Y&code=Z` | None | Password reset |
| `/Oauth/sendPhoneSms?mobile=X` | None | Request SMS verification |
| `/Oauth/sendEmailCode?email=X` | None | Request email verification |
| `/Oauth/getAppPoster` | None | Get promotional banners |
| `/Oauth/getAllKeys` | None | Get all DIY key definitions |
| `/app/learn/get` | Token | Get user's learned remotes |
| `/app/learn/batchUpdate` | Token | Batch update learned data |
| `/app/learn/uirUpload` | None | Upload UIR (learned IR data) |
| `/app/learn/deleteUserDiy?uuid=X` | Token | Delete user DIY remote |
| `/app/learn/checkUserIsAutoUpload` | Token | Check auto-upload setting |
| `/app/version/checkUpdate?...` | None | Check for app updates |
| `/app/version/isHasUpdateData?...` | None | Check for data updates |
| `/app/version/getModuleConfig?...` | None | Get module configuration |
| `/app/version/getAdData?...` | None | Get advertisement data |

Authentication uses a bearer token stored in `GlobalData.getInstance().getUserInfo().token`, passed as a header in authenticated requests.

### IR Data Format in Cloud

The UIR (User IR) upload format used by `UirUploadParam`:

```json
{
  "frequency": 38000,
  "irkeys": [
    {
      "keyId": 123,
      "keyName": "power",
      "irData": [9000, 4500, 560, 560, ...]
    }
  ]
}
```

IR data is stored as arrays of timing values in microseconds, identical to the format used by `sendIRDataToExternalDevice()`.

---

## 20. Third-Party Open Source Support

### iodn/android-ir-blaster

The open-source app [android-ir-blaster](https://github.com/iodn/android-ir-blaster) by NeroTeam Security Labs has partial ElkSmart support:

- Added ElkSmart support starting with VID 0x045C, PID 0x0131
- Written in Dart/Flutter with Kotlin native USB code
- Key files: `ElkSmartUsbProtocolFormatter.kt`, `ElkSmartUsbLearner.kt`, `UsbIrTransmitter.kt`
- Supports both D552 (raw WAVZip) and D226 (Huffman) subtypes
- **Note:** PID 0x02AA ("old" model) is detected but transmit may not function — the protocol for this specific model variant may differ

### Protocol Differences Found (iodn vs Ocrustar APK)

| Aspect | Ocrustar APK | iodn Implementation |
|---|---|---|
| Auth ACK | Sends `FA FA FA FA` after identify | Does NOT send ACK |
| Huffman padding byte | Writes padding count (8 - remainder) | Writes remainder (length % 8) |
| Pair sorting | Sorts top-2 pairs by total duration | No duration sort, frequency order only |
| Background reader | Continuous read thread running | No background reader |

---

## 21. Debugging with USBPcap + Wireshark

### Setup on Windows

1. Download USBPcap from `https://desowin.org/usbpcap/`
2. Install and reboot
3. Open **Admin PowerShell**, identify your USB root hub:
   ```
   USBPcapCMD.exe
   ```
   Pick the root hub that has the SMART device listed.

4. Start capture:
   ```
   USBPcapCMD.exe -d \\.\USBPcap1 -o capture.pcapng
   ```

5. In another terminal, run the script:
   ```
   python elksmart_v12.py --send-test
   ```

6. Stop capture with Ctrl+C

7. Open `capture.pcapng` in Wireshark. Useful filters:
   - `usb.transfer_type == 3` — Bulk transfers only
   - `usb.endpoint_address.direction == 0` — OUT (host→device)
   - `usb.endpoint_address.direction == 1` — IN (device→host)
   - `usb.data_len > 0` — Only packets with payload

### What to Look For

- Compare the exact bytes sent by our script vs what the Ocrustar APK would generate
- Check if the device sends any response/NAK after transmit frames
- Verify the auth handshake completes correctly (FC→FC+ACK→FA)
- Look for any additional commands between auth and first transmit in the APK flow

---

*Analysis performed by decompiling com.payne.okux.apk with JADX 1.5.1, tracing USB protocol from UsbHostManager through IROTG to WAVZip and HufMZip encoders. Cloud API analysis from NetworkOkxDB.java and KookongSDK configuration. Third-party protocol comparison from iodn/android-ir-blaster (ElkSmartUsbProtocolFormatter.kt).*
