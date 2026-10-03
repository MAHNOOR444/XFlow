# Engineering Work Log: Packet Processing & Distributed SIP Pipeline

**Candidate:** Mahnoor Gulzar  
**Date:** October 2026  
**Assignment:** xFlow Technical Competency Evaluation  
**Repository:** Private Git Repository (`xflow`)  

---

## Executive Summary
This work log documents the systematic engineering approach, implementation methodology, challenges encountered, problem-solving techniques, empirical verification, and analytical takeaways from completing the xFlow technical evaluation. The project implements a complete packet processing engine using `libpcap`, a distributed client-server network architecture, an SQLite3 persistence store, comprehensive GoogleTest unit test suites, and an automated cross-platform CMake build system supporting Ubuntu/CentOS Linux and Windows environments.

---

## 1. Approach and Methodology

Our development philosophy for this assignment followed a test-driven, protocol-compliant, and modular systems engineering workflow:

### A. Information Gathering & Protocol Dissection
1. **Network Packet Inspection:** Before writing code, the capture file `sip-rtp-g729a.pcap` was dissected using Wireshark and `tshark`. We identified:
   - Total packets: **433**
   - Protocol composition: **6 SIP packets**, **425 RTP packets**, and **2 UDP control packets**.
   - Encapsulation: Ethernet II (14 bytes) $\rightarrow$ IPv4 (20 bytes) $\rightarrow$ UDP (8 bytes) $\rightarrow$ Payload.
   - Total header offset to payload: $14 + 20 + 8 = 42\text{ bytes}$ (confirming the hint in the prompt: *"All the packets have the same header length up to the SIP content"*).
2. **SIP Header Semantics (RFC 3261):**
   - SIP messages are ASCII text with CRLF (`\r\n`) line delimitations.
   - Headers of interest: `To:`, `From:`, and `Call-ID:`.
   - Modifying `From:` by prepending a name prefix increases the payload size by $\Delta L = \text{length of prefix}$.
3. **Transport Layer Integrity (RFC 791 & RFC 768):**
   - Changing the payload size invalidates:
     - PCAP packet header: `caplen` (captured length) and `len` (wire length).
     - IPv4 header: `Total Length` field and `Header Checksum`.
     - UDP header: `Length` field and `UDP Checksum` (which covers the 12-byte IPv4 pseudo-header, UDP header, and payload).

### B. Architectural Decomposition
To maintain clean separation of concerns and high testability, the system was decomposed into modular components:
- **`packet_headers.h`**: Strict, packed C-struct representations of Ethernet, IPv4, UDP, and IPv4 Pseudo-Headers.
- **`SipParser`**: Robust extraction and modification of SIP headers, handling compact forms (`f:`, `t:`, `i:`), CRLF preservation, and display name prefixing.
- **`Checksum`**: Clean, portable implementation of the 16-bit one's complement Internet checksum for IPv4 and UDP.
- **`PcapProcessor`**: Libpcap reader and dumper. Selectively processes SIP packets while copying RTP/other packets verbatim.
- **`DatabaseManager`**: SQLite3 wrapper supporting prepared statements, schema initialization, and transactional batch insertions.
- **`Network`**: Cross-platform TCP socket abstraction with length-prefixed framing (preventing TCP stream fragmentation issues).

---

## 2. Challenges and Problems Faced

### Challenge 1: The UDP Checksum Offload Mystery in Original Packets
- **Observation:** When inspecting Packet 1 in the original capture with Wireshark, the UDP checksum was `0x1a0a`, but calculating the RFC 768 checksum over pseudo-header + UDP header + payload yielded `0x19e3`.
- **Root Cause Analysis:** Modern network interface cards (NICs) perform hardware checksum offloading. FreeSWITCH or the host OS generated only the partial pseudo-header checksum, leaving the NIC to fill the rest on transmission. Wireshark explicitly confirmed:  
  `Checksum: 0x1a0a [correct] (matches partial checksum, not 0x19e3, likely caused by "UDP checksum offload")`
- **Solution:** When modifying the packet, the software packet generator must produce a fully compliant, self-contained RFC 768 checksum so that any router, middlebox, or Wireshark without offload assumptions validates it as `[Checksum: Good]`. We implemented the full RFC 768 algorithm, which Wireshark immediately validated with zero errors.

### Challenge 2: Synchronizing Multiple Dependent Header Fields
- **Observation:** In network packet modification, modifying variable-length text (SIP) creates a cascade of dependent fields across multiple layers:
  1. PCAP layer: `pcap_pkthdr.caplen` and `pcap_pkthdr.len`
  2. IP layer: `ip_header->total_length` (in big-endian/network byte order)
  3. IP layer: `ip_header->checksum` (recalculated over 20-byte IP header)
  4. UDP layer: `udp_header->length` (in network byte order)
  5. UDP layer: `udp_header->checksum` (recalculated over pseudo-header + UDP header + payload)
- **Solution:** Designed `net::PcapProcessor` to compute the exact $\Delta L$, allocate a resized buffer, copy the headers, insert the new payload, and recompute lengths and checksums in strict bottom-up order.

### Challenge 3: Windows `min`/`max` Macro Collision with Standard Library
- **Observation:** When compiling `src/sip_parser.cpp` with MSVC on Windows, the compiler reported `error C2589: '(': illegal token on right side of '::'` on `std::min(length, size_t(32))`.
- **Root Cause:** Windows `<windows.h>` and `<winsock2.h>` define `#define min(a,b) (((a)<(b))?(a):(b))` by default.
- **Solution:** Enforced `#define NOMINMAX` prior to including any Windows header and used the safe function call syntax `(std::min)(...)`.

### Challenge 4: Cross-Platform Sockets and Libpcap Linking
- **Observation:** Windows uses Winsock2 (`SOCKET`, `WSAStartup`, `closesocket`), whereas Linux uses POSIX sockets (`int`, `close`). Windows uses Npcap (`wpcap.dll`, `wpcap.lib`), whereas Linux uses `libpcap.so` (`-lpcap`).
- **Solution:** 
  - Abstracted sockets behind `socket_t`, `init_sockets()`, `cleanup_sockets()`, and `close_socket()`.
  - Configured `CMakeLists.txt` to automatically branch between Windows (Npcap SDK + `ws2_32`) and Linux (`find_library(PCAP_LIB NAMES pcap)` + `pthread` + `dl`).
  - Bundled SQLite3 amalgamation (`sqlite3.c`, `sqlite3.h`) to guarantee zero missing-dependency failures on any operating system.

---

## 3. Steps Followed with Descriptions & Snapshots

### Task 0: Git Initialization and Workflow
1. Initialized a local Git repository: `git init -b main`.
2. Created `.gitignore` excluding build artifacts, object files, libraries, temporary PCAPs, and databases.
3. Structured atomic commits mapping to each task requirement.

---

### Task 1: Reading, Modifying, and Writing PCAP Packets

#### Step 1.1: Packet Extraction & Header Verification
We opened `sip-rtp-g729a.pcap` using `pcap_open_offline`. For each packet:
- Checked EtherType == `0x0800` (IPv4).
- Checked IP Protocol == `17` (UDP).
- Checked UDP ports: `src_port == 5060 || dest_port == 5060`.
- Verified SIP method or status signature (`INVITE`, `100 Trying`, `200 OK`, `ACK`, `BYE`).

#### Step 1.2: SIP Header Extraction
We parsed the 6 SIP packets in the trace and extracted `To:`, `From:`, and `Call-ID:`:

| Packet # | Type / Method | Call-ID | To Field | Original From Field |
| :---: | :---: | :---: | :---: | :---: |
| **1** | `INVITE` | `1-24411@10.0.2.20` | `test <sip:test@10.0.2.15:5060>` | `"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1` |
| **2** | `100 Trying` | `1-24411@10.0.2.20` | `test <sip:test@10.0.2.15:5060>` | `"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1` |
| **4** | `200 OK` | `1-24411@10.0.2.20` | `test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH` | `"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1` |
| **5** | `ACK` | `1-24411@10.0.2.20` | `test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH` | `"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1` |
| **432** | `BYE` | `1-24411@10.0.2.20` | `"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1` | `test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH` |
| **433** | `200 OK` | `1-24411@10.0.2.20` | `"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1` | `test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH` |

#### Step 1.3: Prepending Candidate Name Prefix
Using candidate prefix `Mahnoor`:
- Packet 1 From field updated from:
  `"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1`
  to:
  `Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1`
- Packet 432 From field updated from:
  `test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH`
  to:
  `Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH`

#### Step 1.4: Wireshark Verification Snapshot
Running Wireshark's `tshark` engine over the generated `output_modified.pcap`:

```
$ tshark -r output_modified.pcap -Y "frame.number == 1" -o ip.check_checksum:TRUE -o udp.check_checksum:TRUE -V

Frame 1: 511 bytes on wire (4088 bits), 511 bytes captured
Internet Protocol Version 4, Src: 10.0.2.20, Dst: 10.0.2.15
    Total Length: 497
    Header Checksum: 0x3354 [correct]
    [Header checksum status: Good]
    [Calculated Checksum: 0x3354]
User Datagram Protocol, Src Port: 5060, Dst Port: 5060
    Length: 477
    Checksum: 0xf126 [correct]
    [Checksum Status: Good]
    [Calculated Checksum: 0xf126]
Session Initiation Protocol (INVITE)
    From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
    To: test <sip:test@10.0.2.15:5060>
    Call-ID: 1-24411@10.0.2.20
```

**Results:**
- Total packets: **433** (identical to input).
- RTP packets preserved: **425** (unmodified bit-for-bit).
- IP & UDP checksums: **100% Good / Verified**.

---

### Task 2: Client-Server Architecture

#### Step 2.1: Protocol Design
To avoid TCP stream boundary concatenation, we implemented a 4-byte big-endian length prefix framing mechanism:
```
[ 4-byte Length N ] [ N bytes UTF-8 Payload ]
```

#### Step 2.2: Live Execution Log
```
=== SERVER TERMINAL ===
[Server] Listening on port 8088... Waiting for client connection.
[Server] Client connected successfully!
[Server] Sending task assignment to client: ASSIGN_PCAP	sip-rtp-g729a.pcap	output_modified.pcap	Mahnoor
[Server] Waiting for client to process PCAP and return modified data...
[Server] Received modified data from client (1172 bytes)
[Server] Deserialized 6 SIP records.
[Server] Writing records to SQLite database...
[Server] All records committed to database successfully.
[Server] Current total records in database: 6
--- Stored Database Records (6) ---
  [Pkt #1] Call-ID: 1-24411@10.0.2.20 | Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  [Pkt #2] Call-ID: 1-24411@10.0.2.20 | Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  [Pkt #4] Call-ID: 1-24411@10.0.2.20 | Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  [Pkt #5] Call-ID: 1-24411@10.0.2.20 | Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  [Pkt #432] Call-ID: 1-24411@10.0.2.20 | Modified From: Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  [Pkt #433] Call-ID: 1-24411@10.0.2.20 | Modified From: Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
[Server] Workflow completed successfully.

=== CLIENT TERMINAL ===
[Client] Connecting to Server at 127.0.0.1:8088...
[Client] Successfully connected to server!
[Client] Received task assignment from server: ASSIGN_PCAP	sip-rtp-g729a.pcap	output_modified.pcap	Mahnoor
[Client] Executing Task 1:
         Input File:   sip-rtp-g729a.pcap
         Output File:  output_modified.pcap
         Name Prefix:  Mahnoor
[Client] Task 1 Completed successfully!
         Processed 433 total packets.
         Modified  6 SIP packets.
         Preserved 425 RTP packets.
[Client] Sending modified data back to server...
[Client] Server acknowledged: SUCCESS	Inserted 6 records into database.
[Client] Done.
```

---

### Task 3: SQLite3 Database Implementation
We implemented `db::DatabaseManager` with the following schema:
```sql
CREATE TABLE IF NOT EXISTS sip_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_number INTEGER NOT NULL,
    method_or_status TEXT,
    from_field TEXT NOT NULL,
    to_field TEXT NOT NULL,
    call_id TEXT NOT NULL,
    modified_from TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```
- Inserts are executed using prepared statements (`sqlite3_prepare_v2`) and parameterized bindings (`sqlite3_bind_text`, `sqlite3_bind_int`) to prevent injection and maximize throughput.
- Batch inserts are wrapped inside an explicit transaction (`BEGIN TRANSACTION` / `COMMIT`).

---

### Task 4: Google Test Unit Testing

We wrote a suite of 9 tests across 4 test fixtures:
```
[==========] Running 9 tests from 4 test suites.
[----------] Global test environment set-up.
[----------] 2 tests from DatabaseTest
[ RUN      ] DatabaseTest.InsertAndQueryRecords
[       OK ] DatabaseTest.InsertAndQueryRecords (1 ms)
[ RUN      ] DatabaseTest.BulkInsertRecords
[       OK ] DatabaseTest.BulkInsertRecords (0 ms)
[----------] 2 tests from DatabaseTest (3 ms total)

[----------] 3 tests from SipParserTest
[ RUN      ] SipParserTest.IsSipPayloadIdentification
[       OK ] SipParserTest.IsSipPayloadIdentification (0 ms)
[ RUN      ] SipParserTest.ExtractSipFields
[       OK ] SipParserTest.ExtractSipFields (0 ms)
[ RUN      ] SipParserTest.ModifyFromHeaderWithPrefix
[       OK ] SipParserTest.ModifyFromHeaderWithPrefix (0 ms)
[----------] 3 tests from SipParserTest (0 ms total)

[----------] 3 tests from ChecksumTest
[ RUN      ] ChecksumTest.BasicInternetChecksum
[       OK ] ChecksumTest.BasicInternetChecksum (0 ms)
[ RUN      ] ChecksumTest.IPv4HeaderChecksum
[       OK ] ChecksumTest.IPv4HeaderChecksum (0 ms)
[ RUN      ] ChecksumTest.UDPChecksumRFC768
[       OK ] ChecksumTest.UDPChecksumRFC768 (0 ms)
[----------] 3 tests from ChecksumTest (0 ms total)

[----------] 1 test from PcapProcessorTest
[ RUN      ] PcapProcessorTest.ProcessPcapEndToEnd
[       OK ] PcapProcessorTest.ProcessPcapEndToEnd (11 ms)
[----------] 1 test from PcapProcessorTest (11 ms total)

[----------] Global test environment tear-down
[==========] 9 tests from 4 test suites ran. (15 ms total)
[  PASSED  ] 9 tests.
```

---

### Task 5: CMake Build Configuration
Configured standard targets:
- `xflow_core`: Static library containing the engine logic.
- `sqlite3_static`: Static SQLite3 engine.
- `xflow_processor`: Standalone CLI tool.
- `xflow_server`: Server application.
- `xflow_client`: Client application.
- `unit_tests`: GoogleTest runner.
- Integrated CTest via `enable_testing()` and `add_test()`.

---

## 4. Overall Analysis of the Assignment

1. **Practical Telecom & Systems Reality:** This assignment mirrors real-world Session Border Controller (SBC) and VoIP proxy operations. In carrier telecom networks, SIP proxies constantly rewrite `From:`, `To:`, and `Via:` headers (topology hiding, identity manipulation, authentication) and must rewrite IP and UDP checksums in wire-speed pipelines.
2. **Layer Interdependency:** Network software requires strict awareness of layer encapsulation. Modifying an application-layer string (SIP) without understanding its ripple effect on transport (UDP length/checksum), network (IP length/checksum), and capture framing (PCAP caplen) will break downstream systems.
3. **Cross-Platform Robustness:** Writing networking code that compiles with zero warnings and runs identically across Linux (POSIX) and Windows (Winsock/MSVC) requires disciplined abstraction patterns.

---

## 5. Key Takeaways

1. **Verification-Driven Engineering:** Relying on automated external validation (such as `tshark` packet checksum verification) proved invaluable. It removed guesswork and ensured 100% compliance with industry standards.
2. **Defensive Coding in Packet Parsing:** Real-world packets can be malformed or truncated. Always check packet length bounds before accessing struct members (`caplen >= ip_offset + ihl + sizeof(UDPHeader)`).
3. **Test Automation Saves Time:** Setting up Google Test early enabled rapid iteration on checksum calculations and SIP header extraction without manual trial-and-error.
4. **Complete Documentation as Code:** A well-structured project with clear CMake targets, comprehensive documentation, and atomic Git commits allows any engineer or CI/CD system to clone, build, and verify the codebase in minutes.
