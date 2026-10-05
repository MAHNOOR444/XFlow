# Engineering Work Log: Packet Processing and Distributed SIP Pipeline

Candidate: Mahnoor
Assignment: xFlow Technical Competency Evaluation
Date: October 2026

---

## 1. Assignment Goals and Scope

The goal of this assignment was to build a complete, production-grade network packet processing utility and distributed client-server pipeline in C++17. The project involves low-level network packet parsing, SIP application-layer string manipulation, transport and network layer checksum recalculations, reliable client-server socket communication, relational database persistence with SQLite, and comprehensive unit testing.

The work was divided into six core areas:
- Task 0: Version control setup using Git with a clean commit history and proper dependency management.
- Task 1: Standalone PCAP processor using libpcap / Npcap. The engine reads sip-rtp-g729a.pcap, identifies SIP packets on UDP port 5060, parses the To, From, and Call-ID headers, prepends the candidate name prefix (Mahnoor) to the From field, recomputes IPv4 and UDP lengths and checksums, and dumps the modified stream to output_modified.pcap while leaving RTP audio packets untouched.
- Task 2: Distributed client-server architecture. The server sends a task assignment command over a TCP socket, the client receives the command, runs the packet processing routine, and streams the extracted SIP records back to the server.
- Task 3: SQLite database persistence. The server stores all extracted SIP metadata (packet number, method/status, Call-ID, To, From, modified From, and timestamps) in an SQLite database file named sip_records.db.
- Task 4: Unit testing with Google Test covering database queries, SIP parsing, From field modification, Internet checksum calculations, and end-to-end PCAP processing.
- Task 5: Cross-platform CMake build configuration supporting Windows (MSVC) and Linux (GCC/Clang).

---

## 2. System Architecture and Engineering Approach

### Packet Layering Analysis

Before writing any code, I analyzed the provided capture file sip-rtp-g729a.pcap using Wireshark and tshark to understand the packet structure:
- Total packet count: 433 packets.
- Protocol breakdown: 6 SIP signaling packets, 425 RTP media packets carrying G.729 audio, and 2 UDP control packets.
- Layer encapsulation:
  1. Ethernet II frame: 14 bytes (destination MAC, source MAC, EtherType 0x0800 for IPv4).
  2. IPv4 header: 20 bytes (protocol 17 for UDP, standard header length of 5 32-bit words).
  3. UDP header: 8 bytes (source port, destination port, length, checksum).
  4. Payload: Starts at offset 14 + 20 + 8 = 42 bytes from the beginning of the frame.
  This confirms the prompt specification that all packets share an identical 42-byte header offset up to the SIP or RTP content.

### SIP Protocol Considerations (RFC 3261)

SIP is a plain-text protocol structured similarly to HTTP. Lines are terminated by CRLF (\r\n), and the message header block is separated from the optional SDP body by an empty line (\r\n\r\n).
Key headers requiring extraction:
- Call-ID (or compact form i): Unique dialog identifier.
- From (or compact form f): Caller identity, containing display name, URI, and tags.
- To (or compact form t): Callee identity.

When modifying the From field:
- The candidate name prefix (Mahnoor) must be prepended directly to the content following From: .
- Example: From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1 becomes From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1.
- Prepending this prefix increases the payload length by exactly 7 bytes (the character length of Mahnoor).
- All other headers, header order, and any attached SDP session descriptors must remain intact.

### Checksum and Length Mechanics (RFC 791 and RFC 768)

Because the SIP payload size changes, several higher-layer and lower-layer fields become invalid and must be updated in a bottom-up sequence:
1. Application layer: Payload length increases by delta L.
2. UDP layer (RFC 768):
   - UDP length field must be set to sizeof(UDPHeader) + new_payload_length.
   - UDP checksum must be recalculated over a 12-byte IPv4 pseudo-header (source IP, destination IP, zero byte, protocol 17, UDP length), followed by the 8-byte UDP header (with checksum set to zero during calculation), followed by the new payload.
3. IPv4 layer (RFC 791):
   - Total length field must be set to ip_header_length + sizeof(UDPHeader) + new_payload_length.
   - IPv4 header checksum must be recalculated over the 20-byte IP header (with checksum field set to zero during calculation) using the standard 16-bit one's complement algorithm (RFC 1071).
4. PCAP packet framing:
   - Captured length (caplen) and wire length (len) in the pcap_pkthdr structure must both be incremented by delta L before dumping to disk.

---

## 3. Detailed Task-by-Task Implementation

### Task 0: Repository Organization and Git Setup

I initialized a clean Git repository and configured a comprehensive .gitignore file.
Key considerations:
- Excluded compiler output folders (build/, out/, .vs/).
- Excluded intermediate object files (.o, .obj), temporary binaries (.exe, .dll), and generated test artifacts.
- Bundled the essential 64-bit Npcap SDK import library (third_party/npcap-sdk/Lib/x64/wpcap.lib) and SQLite3 amalgamation (third_party/sqlite3/sqlite3.c and sqlite3.h) directly in the repository so the project compiles on fresh Windows and Linux setups without missing dependencies.

### Task 1: Standalone PCAP Processor

Implemented in src/main.cpp, src/pcap_processor.cpp, src/sip_parser.cpp, and src/checksum.cpp.

Packet Processing Logic:
1. Opens the input capture file using pcap_open_offline().
2. Initializes the output writer using pcap_dump_open().
3. Loops through each packet using pcap_next_ex():
   - Validates minimum Ethernet frame size.
   - Inspects EtherType to ensure IPv4 (0x0800).
   - Inspects IP protocol to ensure UDP (17).
   - Inspects UDP ports. If either port is 5060, the packet is checked for SIP text signatures (such as INVITE, SIP/2.0, ACK, BYE).
   - If identified as SIP:
     - Extracts To, From, and Call-ID values.
     - Prepends Mahnoor to the From header.
     - Allocates a resized packet buffer to accommodate the new payload size.
     - Copies Ethernet, IP, and UDP headers into the new buffer.
     - Copies the modified SIP payload into place.
     - Updates IP total length and calls compute_ipv4_checksum().
     - Updates UDP length and calls compute_udp_checksum().
     - Updates pcap_pkthdr lengths and writes the modified packet via pcap_dump().
   - If identified as RTP or control packet:
     - Preserves the packet exactly as captured and writes it to the output file without modification.
4. Closes both the capture handle and the dumper.

### Task 2: Client-Server Network Pipeline

Implemented in src/server_main.cpp, src/client_main.cpp, and src/network.cpp.

Network Protocol and Framing:
TCP is a byte-stream protocol without built-in message boundaries. To prevent message concatenation or partial read issues, I implemented a 4-byte big-endian length prefix framing mechanism:
- Every transmitted message begins with 4 bytes indicating payload length N in network byte order.
- The receiver reads exactly 4 bytes first, decodes the length, and then loops until all N bytes of the payload have arrived.

Execution Flow:
1. The server binds to port 8088 and listens for connections.
2. The client connects to the server IP and port.
3. The server sends the assignment string formatted with tab delimiters:
   ASSIGN_PCAP <input_file> <output_file> <name_prefix>
4. The client parses the command, runs PcapProcessor on the specified file, and collects extracted SipRecord structures.
5. The client serializes the records into a structured text format and sends them to the server over the TCP socket.
6. The server receives the records, deserializes them, stores them in SQLite, and sends a confirmation ACK back to the client.

### Task 3: SQLite Database Persistence

Implemented in src/database_manager.cpp and include/database_manager.h.

Database Design:
The SQLite database stores each extracted SIP message in the table sip_records:

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

Key Implementation Points:
- Uses sqlite3_prepare_v2() and parameterized bindings (sqlite3_bind_text, sqlite3_bind_int) to ensure safe SQL execution.
- Wraps batch insertions in a single transaction (BEGIN TRANSACTION / COMMIT) for performance.
- Provides query helpers (query_all(), query_by_call_id(), get_record_count()) used by the server to display stored records immediately after processing.

### Task 4: Unit Testing with Google Test

The test suite is located in tests/ and covers all critical modules:
- test_checksum.cpp: Tests 16-bit Internet checksum calculation, RFC 791 IPv4 header checksum verification against known Wireshark ground truth, and RFC 768 UDP pseudo-header checksum generation.
- test_sip_parser.cpp: Tests SIP message identification, header extraction (To, From, Call-ID), and display name prefix modification.
- test_database.cpp: Tests in-memory SQLite table creation, record insertion, querying by Call-ID, and transactional bulk insertion.
- test_pcap_processor.cpp: Tests end-to-end processing of sip-rtp-g729a.pcap, validating packet counts (433 total, 6 SIP modified, 425 RTP preserved) and output file creation.

### Task 5: Cross-Platform Build System

CMakeLists.txt provides clean cross-platform compilation:
- On Windows: Links against bundled third_party/npcap-sdk/Lib/x64/wpcap.lib and ws2_32.lib.
- On Linux: Detects system libpcap via find_library() and links pthread and dl.
- Bundles the SQLite amalgamation in third_party/sqlite3/ to eliminate external database installation requirements.
- Uses FetchContent to automatically download and build Google Test v1.14.0 during compilation.
- Copies the input PCAP file next to the test and processor executables in a post-build step so tests run without manual file copying.

---

## 4. Technical Challenges Encountered and Solutions

### Challenge 1: The UDP Checksum Offload Discrepancy in Original Packets

Observation:
When inspecting Packet 1 in the original capture sip-rtp-g729a.pcap with Wireshark, the recorded UDP checksum was 0x1a0a. However, calculating the RFC 768 checksum manually over the pseudo-header, UDP header, and payload yielded 0x19e3.

Investigation:
Modern network interface cards (NICs) use hardware checksum offloading. When capturing on the transmitting host (or when generated by tools like SIPp / FreeSWITCH), the OS generates a partial checksum, leaving the NIC hardware to compute the final value on transmission. Wireshark flags this explicitly:
Checksum: 0x1a0a [correct] (matches partial checksum, not 0x19e3, likely caused by UDP checksum offload)

Solution:
When rewriting the packet in software, we cannot rely on hardware offload assumptions because the resulting PCAP may be inspected on systems without offload heuristics. I implemented the complete, standard RFC 768 algorithm:
1. Construct the 12-byte IPv4 pseudo-header (Source IP, Destination IP, 0x00, Protocol 17, UDP Length).
2. Set udp_header->checksum = 0.
3. Compute the 16-bit one's complement Internet checksum across the pseudo-header, UDP header, and modified payload.
4. If the computed checksum evaluates to 0x0000, invert to 0xFFFF (as required by RFC 768 to distinguish calculated zero from checksum disabled).
5. Wireshark immediately validated the newly generated checksum (0xf126) as 100% Good and correct.

### Challenge 2: Synchronizing Multi-Layer Dependent Header Fields

Observation:
Modifying a text field in SIP alters the payload size by delta L. This changes multiple dependent header values across layers 2, 3, and 4:
- PCAP frame level: caplen and len.
- IPv4 level: total_length and checksum.
- UDP level: length and checksum.

Solution:
I designed PcapProcessor to calculate delta L dynamically, allocate a new buffer of size original_caplen + delta L, copy the existing headers, append the modified SIP payload, and then recalculate the length and checksum fields in strict order:
1. Update IPv4 total_length = htons(ihl + sizeof(UDPHeader) + new_payload_len).
2. Calculate and store IPv4 checksum.
3. Update UDP length = htons(sizeof(UDPHeader) + new_payload_len).
4. Calculate and store UDP checksum with the pseudo-header.
5. Update pcap_pkthdr caplen and len.

### Challenge 3: Windows NOMINMAX Macro Collision

Observation:
When compiling on Windows with MSVC, including winsock2.h or windows.h caused errors in src/sip_parser.cpp:
error C2589: '(': illegal token on right side of '::'
on calls to std::min(length, size_t(32)).

Cause:
Windows header files historically define min and max as preprocessor macros, colliding with the C++ standard library std::min and std::max.

Solution:
1. Added #define NOMINMAX before including any Windows header in include/packet_headers.h.
2. Wrapped std::min calls in parentheses: (std::min)(length, size_t(32)) to prevent macro expansion.

### Challenge 4: Cross-Platform Socket Abstraction and Npcap Linking

Observation:
Windows and Linux handle networking differently:
- Windows requires WSAStartup(), WSACleanup(), uses SOCKET (an unsigned type), closesocket(), and WSAGetLastError().
- Linux uses POSIX sockets (int), close(), and errno.
- Windows requires wpcap.lib from Npcap SDK, while Linux links -lpcap.

Solution:
1. Created include/network.h with platform-agnostic type definitions (socket_t, INVALID_SOCKET_VALUE, SOCKET_ERROR_CODE).
2. Implemented net::init_sockets(), net::cleanup_sockets(), and net::close_socket() that compile the correct platform calls conditionally.
3. Bundled 64-bit Npcap SDK import libraries in third_party/npcap-sdk/Lib/x64/ so Windows builds succeed without requiring manual SDK path configuration.

---

## 5. Packet Dissection and Wireshark Verification Data

### Extracted and Modified SIP Packets

The input capture contains 6 SIP messages out of 433 total packets:

Table of SIP Packets:
- Packet 1: Method INVITE, Call-ID 1-24411@10.0.2.20
  To: test <sip:test@10.0.2.15:5060>
  Original From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1

- Packet 2: Method 100 Trying, Call-ID 1-24411@10.0.2.20
  To: test <sip:test@10.0.2.15:5060>
  Original From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1

- Packet 4: Method 200 OK, Call-ID 1-24411@10.0.2.20
  To: test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  Original From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1

- Packet 5: Method ACK, Call-ID 1-24411@10.0.2.20
  To: test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  Original From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1

- Packet 432: Method BYE, Call-ID 1-24411@10.0.2.20
  To: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Original From: test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  Modified From: Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH

- Packet 433: Method 200 OK, Call-ID 1-24411@10.0.2.20
  To: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Original From: test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  Modified From: Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH

### Wireshark / TShark Checksum Status Verification

Running tshark with explicit checksum validation enabled:

Command:
```bat
"C:\Program Files\Wireshark\tshark.exe" -r output_modified.pcap -Y "sip" -o ip.check_checksum:TRUE -o udp.check_checksum:TRUE -T fields -e frame.number -e ip.checksum.status -e udp.checksum.status
```

Output:
```
1    1    1
2    1    1
4    1    1
5    1    1
432  1    1
433  1    1
```

Interpretation:
In Wireshark, status code 1 corresponds to Good (checksum matched calculated value). Both IP and UDP checksums across all 6 modified SIP packets are verified Good.

Detailed inspection of Frame 1:
```
Frame 1: 511 bytes on wire, 511 bytes captured
Internet Protocol Version 4, Src: 10.0.2.20, Dst: 10.0.2.15
    Total Length: 497
    Header Checksum: 0x3354 [correct]
    [Header checksum status: Good]
User Datagram Protocol, Src Port: 5060, Dst Port: 5060
    Length: 477
    Checksum: 0xf126 [correct]
    [Checksum Status: Good]
Session Initiation Protocol (INVITE)
    From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
    To: test <sip:test@10.0.2.15:5060>
    Call-ID: 1-24411@10.0.2.20
```

### RTP Packet Integrity

- Total RTP packets in original trace: 425 packets.
- Total RTP packets in modified trace: 425 packets.
- Verified that ports (source 28120, destination 6000 and reverse), sequence numbers, timestamps, payload type (G.729, PT=18), and binary payload data are byte-for-byte identical to the original capture.

---

## 6. Live Execution Logs

### Standalone Processor (Task 1)

```
> .\build\Release\xflow_processor.exe sip-rtp-g729a.pcap output_modified.pcap Mahnoor
Starting PCAP processing:
  Input:  sip-rtp-g729a.pcap
  Output: output_modified.pcap
  Prefix: Mahnoor

Processing completed successfully.
Total packets: 433
SIP packets modified: 6
RTP packets preserved: 425
Other packets: 2

Extracted SIP records (6):
Packet #1 [INVITE sip:test@10.0.2.15:5060 SIP/2.0]
  Call-ID: 1-24411@10.0.2.20
  To: test <sip:test@10.0.2.15:5060>
  Original From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
Packet #2 [SIP/2.0 100 Trying]
  Call-ID: 1-24411@10.0.2.20
  To: test <sip:test@10.0.2.15:5060>
  Original From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
Packet #4 [SIP/2.0 200 OK]
  Call-ID: 1-24411@10.0.2.20
  To: test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  Original From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
Packet #5 [ACK sip:test@10.0.2.15:5060 SIP/2.0]
  Call-ID: 1-24411@10.0.2.20
  To: test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  Original From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
Packet #432 [BYE sip:sipp@10.0.2.20:5060 SIP/2.0]
  Call-ID: 1-24411@10.0.2.20
  To: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Original From: test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  Modified From: Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
Packet #433 [SIP/2.0 200 OK]
  Call-ID: 1-24411@10.0.2.20
  To: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Original From: test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  Modified From: Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH

Output saved to output_modified.pcap
```

### Distributed Client-Server Run (Tasks 2 and 3)

Server Output:
```
> .\build\Release\xflow_server.exe 8088 sip_records.db sip-rtp-g729a.pcap Mahnoor
Starting Server on port 8088...
Database file: sip_records.db
Assigned PCAP: sip-rtp-g729a.pcap

Server listening on port 8088. Waiting for client...
Client connected.
Sent task to client: sip-rtp-g729a.pcap
Received 6 records from client.
Saved records into SQLite database successfully.

Database contents (6 rows):
Packet #1 | Call-ID: 1-24411@10.0.2.20
  From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  To:   test <sip:test@10.0.2.15:5060>
  Mod:  Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
Packet #2 | Call-ID: 1-24411@10.0.2.20
  From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  To:   test <sip:test@10.0.2.15:5060>
  Mod:  Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
Packet #4 | Call-ID: 1-24411@10.0.2.20
  From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  To:   test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  Mod:  Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
Packet #5 | Call-ID: 1-24411@10.0.2.20
  From: "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  To:   test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  Mod:  Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
Packet #432 | Call-ID: 1-24411@10.0.2.20
  From: test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  To:   "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Mod:  Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
Packet #433 | Call-ID: 1-24411@10.0.2.20
  From: test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
  To:   "G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
  Mod:  Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH

Server finished processing.
```

Client Output:
```
> .\build\Release\xflow_client.exe 127.0.0.1 8088
Connecting to server at 127.0.0.1:8088...
Connected to server.
Received task assignment: ASSIGN_PCAP	sip-rtp-g729a.pcap	output_modified.pcap	Mahnoor
Processing PCAP...
PCAP processed: 433 total packets, 6 SIP packets modified.
Sending extracted records to server...
Server response: SUCCESS	Inserted 6 records into database.
Client task finished.
```

### Unit Tests Run (Task 4)

```
> .\build\Release\unit_tests.exe
[==========] Running 9 tests from 4 test suites.
[----------] Global test environment set-up.
[----------] 2 tests from DatabaseTest
[ RUN      ] DatabaseTest.InsertAndQueryRecords
[       OK ] DatabaseTest.InsertAndQueryRecords (0 ms)
[ RUN      ] DatabaseTest.BulkInsertRecords
[       OK ] DatabaseTest.BulkInsertRecords (0 ms)
[----------] 2 tests from DatabaseTest (1 ms total)

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
[       OK ] PcapProcessorTest.ProcessPcapEndToEnd (5 ms)
[----------] 1 test from PcapProcessorTest (5 ms total)

[----------] Global test environment tear-down
[==========] 9 tests from 4 test suites ran. (7 ms total)
[  PASSED  ] 9 tests.
```

---

## 7. Key Engineering Takeaways and Conclusions

1. Network Protocol Awareness:
In low-level systems programming, you cannot treat network packets as plain strings. Changing application data has immediate cascading consequences across transport and network headers. Implementing the bottom-up update pipeline ensured that length fields and checksums remained valid across all layers.

2. Empirical Verification over Assumptions:
Using Wireshark and tshark to validate the output capture was crucial. It exposed the hardware checksum offload behavior in the original PCAP file and allowed me to verify that my software-calculated checksums met RFC standards with a 100% Good rating.

3. Cross-Platform Discipline:
Abstracting socket APIs and bundling dependencies (Npcap SDK x64 import library and SQLite3 amalgamation) allowed the project to build cleanly on both Windows and Linux without complex environment setup.

4. Defensive Design:
All packet parsing routines explicitly verify capture lengths before dereferencing struct pointers. Similarly, SQL statements use parameterized queries to avoid formatting errors and security vulnerabilities.
