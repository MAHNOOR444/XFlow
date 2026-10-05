# xFlow Packet Processing and Distributed SIP Pipeline

A cross-platform C++17 packet processing engine and client-server system. The application reads a VoIP network capture (sip-rtp-g729a.pcap), extracts and parses SIP messages, modifies the From header by prepending a name prefix, recalculates RFC-compliant IPv4 and UDP checksums and lengths, preserves RTP media packets untouched, and transfers extracted records over a TCP socket to an SQLite database on the server.

---

## Table of Contents

1. Project Overview
2. Architecture and Data Flow
3. Repository Structure
4. Prerequisites and Environment Setup
5. How to Build the Project
   - Building on Windows
   - Building on Linux
6. How to Run the Applications
   - Task 1: Standalone PCAP Processor
   - Task 2 and 3: Client-Server Architecture and Database
7. Task 4: Running Unit Tests
8. Wireshark and Packet Validation
9. Verification of SQLite Database Records
10. Engineering Documentation

---

## 1. Project Overview

This repository contains the complete implementation for the xFlow technical evaluation, covering all five required tasks:

- Task 0: Clean Git repository management, appropriate ignore rules, bundled third-party dependencies, and atomic commits.
- Task 1: PCAP packet processing engine using libpcap. It reads sip-rtp-g729a.pcap, identifies SIP packets on UDP port 5060, extracts To, From, and Call-ID headers, prepends the candidate name prefix (Mahnoor) to the From field, recalculates IPv4 total length, IPv4 header checksum (RFC 791), UDP length, and UDP checksum (RFC 768), and writes the modified stream to output_modified.pcap. RTP packets on audio ports are written to the output file completely untouched.
- Task 2: Client-server distributed architecture. Sockets are implemented using cross-platform abstractions (Winsock on Windows, POSIX on Linux) with a 4-byte length-prefix framing protocol. The server assigns the PCAP processing job to the client over TCP, the client processes the capture file, and streams the extracted SIP records back to the server.
- Task 3: SQLite database persistence. The server persists extracted SIP metadata into an SQLite database (sip_records.db) with parameterized queries and batch transactions, then performs verification queries.
- Task 4: Comprehensive Google Test suite with 9 unit tests covering SQLite operations, SIP header extraction, display name prefix modification, RFC 791 and RFC 768 checksum calculations, and end-to-end PCAP processing.
- Task 5: Cross-platform CMake build configuration supporting MSVC on Windows and GCC/Clang on Linux.

---

## 2. Architecture and Data Flow

The project consists of three main executables and a core shared library:

- xflow_core: Static library containing the PCAP engine, SIP parser, checksum recalculator, database manager, and socket networking helper.
- xflow_processor: Standalone command-line tool for direct file-to-file PCAP processing.
- xflow_server: TCP server that issues task assignments, receives extracted records from the client, and stores them in SQLite.
- xflow_client: TCP client that connects to the server, receives the assignment, processes the PCAP file, and returns the parsed SIP records.
- unit_tests: Google Test executable that runs the test suite.

Data Flow Diagram:

```
[ xflow_server ]                                    [ xflow_client ]
       |                                                   |
       |  1. TCP Connection on Port 8088                   |
       |<--------------------------------------------------|
       |                                                   |
       |  2. Send Task Assignment:                         |
       |     ASSIGN_PCAP sip-rtp-g729a.pcap Mahnoor        |
       |-------------------------------------------------->|
       |                                                   |
       |                                           [ PcapProcessor ]
       |                                           - Open offline PCAP
       |                                           - Filter SIP on port 5060
       |                                           - Prepend prefix to From
       |                                           - Recompute IP & UDP checksums
       |                                           - Dump output_modified.pcap
       |                                           - Leave RTP packets intact
       |                                                   |
       |  3. Return Serialized SIP Records                 |
       |<--------------------------------------------------|
       |
 [ DatabaseManager ]
 - Insert into sip_records table
 - Execute verification query
       |
       |  4. Send Success Acknowledgment                   |
       |-------------------------------------------------->|
```

---

## 3. Repository Structure

```
xflow/
├── CMakeLists.txt              # Cross-platform CMake build configuration
├── README.md                   # Human-readable guide and user manual
├── WORK_LOG.md                 # Detailed technical work log and report
├── build.bat                   # Convenience Windows build script
├── run_tests.bat               # Convenience test runner script for Windows
├── sip-rtp-g729a.pcap          # Input PCAP file provided for evaluation
├── include/
│   ├── checksum.h              # RFC 791 and RFC 768 checksum calculator declarations
│   ├── database_manager.h      # SQLite3 database interface declaration
│   ├── network.h               # Cross-platform socket and serialization helpers
│   ├── packet_headers.h        # Packed structs for Ethernet, IPv4, UDP, and SIP records
│   ├── pcap_processor.h        # Libpcap file reader, modifier, and dumper
│   └── sip_parser.h            # SIP method detection, header parsing, and modification
├── src/
│   ├── checksum.cpp            # Checksum algorithm implementations
│   ├── client_main.cpp         # Task 2: Client entry point
│   ├── database_manager.cpp    # Task 3: SQLite schema, prepared statements, and transactions
│   ├── main.cpp                # Task 1: Standalone PCAP processor entry point
│   ├── network.cpp             # TCP framing, send/receive loops, record serialization
│   ├── pcap_processor.cpp      # Offline packet processing loop and header rewriting
│   ├── server_main.cpp         # Task 2 & 3: Server entry point and database integration
│   └── sip_parser.cpp          # SIP string parsing and prefix insertion logic
├── tests/
│   ├── test_checksum.cpp       # Unit tests for Internet, IPv4, and UDP checksums
│   ├── test_database.cpp       # Unit tests for SQLite database operations
│   ├── test_main.cpp           # Google Test main runner
│   ├── test_pcap_processor.cpp # End-to-end integration test with sample PCAP
│   └── test_sip_parser.cpp     # Unit tests for SIP parsing and From field modification
└── third_party/
    ├── npcap-sdk/              # Npcap SDK headers and 64-bit import library for Windows
    │   ├── Include/            # pcap.h and related network headers
    │   └── Lib/x64/            # 64-bit wpcap.lib and Packet.lib
    └── sqlite3/                # Official SQLite3 amalgamation
        ├── sqlite3.c           # SQLite engine C source
        └── sqlite3.h           # SQLite C header
```

---

## 4. Prerequisites and Environment Setup

### Windows

- Visual Studio 2022 (Community or higher with the Desktop development with C++ workload installed).
- CMake 3.20 or newer.
- Npcap driver installed on your machine (available from npcap.com or installed with Wireshark).
- The project already bundles the necessary Npcap SDK headers and 64-bit import libraries in third_party/npcap-sdk, so no manual library configuration is needed.
- SQLite3 is bundled in third_party/sqlite3.

### Linux (Ubuntu / Debian / CentOS / Fedora)

- GCC 9+ or Clang 10+ with C++17 support.
- CMake 3.20 or newer.
- Development packages for libpcap and sqlite3:

On Ubuntu / Debian:
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libpcap-dev libsqlite3-dev git
```

On CentOS / RHEL / Fedora:
```bash
sudo dnf install -y gcc-c++ cmake libpcap-devel sqlite-devel git
```

---

## 5. How to Build the Project

### Building on Windows

Option A: Using the one-click build script
Open PowerShell or Command Prompt in the repository root and run:
```bat
build.bat
```
This script detects Visual Studio 2022, configures CMake for x64, and compiles the Release binaries into the build directory.

Option B: Using CMake directly from the command line
```bat
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

All compiled executables will be located in the build/Release folder:
- build/Release/xflow_processor.exe
- build/Release/xflow_server.exe
- build/Release/xflow_client.exe
- build/Release/unit_tests.exe

### Building on Linux

From the project root:
```bash
mkdir -p build && cd build
cmake ..
cmake --build . -j$(nproc)
```

All compiled binaries will be created directly in the build folder:
- build/xflow_processor
- build/xflow_server
- build/xflow_client
- build/unit_tests

---

## 6. How to Run the Applications

### Task 1: Standalone PCAP Processor

The standalone processor reads an input PCAP, processes each packet, prepends the name prefix to the SIP From header, recalculates all required checksums, and writes the output PCAP.

Command Syntax:
```
xflow_processor [input_pcap] [output_pcap] [name_prefix]
```

Default values if arguments are omitted:
- input_pcap: sip-rtp-g729a.pcap
- output_pcap: output_modified.pcap
- name_prefix: Mahnoor

Running on Windows:
```bat
.\build\Release\xflow_processor.exe sip-rtp-g729a.pcap output_modified.pcap Mahnoor
```

Running on Linux:
```bash
./build/xflow_processor sip-rtp-g729a.pcap output_modified.pcap Mahnoor
```

Sample Output:
```
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

---

### Task 2 and 3: Client-Server Architecture and Database

To run the distributed workflow, open two separate terminal windows.

Server Command Syntax:
```
xflow_server [port] [db_file] [input_pcap] [name_prefix]
```
Defaults: port 8088, db_file sip_records.db, input_pcap sip-rtp-g729a.pcap, name_prefix Mahnoor.

Client Command Syntax:
```
xflow_client [server_ip] [server_port]
```
Defaults: server_ip 127.0.0.1, server_port 8088.

#### Step 1: Start the Server (Terminal 1)

On Windows:
```bat
.\build\Release\xflow_server.exe 8088 sip_records.db sip-rtp-g729a.pcap Mahnoor
```

On Linux:
```bash
./build/xflow_server 8088 sip_records.db sip-rtp-g729a.pcap Mahnoor
```

The server starts listening on port 8088 and creates or opens sip_records.db.

#### Step 2: Start the Client (Terminal 2)

On Windows:
```bat
.\build\Release\xflow_client.exe 127.0.0.1 8088
```

On Linux:
```bash
./build/xflow_client 127.0.0.1 8088
```

#### What Happens Next:
1. The client connects to the server over TCP port 8088.
2. The server dispatches the job message: ASSIGN_PCAP sip-rtp-g729a.pcap output_modified.pcap Mahnoor.
3. The client receives the task, executes PcapProcessor, writes the new output_modified.pcap, and packages the 6 extracted SIP records.
4. The client sends the serialized records back to the server.
5. The server deserializes the records, inserts them into sip_records.db inside a transaction, performs a database query to display stored contents, and returns a SUCCESS confirmation to the client.

---

## 7. Task 4: Running Unit Tests

The test suite is built on Google Test (automatically downloaded and integrated by CMake via FetchContent).

Option A: Run using the Windows test batch script
```bat
run_tests.bat
```

Option B: Run via CTest
On Windows:
```bat
ctest --test-dir build -C Release --output-on-failure
```

On Linux:
```bash
cd build && ctest --output-on-failure
```

Option C: Run the test executable directly
On Windows:
```bat
.\build\Release\unit_tests.exe
```

On Linux:
```bash
./build/unit_tests
```

### Test Suite Overview:

1. DatabaseTest.InsertAndQueryRecords
   Verifies SQLite schema creation, insertion of individual records, query by call_id, and full table scans.
2. DatabaseTest.BulkInsertRecords
   Verifies fast transactional batch insertion using BEGIN TRANSACTION and COMMIT.
3. SipParserTest.IsSipPayloadIdentification
   Validates identification of SIP message methods and status lines (INVITE, 200 OK) while rejecting binary RTP data.
4. SipParserTest.ExtractSipFields
   Validates accurate extraction of To, From, and Call-ID headers.
5. SipParserTest.ModifyFromHeaderWithPrefix
   Validates prepending the prefix to the From header while preserving all other headers and SDP body.
6. ChecksumTest.BasicInternetChecksum
   Verifies the standard 16-bit one's complement Internet checksum calculation and loopback zero check.
7. ChecksumTest.IPv4HeaderChecksum
   Verifies IPv4 header checksum calculation against real capture packet headers.
8. ChecksumTest.UDPChecksumRFC768
   Verifies RFC 768 UDP checksum computation covering the IPv4 pseudo-header, UDP header, and payload.
9. PcapProcessorTest.ProcessPcapEndToEnd
   End-to-end integration test reading sip-rtp-g729a.pcap, verifying 433 total packets, 6 modified SIP packets, and 425 intact RTP packets.

All 9 tests pass with zero failures.

---

## 8. Wireshark and Packet Validation

To ensure network protocol integrity, the generated output_modified.pcap was verified using Wireshark and tshark.

### Checksum Validation Command:
```bat
"C:\Program Files\Wireshark\tshark.exe" -r output_modified.pcap -Y "sip" -o ip.check_checksum:TRUE -o udp.check_checksum:TRUE -T fields -e frame.number -e ip.checksum.status -e udp.checksum.status
```

Output Result:
```
1    1    1
2    1    1
4    1    1
5    1    1
432  1    1
433  1    1
```

Explanation of Status Codes:
- Status 1 indicates Good (Verified correct by Wireshark).
- Every single SIP packet in output_modified.pcap has an IP checksum status of Good and a UDP checksum status of Good.

### Packet Details Summary:

- Total packets in original PCAP: 433
- Total packets in modified PCAP: 433
- Preserved RTP packets: 425 (unchanged)
- Preserved UDP control packets: 2 (unchanged)
- Modified SIP packets: 6 (frames 1, 2, 4, 5, 432, 433)

Sample inspection of Frame 1 in Wireshark:
- Total Length: 497 bytes (increased by length of prefix)
- IP Header Checksum: 0x3354 [correct, Good]
- UDP Length: 477 bytes
- UDP Checksum: 0xf126 [correct, Good]
- SIP From Header: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1

---

## 9. Verification of SQLite Database Records

The database created by xflow_server is a standard SQLite3 file named sip_records.db.

Table Schema:
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

You can inspect the contents using any SQLite viewer or the sqlite3 command-line utility:
```bash
sqlite3 sip_records.db "SELECT packet_number, call_id, modified_from FROM sip_records;"
```

Expected rows:
- Packet 1: Call-ID 1-24411@10.0.2.20, Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
- Packet 2: Call-ID 1-24411@10.0.2.20, Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
- Packet 4: Call-ID 1-24411@10.0.2.20, Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
- Packet 5: Call-ID 1-24411@10.0.2.20, Modified From: Mahnoor"G729/8000" <sip:sipp@10.0.2.20:5060>;tag=1
- Packet 432: Call-ID 1-24411@10.0.2.20, Modified From: Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH
- Packet 433: Call-ID 1-24411@10.0.2.20, Modified From: Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH

---

## 10. Engineering Documentation

For in-depth discussion on protocol design decisions, RFC specifications, challenges faced during development (such as UDP checksum offloading in original captures and Windows header macro conflicts), and packet comparison tables, please refer to WORK_LOG.md.
