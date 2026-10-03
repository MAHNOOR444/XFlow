# xFlow Packet Processing Assignment

A scalable, cross-platform C++17 networked application and packet processor utilizing `libpcap` to read, modify, and write SIP/RTP PCAP packets, communicate across a client-server socket architecture, store extracted SIP call metadata into an SQLite3 database, and validate integrity with GoogleTest and Wireshark.

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture & Design](#architecture--design)
3. [Prerequisites & Dependencies](#prerequisites--dependencies)
4. [Building the Project with CMake](#building-the-project-with-cmake)
   - [Linux (Ubuntu / Debian / CentOS)](#linux-ubuntu--debian--centos)
   - [Windows (MSVC / Visual Studio 2022)](#windows-msvc--visual-studio-2022)
5. [Running the Application](#running-the-application)
   - [Task 1: Standalone PCAP Processor](#task-1-standalone-pcap-processor)
   - [Task 2 & 3: Client-Server Architecture & Database](#task-2--3-client-server-architecture--database)
6. [Task 4: Running Google Test Unit Tests](#task-4-running-google-test-unit-tests)
7. [Wireshark & Packet Integrity Validation](#wireshark--packet-integrity-validation)
8. [Work Log](#work-log)

---

## Project Overview

This project was built to address the xFlow engineering evaluation requirements:
- **Task 0**: Git repository management, version control, and clean history.
- **Task 1**: Read `sip-rtp-g729a.pcap` using `libpcap`, extract SIP messages, extract `To`, `From`, and `Call-ID` fields, prepend candidate name prefix to the `From:` header content, recompute IPv4/UDP checksums and packet lengths, and write to a new PCAP without modifying RTP packets.
- **Task 2**: Client-Server socket communication where the server assigns the PCAP task to the client, the client executes packet processing, and sends the extracted data back to the server.
- **Task 3**: SQLite3 database storage on the server to persist `packet_number`, `call_id`, `from_field`, `to_field`, `modified_from`, and timestamps.
- **Task 4**: Comprehensive unit tests using the Google Test (`gtest`) framework covering database queries, SIP parsing/modifications, and RFC 791 / RFC 768 checksum verification.
- **Task 5**: Modern CMake build system with seamless support for Linux and Windows.

---

## Architecture & Design

```
+---------------------------------------------------------------------------------------+
|                                  xFlow Architecture                                    |
+---------------------------------------------------------------------------------------+
                                  
     [ xflow_server ]                                    [ xflow_client ]
            |                                                   |
            |  1. TCP Connect (Port 8088)                       |
            |<--------------------------------------------------|
            |                                                   |
            |  2. Task Request: "ASSIGN_PCAP sip-rtp-g729a.pcap"|
            |-------------------------------------------------->|
            |                                                   |
            |                                        +----------v----------+
            |                                        |    PcapProcessor    |
            |                                        | - libpcap Offline   |
            |                                        | - Filter SIP (5060) |
            |                                        | - Prepend Prefix    |
            |                                        | - Recompute Checksum|
            |                                        | - Dump modified PCAP|
            |                                        +----------+----------+
            |                                                   |
            |  3. Return Extracted Records & Status             |
            |<--------------------------------------------------+
            |
    +-------v-------+
    |DatabaseManager|
    |  - SQLite3    |
    |  - INSERT/TRAN|
    |  - SQL Query  |
    +-------+-------+
            |
            |  4. Acknowledge Success
            |-------------------------------------------------->|
```

### Key Modules:
- **`include/packet_headers.h`**: Struct definitions for Ethernet (14B), IPv4 (20B), UDP (8B), IPv4 Pseudo-Header, and `SipRecord`. Packed with `#pragma pack(push, 1)`.
- **`src/checksum.cpp` / `include/checksum.h`**: Computes RFC 791 IP header checksum and RFC 768 UDP checksum over pseudo-header + UDP header + payload with odd-byte handling.
- **`src/sip_parser.cpp` / `include/sip_parser.h`**: Dissects SIP request/status lines, extracts headers (`To`, `From`, `Call-ID`, compact aliases `t`, `f`, `i`), and inserts the prefix into the `From:` header while preserving all other headers and SDP body.
- **`src/pcap_processor.cpp` / `include/pcap_processor.h`**: Libpcap reader and dumper. Preserves RTP packets untouched, adjusts `caplen` and `origlen`, and writes modified SIP packets.
- **`src/database_manager.cpp` / `include/database_manager.h`**: SQLite3 interface handling schema creation, transaction-based inserts, and queries.
- **`src/network.cpp` / `include/network.h`**: Cross-platform length-prefixed TCP socket communication (supporting both POSIX sockets and Windows Winsock2).

---

## Prerequisites & Dependencies

### Linux (Ubuntu 20.04 / 22.04 / 24.04 or CentOS):
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libpcap-dev libsqlite3-dev git
```
*(On CentOS / RHEL: `sudo yum install gcc-c++ cmake libpcap-devel sqlite-devel git`)*

### Windows:
- Visual Studio 2022 (with "Desktop development with C++") or MinGW-w64.
- CMake (version 3.20 or newer).
- Npcap (or Wireshark with Npcap installed).
- The project bundles the **Npcap SDK** (`third_party/npcap-sdk`) and **SQLite3 amalgamation** (`third_party/sqlite3`), enabling zero-friction compilation on Windows.

---

## Building the Project with CMake

### Linux:
```bash
# Clone the repository
git clone <repo-url>
cd xflow

# Create build directory
mkdir build && cd build

# Configure and compile
cmake ..
cmake --build . -j$(nproc)
```

### Windows (PowerShell / Command Prompt):
```powershell
# From the root directory:
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

---

## Running the Application

### Task 1: Standalone PCAP Processor
You can execute the PCAP processor directly on any PCAP file:
```bash
# Linux:
./build/xflow_processor sip-rtp-g729a.pcap output_modified.pcap Mahnoor

# Windows:
.\build\Release\xflow_processor.exe sip-rtp-g729a.pcap output_modified.pcap Mahnoor
```

**Output Summary:**
- Reads 433 total packets.
- Identifies and modifies 6 SIP packets (prepending name prefix to `From:`).
- Preserves 425 RTP packets and 2 non-SIP UDP packets untouched.
- Generates `output_modified.pcap` with recalculated IP & UDP checksums.

---

### Task 2 & 3: Client-Server Architecture & Database

1. **Terminal 1: Start the Server**
   ```bash
   # Linux:
   ./build/xflow_server 8088 sip_records.db sip-rtp-g729a.pcap Mahnoor

   # Windows:
   .\build\Release\xflow_server.exe 8088 sip_records.db sip-rtp-g729a.pcap Mahnoor
   ```

2. **Terminal 2: Start the Client**
   ```bash
   # Linux:
   ./build/xflow_client 127.0.0.1 8088

   # Windows:
   .\build\Release\xflow_client.exe 127.0.0.1 8088
   ```

**Flow:**
- The server sends the PCAP file name to the client.
- The client reads the input PCAP, extracts SIP information, modifies the `From` header, updates checksums, writes the new PCAP file, and streams the extracted records back to the server.
- The server stores the `To`, `From`, and `Call ID` fields in the SQLite database (`sip_records.db`), verifies the records with SQL queries, and prints a formatted summary.

---

## Task 4: Running Google Test Unit Tests

GoogleTest is automatically downloaded and built via CMake `FetchContent`.

### Run via CTest:
```bash
# Linux:
cd build && ctest --output-on-failure

# Windows:
ctest --test-dir build -C Release --output-on-failure
```

### Run the Test Binary Directly:
```bash
# Linux:
./build/unit_tests

# Windows:
.\build\Release\unit_tests.exe
```

**Unit Test Coverage:**
1. `DatabaseTest.InsertAndQueryRecords`: Verifies SQLite schema creation, insertion of SIP records, and querying by Call-ID and full table scan.
2. `DatabaseTest.BulkInsertRecords`: Tests transactional bulk insertion.
3. `SipParserTest.IsSipPayloadIdentification`: Tests SIP message signature detection.
4. `SipParserTest.ExtractSipFields`: Validates extraction of `To`, `From`, and `Call-ID`.
5. `SipParserTest.ModifyFromHeaderWithPrefix`: Validates that prefix is prepended to the `From` field while maintaining other headers and SDP body.
6. `ChecksumTest.BasicInternetChecksum`: Validates 16-bit Internet checksum algorithm.
7. `ChecksumTest.IPv4HeaderChecksum`: Validates IPv4 header checksum calculation matching Wireshark ground truth.
8. `ChecksumTest.UDPChecksumRFC768`: Validates RFC 768 pseudo-header UDP checksum calculation.
9. `PcapProcessorTest.ProcessPcapEndToEnd`: End-to-end integration test reading `sip-rtp-g729a.pcap`, verifying 433 packets, 6 modified SIP packets, and 425 intact RTP packets.

---

## Wireshark & Packet Integrity Validation

The generated `output_modified.pcap` was thoroughly verified using Wireshark and `tshark`:
```bash
tshark -r output_modified.pcap -Y "sip" -o ip.check_checksum:TRUE -o udp.check_checksum:TRUE -T fields -e frame.number -e ip.checksum.status -e udp.checksum.status -e sip.from.addr
```

**Verification Results:**
- All IP checksum statuses: `1` (`Good`)
- All UDP checksum statuses: `1` (`Good`)
- Packet count: Exactly 433 packets.
- No dissection errors or malformed packet alerts reported by Wireshark.

---

## Work Log
For the detailed engineering report, design decisions, challenges encountered, packet snapshots, and takeaways, please refer to [WORK_LOG.md](WORK_LOG.md).
