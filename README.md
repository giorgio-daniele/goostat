# Goostat

Goostat is a simple clone of [Tstat](http://www.tstat.polito.it/), written in Go. It was developed during the 2024 Christmas holidays as a personal project to help manage and cope with a **schizophrenia** crisis. This software is designed to reconstruct data exchanges for both TCP and UDP protocols. 

In TCP, client and server flows are highly correlated through flags (SYN, RST, FIN), while in UDP, client and server flows are decoupled. The software reconstructs data exchanges from the client perspective, where the client is identified by an IP address, which is considered local within a specified network, whose CIDR block is provided as input.

## Methodology

Goostat reconstructs TCP data exchanges by detecting when SYN = 1 and ACK = 0 from an IP address within the specified local network. The exchange is considered complete once either the client or the server emits a FIN or RST flag.

## Features

- Reconstructs detailed TCP data exchanges from the client perspective
- Supports both TCP and UDP protocols
- Analyzes traffic from pcap trace files
- Statistical breakdown of TCP flows, including flags (e.g., SYN, RST, FIN)
  
## Requirements

- GoLang (latest stable version)
- Libpcap or an equivalent packet capture library

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/giorgio-daniele/goostat.git
    cd goostat
    ```

2. Install dependencies:
    ```bash
    go mod tidy
    ```

3. Install libpcap (for packet capture support):
    - On Ubuntu/Debian:
      ```bash
      sudo apt-get install libpcap-dev
      ```

4. Build the project:
    ```bash
    go build -o goostat
    ```

5. Run Goostat:
    ```bash
    ./goostat -i <pcap> -n <network>
    ```

## Usage

To use Goostat, provide a CIDR block representing your local network and a `.pcap` file for analysis. The software will reconstruct and report on data exchanges from the perspective of the client IP within the specified network.

### Example:
```bash
./goostat --n 192.168.1.0/24 --i network-traffic.pcap
