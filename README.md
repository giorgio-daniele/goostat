# Goostat
Goostat is a simple clone of [Tstat](http://www.tstat.polito.it/), written in Go. It was developed during the Christmas holidays, during a period of intense psychotic activity. 

## Purpose

This software allows for the reconstruction of TCP and UDP flows within a network trace. The network trace should be captured in a LAN, where a client is considered to have a private IP address, specifically when using IPv4. Currently, Goostat only supports IPv4. Each client is identified by whether its IP address is private, so the flows are reconstructed from the client’s perspective. Since data transfers are typically initiated by clients, Goostat detects the opening of each TCP-based data transfer and UDP-based data transfer by tracing private IP addresses.

## Methodology

### TCP

A TCP-based data transfer can be easily reconstructed using two procedures: the connection establishment handshake and the connection termination handshake. Given a `.pcap` trace, Goostat reconstructs the TCP connections that occurred in the trace, using the 3-way handshake with `SYN/ACK` as an indicator for the start of a new data transfer, and the equivalent procedure with `FIN/RST` to signal its closure.

### UDP

A UDP-based data transfer does not have explicit signaling, as the protocol is not connection-oriented. A new UDP-based data transfer is detected when a client sends a packet toward a server whose socket has not been previously traced. Client-side and server-side flows are traced separately, so each flow has its own start and end, with a timeout indicating the amount of idle time for the flow. If the last packet observed is too far in time, beyond the timeout threshold, the flow is considered closed.

## Metrics Explained

### TCP

Goostat collects the following metrics for each TCP connection:

- **Source IP (`SrcIP`)**: The IP address of the client initiating the connection.
- **Destination IP (`DstIP`)**: The IP address of the server receiving the connection.
- **Source Port (`SrcPort`)**: The port number used by the client for the connection.
- **Destination Port (`DstPort`)**: The port number used by the server for the connection.

For both the client and server:

- **Packs**: The total number of packets sent.
- **Bytes**: The total number of bytes sent.
- **Payload Packs**: The number of packets that contained payload (actual data).
- **Payload Bytes**: The total number of bytes transferred as payload.

Additional connection flags for each side (client and server):

- **SYN**: The number of SYN packets sent (used for initiating a connection).
- **ACK**: The number of ACK packets sent (used for acknowledging data).
- **FIN**: The number of FIN packets sent (used for gracefully closing a connection).
- **RST**: The number of RST packets sent (used for forcibly closing a connection).
- **URG**: The number of URG packets sent (indicating urgent data).
- **PSH**: The number of PSH packets sent (indicating the receiver should pass the data to the application without buffering).

Timestamps:

- **Ts**: The timestamp of the start of the connection (when the first packet is observed).
- **Te**: The timestamp of the end of the connection (when the last packet is observed).

---

### UDP

Goostat collects the following metrics for each UDP connection:

- **Source IP (`SrcIP`)**: The IP address of the client initiating the connection.
- **Destination IP (`DstIP`)**: The IP address of the server receiving the connection.
- **Source Port (`SrcPort`)**: The port number used by the client for the connection.
- **Destination Port (`DstPort`)**: The port number used by the server for the connection.

For both the client and server:

- **Packs**: The total number of packets sent.
- **Bytes**: The total number of bytes sent.

Timestamps:

- **Ts**: The timestamp of the start of the flow (when the first packet is observed).
- **Te**: The timestamp of the end of the flow (when the last packet is observed).
