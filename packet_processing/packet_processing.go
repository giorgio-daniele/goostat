package packet_processing

import (
	"goostat/metrics"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func updateTcpFlowMetrics(connection *metrics.TcpFlowMetrics, tcp *layers.TCP) {
	connection.Packs++
	connection.Bytes += len(tcp.Payload) + int(tcp.DataOffset)*4
	if tcp.ACK {
		connection.ACK++
	}
	if tcp.PSH {
		connection.PSH++
	}
	if tcp.URG {
		connection.URG++
	}
	if len(tcp.Payload) > 0 {
		connection.PayloadPacks++
		connection.PayloadBytes += len(tcp.Payload)
	}
}

func ProcessUdpPacket(packet gopacket.Packet) {
	// Define the layers
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)

	// Define the timestamp
	stamp := packet.Metadata().Timestamp.Unix()

	// Define the keys
	key := metrics.GetConnectionKeyUdp(ip4, udp, false)
	rev := metrics.GetConnectionKeyUdp(ip4, udp, true)

	// Client side
	if connection, exists := metrics.UdpConnections[key]; exists {
		connection.Client.Packs++
		connection.Client.Bytes += len(udp.Payload)
	} else {
		connection := &metrics.UdpConnection{
			Client: metrics.UdpFlowMetrics{Packs: 1, Bytes: len(udp.Payload)},
		}
		connection.Client.Ts = stamp
		connection.Client.Last = stamp
		metrics.UdpConnections[key] = connection
	}

	// Server side
	if connection, exists := metrics.UdpConnections[rev]; exists {
		if connection.Server.Packs == 0 {
			connection.Server.Ts = stamp
			connection.Server.Last = stamp
		}
		connection.Server.Packs++
		connection.Server.Bytes += len(udp.Payload)
	}

	// Update all connections
	for _, connection := range metrics.UdpConnections {
		if connection.Client.Te == 0 && connection.Client.Last > 120_000 {
			connection.Client.Te = stamp
		}
		if connection.Server.Te == 0 && connection.Server.Last > 120_000 {
			connection.Server.Te = stamp
		}
	}

}

func ProcessTcpPacket(packet gopacket.Packet) {
	// Define the layers
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	// Define the timestamp
	stamp := packet.Metadata().Timestamp.Unix()

	// Define the keys
	key := metrics.GetConnectionKeyTcp(ip4, tcp, false)
	rev := metrics.GetConnectionKeyTcp(ip4, tcp, true)

	if tcp.SYN && !tcp.ACK && ip4.SrcIP.IsPrivate() {
		// Client initiates 3-way handshake
		metrics.TcpConnections[key] = &metrics.TcpConnection{
			Client: metrics.TcpFlowMetrics{Packs: 1, Bytes: len(tcp.Payload), SYN: 1},
		}

	} else if tcp.SYN && tcp.ACK && !ip4.SrcIP.IsPrivate() {
		// Server initiates 3-way handshake
		if connection, exists := metrics.TcpConnections[rev]; exists {
			connection.Server = metrics.TcpFlowMetrics{Packs: 1, Bytes: len(tcp.Payload), SYN: 1, ACK: 1}
		}

	} else if (tcp.FIN || tcp.RST) && ip4.SrcIP.IsPrivate() {
		// Client wants to close the connection
		if connection, exists := metrics.TcpConnections[key]; exists {
			if tcp.FIN {
				connection.Client.FIN++
			}
			if tcp.RST {
				connection.Client.RST++
			}
			updateTcpFlowMetrics(&connection.Client, tcp)
			connection.Te = stamp
		}

	} else if (tcp.FIN || tcp.RST) && !ip4.SrcIP.IsPrivate() {
		// Server wants to close the connection
		if connection, exists := metrics.TcpConnections[rev]; exists {
			if tcp.FIN {
				connection.Server.FIN++
			}
			if tcp.RST {
				connection.Server.RST++
			}
			updateTcpFlowMetrics(&connection.Server, tcp)
			connection.Te = stamp
		}

	} else {
		if connection, exists := metrics.TcpConnections[key]; exists {
			if tcp.ACK && connection.Client.Packs == 1 {
				// 3-way handshake is now completed
				connection.Ts = stamp
			}
			// Ongoing connection (client packet)
			updateTcpFlowMetrics(&connection.Client, tcp)
		}

		if connection, exists := metrics.TcpConnections[rev]; exists {
			// Ongoing connection (server packet)
			updateTcpFlowMetrics(&connection.Server, tcp)
		}
	}
}
