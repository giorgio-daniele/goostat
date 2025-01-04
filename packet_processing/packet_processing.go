package packet_processing

import (
	"goostat/metrics"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ProcessTCPPacket processes a TCP packet and updates the metrics
func ProcessTCPPacket(packet gopacket.Packet) {
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	packetTime := packet.Metadata().Timestamp.Unix()

	// New connection (SYN without ACK)
	if tcp.SYN && !tcp.ACK {
		metrics.TCPConnections[metrics.GetConnectionKey(ip4, tcp, false)] = &metrics.TCPConnection{
			Client: metrics.TCPFlowMetrics{Packs: 1},
			Server: metrics.TCPFlowMetrics{},
			Ts:     packetTime,
			Te:     0,
		}
	} else if tcp.SYN && tcp.ACK {
		// Connection established, update server metrics
		rev := metrics.GetConnectionKey(ip4, tcp, true)
		if conn, exists := metrics.TCPConnections[rev]; exists {
			conn.Server.Packs++
			// Increment the flag counters
			if tcp.SYN {
				conn.Server.SYN++
			}
			if tcp.ACK {
				conn.Server.ACK++
			}
		}
	} else if tcp.FIN || tcp.RST {
		// Connection teardown, update both client and server metrics
		rev := metrics.GetConnectionKey(ip4, tcp, true)
		if conn, exists := metrics.TCPConnections[rev]; exists {
			conn.Server.Packs++
			conn.Te = packetTime
			// Increment the flag counters
			if tcp.FIN {
				conn.Server.FIN++
			}
			if tcp.RST {
				conn.Server.RST++
			}
		}
		key := metrics.GetConnectionKey(ip4, tcp, false)
		if conn, exists := metrics.TCPConnections[key]; exists {
			conn.Client.Packs++
			conn.Te = packetTime
			// Increment the flag counters
			if tcp.FIN {
				conn.Client.FIN++
			}
			if tcp.RST {
				conn.Client.RST++
			}
		}
	} else {
		// Regular packet, update metrics for both directions
		rev := metrics.GetConnectionKey(ip4, tcp, true)
		if conn, exists := metrics.TCPConnections[rev]; exists {
			conn.Server.Packs++
			if len(tcp.Payload) > 0 {
				conn.Server.PayloadPacks++
				conn.Server.PayloadBytes += len(tcp.Payload)
			}
			// Increment the flag counters
			if tcp.SYN {
				conn.Server.SYN++
			}
			if tcp.ACK {
				conn.Server.ACK++
			}
			if tcp.PSH {
				conn.Server.PSH++
			}
			if tcp.URG {
				conn.Server.URG++
			}
		}
		key := metrics.GetConnectionKey(ip4, tcp, false)
		if conn, exists := metrics.TCPConnections[key]; exists {
			conn.Client.Packs++
			if len(tcp.Payload) > 0 {
				conn.Client.PayloadPacks++
				conn.Client.PayloadBytes += len(tcp.Payload)
			}
			// Increment the flag counters
			if tcp.ACK {
				conn.Client.ACK++
			}
			if tcp.PSH {
				conn.Client.PSH++
			}
			if tcp.URG {
				conn.Client.URG++
			}
		}
	}
}
