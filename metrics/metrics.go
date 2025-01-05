package metrics

import (
	"fmt"

	"github.com/google/gopacket/layers"
)

// Key represents the unique key for each connection (client-server)
type Key struct {
	SrcIP   string
	DstIP   string
	SrcPort string
	DstPort string
}

// TcpFlowMetrics stores the packet and byte counters for a connection
type TcpFlowMetrics struct {
	Packs        int // Total TCP packets (including signaling packets)
	Bytes        int // Total TCP bytes (including the header)
	PayloadPacks int // TCP packets with payload
	PayloadBytes int // TCP bytes as payload
	SYN          int // SYN flag packets
	ACK          int // ACK flag packets
	FIN          int // FIN flag packets
	RST          int // RST flag packets
	URG          int // URG flag packets
	PSH          int // PSH flag packets
}

// UdpFlowMetrics stores the packet and byte counters for a connection
type UdpFlowMetrics struct {
	Packs int   // Total packets
	Bytes int   // Total bytes
	Last  int64 // Last packet observed
	Ts    int64 // When the flow starts
	Te    int64 // When the flow ends
}

// TcpConnection holds metrics for both client and server
type TcpConnection struct {
	Client TcpFlowMetrics
	Server TcpFlowMetrics
	Ts     int64 // When the connection starts
	Te     int64 // When the connection ends
}

// UdpConnection holds metrics for both client and server
type UdpConnection struct {
	Client UdpFlowMetrics
	Server UdpFlowMetrics
}

// Global variables
var TcpConnections = make(map[Key]*TcpConnection)
var UdpConnections = make(map[Key]*UdpConnection)

// Helper function to get a key for a connection
func GetConnectionKeyTcp(ip4 *layers.IPv4, tcp *layers.TCP, reverse bool) Key {
	if reverse {
		return Key{
			SrcIP:   ip4.DstIP.String(),
			DstIP:   ip4.SrcIP.String(),
			SrcPort: fmt.Sprintf("%d", tcp.DstPort),
			DstPort: fmt.Sprintf("%d", tcp.SrcPort),
		}
	}
	return Key{
		SrcIP:   ip4.SrcIP.String(),
		DstIP:   ip4.DstIP.String(),
		SrcPort: fmt.Sprintf("%d", tcp.SrcPort),
		DstPort: fmt.Sprintf("%d", tcp.DstPort),
	}
}

func GetConnectionKeyUdp(ip4 *layers.IPv4, udp *layers.UDP, reverse bool) Key {
	if reverse {
		return Key{
			SrcIP:   ip4.DstIP.String(),
			DstIP:   ip4.SrcIP.String(),
			SrcPort: fmt.Sprintf("%d", udp.DstPort),
			DstPort: fmt.Sprintf("%d", udp.SrcPort),
		}
	}
	return Key{
		SrcIP:   ip4.SrcIP.String(),
		DstIP:   ip4.DstIP.String(),
		SrcPort: fmt.Sprintf("%d", udp.SrcPort),
		DstPort: fmt.Sprintf("%d", udp.DstPort),
	}
}
