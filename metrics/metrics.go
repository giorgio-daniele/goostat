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

// TCPFlowMetrics stores the packet and byte counters for a connection
type TCPFlowMetrics struct {
	Packs        int // Total packets
	Bytes        int // Total bytes
	PayloadPacks int // Packets with payload
	PayloadBytes int // Bytes from payload
	SYN          int // SYN flag packets
	ACK          int // ACK flag packets
	FIN          int // FIN flag packets
	RST          int // RST flag packets
	URG          int // URG flag packets
	PSH          int // PSH flag packets
}

// TCPConnection holds metrics for both client and server
type TCPConnection struct {
	Client TCPFlowMetrics
	Server TCPFlowMetrics
	Ts     int64
	Te     int64
}

var TCPConnections = make(map[Key]*TCPConnection)

// Helper function to get a key for a connection
func GetConnectionKey(ip4 *layers.IPv4, tcp *layers.TCP, reverse bool) Key {
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
