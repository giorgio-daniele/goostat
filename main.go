package main

import (
	"flag"
	"fmt"
	"goostat/display"
	"goostat/metrics"
	"goostat/packet_processing"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func createFile(dir, filename string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	filePath := filepath.Join(dir, filename)
	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file %s: %w", filename, err)
	}

	return file, nil
}

func saveMetrics(traceName, filename, header string, dataFunc func() []string) error {
	dir := fmt.Sprintf("%s.out", traceName)

	file, err := createFile(dir, filename)
	if err != nil {
		return fmt.Errorf("[ERR]: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(header)
	if err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	for _, line := range dataFunc() {
		_, err := file.WriteString(line)
		if err != nil {
			return fmt.Errorf("failed to write data: %w", err)
		}
	}

	return nil
}

func formatTcpMetrics() []string {
	var lines []string

	for key, conn := range metrics.TcpConnections {
		lines = append(lines, fmt.Sprintf(
			"%s %s %s %s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",
			key.SrcIP, key.DstIP, key.SrcPort, key.DstPort,
			conn.Client.Packs,
			conn.Client.Bytes,
			conn.Client.PayloadPacks,
			conn.Client.PayloadBytes,
			conn.Server.Packs,
			conn.Server.Bytes,
			conn.Server.PayloadPacks,
			conn.Server.PayloadBytes,
			conn.Ts, conn.Te,
			conn.Client.SYN, conn.Client.ACK,
			conn.Client.FIN, conn.Client.RST,
			conn.Client.URG, conn.Client.PSH,
			conn.Server.SYN, conn.Server.ACK,
			conn.Server.FIN, conn.Server.RST,
			conn.Server.URG, conn.Server.PSH,
		))
	}
	return lines
}

func formatUdpMetrics() []string {
	var lines []string

	for key, conn := range metrics.UdpConnections {
		lines = append(lines, fmt.Sprintf(
			"%s %s %s %s %d %d %d %d %d %d %d %d\n",
			key.SrcIP, key.DstIP, key.SrcPort, key.DstPort,
			conn.Client.Packs,
			conn.Client.Bytes,
			conn.Server.Packs,
			conn.Server.Bytes,
			conn.Client.Ts, conn.Client.Te,
			conn.Server.Ts, conn.Server.Te,
		))
	}
	return lines
}

func processPackets(handle *pcap.Handle, totalPackets int) error {
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := 0

	for packet := range source.Packets() {
		switch {
		case packet.Layer(layers.LayerTypeTCP) != nil:
			packet_processing.ProcessTcpPacket(packet)

		case packet.Layer(layers.LayerTypeUDP) != nil:
			packet_processing.ProcessUdpPacket(packet)
		}

		packets++
		display.PrintProgressBar(packets, totalPackets)
	}

	return nil
}

func countPackets(handle *pcap.Handle) (int, error) {
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	count := 0

	for range source.Packets() {
		count++
	}

	return count, nil
}

func main() {
	display.PrintAsciiArt()

	var pcapTrace string

	flag.StringVar(&pcapTrace, "i", "", "Specify input trace file (e.g., example.pcap).")
	flag.Parse()

	if pcapTrace == "" {
		fmt.Println("[ERR]: Input trace file must be specified.")
		fmt.Println("[LOG]: Usage: goostat --i <pcap_file>")
		return
	}

	handle, err := pcap.OpenOffline(pcapTrace)
	if err != nil {
		fmt.Printf("[ERR]: failed to open file: %v\n", err)
		return
	}
	defer handle.Close()

	packetCount, err := countPackets(handle)
	if err != nil {
		fmt.Printf("[ERR]: failed to count packets: %v\n", err)
		return
	}

	fmt.Printf("[LOG]: Processing %d packets from trace\n", packetCount)

	handle, err = pcap.OpenOffline(pcapTrace)
	if err != nil {
		fmt.Printf("[ERR]: failed to reopen file: %v\n", err)
		return
	}
	defer handle.Close()

	err = processPackets(handle, packetCount)
	if err != nil {
		fmt.Printf("[ERR]: failed to process packets: %v\n", err)
		return
	}

	traceName := filepath.Base(pcapTrace[:len(pcapTrace)-len(filepath.Ext(pcapTrace))])

	err = saveMetrics(traceName, "log_tcp_complete", display.LogTCPCompleteHeader, formatTcpMetrics)
	if err != nil {
		fmt.Printf("[ERR]: failed to save TCP metrics: %v\n", err)
		return
	}

	err = saveMetrics(traceName, "log_udp_complete", display.LogUDPCompleteHeader, formatUdpMetrics)
	if err != nil {
		fmt.Printf("[ERR]: failed to save UDP metrics: %v\n", err)
		return
	}

	fmt.Println("\n")
}
