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

func saveTCPMetrics(traceName string) error {
	dir := traceName + ".out"
	out := filepath.Join(dir, "log_tcp_complete")

	// Create the folder if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("[ERR]: %s", err)
	}

	// Open the file for writing
	file, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("[ERR]: %s", err)
	}
	defer file.Close()

	// Write the header
	header := "srcip dstip srcport dstport " +
		"client_packs client_bytes client_packs_data client_bytes_data " +
		"server_packs server_bytes server_packs_data server_bytes_data " +
		"start_time end_time " +
		"client_SYN client_ACK client_FIN client_RST client_URG client_PSH " +
		"server_SYN server_ACK server_FIN server_RST server_URG server_PSH\n"

	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("[ERR]: %s", err)
	}

	// Write the metrics
	for key, connection := range metrics.TCPConnections {
		line := fmt.Sprintf("%s %s %s %s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",
			key.SrcIP,
			key.DstIP,
			key.SrcPort,
			key.DstPort,
			connection.Client.Packs,
			connection.Client.Bytes,
			connection.Client.PayloadPacks,
			connection.Client.PayloadBytes,
			connection.Server.Packs,
			connection.Server.Bytes,
			connection.Server.PayloadPacks,
			connection.Server.PayloadBytes,
			connection.Ts,
			connection.Te,
			connection.Client.SYN,
			connection.Client.ACK,
			connection.Client.FIN,
			connection.Client.RST,
			connection.Client.URG,
			connection.Client.PSH,
			connection.Server.SYN,
			connection.Server.ACK,
			connection.Server.FIN,
			connection.Server.RST,
			connection.Server.URG,
			connection.Server.PSH,
		)

		if _, err := file.WriteString(line); err != nil {
			return fmt.Errorf("[ERR]: %s", err)
		}
	}
	return nil
}

func main() {
	// Print Title
	display.PrintAsciiArt()

	// variables declaration
	var pcapTrace string
	var cidr string

	// Flags declaration using flag package
	flag.StringVar(&pcapTrace, "i", "", "Specify input trace file (e.g., example.pcap).")
	flag.StringVar(&cidr, "n", "", "Specify the network CIDR (e.g., 192.168.200.0/24).")

	// Flags parsing
	flag.Parse()

	// Check command line arguments
	if pcapTrace == "" || cidr == "" {
		fmt.Println("[ERR]: Both input trace file and CIDR block must be specified.")
		fmt.Println("[LOG]: Usage: goostat --u <pcap_file> --p <local_network_cidr>")
		return
	}

	// Open the pcap file
	handle, err := pcap.OpenOffline(pcapTrace)
	if err != nil {
		fmt.Printf("[ERR]: %s\n", err)
		return
	}

	// Count how many packets
	packetCount := 0
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for range source.Packets() {
		packetCount++
	}

	// Print the number of packets in the trace
	fmt.Printf("[LOG] Goostat is about to process %d packets from trace\n", packetCount)

	// Open the pcap file
	handle, err = pcap.OpenOffline(pcapTrace)
	if err != nil {
		fmt.Printf("[ERR]: %s\n", err)
		return
	}

	// Process each packet and show progress
	source = gopacket.NewPacketSource(handle, handle.LinkType())
	packets := 0
	for packet := range source.Packets() {
		// Process only TCP packets
		if packet.Layer(layers.LayerTypeTCP) != nil {
			packet_processing.ProcessTCPPacket(packet)
		}
		packets++

		// Update and print progress bar
		display.PrintProgressBar(packets, packetCount)
	}

	// Close the capture
	handle.Close()

	// Extract the trace name from the pcap file
	basePath := filepath.Base(pcapTrace)
	name := basePath[:len(basePath)-len(filepath.Ext(basePath))]

	// Print the results
	err = saveTCPMetrics(name)
	if err != nil {
		fmt.Printf("[ERR]: %s\n", err)
		return
	}

	fmt.Println("All done!")
}
