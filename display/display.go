package display

import (
	"fmt"
)

// Headers for TCP and UDP logs
const (
	LogTCPCompleteHeader = "c_ip s_ip c_port s_port " +
		"c_packs c_bytes c_packs_data c_bytes_data " +
		"s_packs s_bytes s_packs_data s_bytes_data " +
		"ts te " +
		"c_SYN c_ACK c_FIN c_RST c_URG c_PSH " +
		"s_SYN s_ACK s_FIN s_RST s_URG s_PSH\n"

	LogUDPCompleteHeader = "c_ip s_ip c_port s_port " +
		"c_packs c_bytes " +
		"s_packs s_bytes " +
		"c_ts c_te s_ts s_te\n"
)

const Title = `
	_____ ____  ____  ____  _____  ____  _____ 
	/  __//  _ \/  _ \/ ___\/__ __\/  _ \/__ __\
	| |  _| / \|| / \||    \  / \  | / \|  / \  
	| |_//| \_/|| \_/|\___ |  | |  | |-||  | |  
	\____\\____/\____/\____/  \_/  \_/ \|  \_/  
`

// Print the ASCII art for "Goostat"
func PrintAsciiArt() {
	fmt.Println(Title)
}

// Print the progress bar for packet processing
func PrintProgressBar(processed, total int) {
	prog := float64(processed) / float64(total) * 100
	blen := 50 // Length of the progress bar
	progressBar := "["

	// Calculate how many blocks to show
	progressBlocks := int(prog * float64(blen) / 100)
	for i := 0; i < blen; i++ {
		if i < progressBlocks {
			progressBar += "="
		} else {
			progressBar += " "
		}
	}
	progressBar += fmt.Sprintf("] %.2f%%", prog)
	fmt.Printf("\r%s", progressBar) // Print on the same line
}
