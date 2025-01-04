package display

import (
	"fmt"
)

// Print the ASCII art for "Goostat"
func PrintAsciiArt() {
	fmt.Println(`
 _____ ____  ____  ____  _____  ____  _____ 
/  __//  _ \/  _ \/ ___\/__ __\/  _ \/__ __\
| |  _| / \|| / \||    \  / \  | / \|  / \  
| |_//| \_/|| \_/|\___ |  | |  | |-||  | |  
\____\\____/\____/\____/  \_/  \_/ \|  \_/  
`)
}

// Print the progress bar for packet processing
func PrintProgressBar(processed, total int) {
	prog := float64(processed) / float64(total) * 100
	blen := 50 // Length of the progress bar
	progressBar := "["

	// Calculate how many blocks to show
	progressBlocks := int(prog / (100 / float64(blen)))
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
