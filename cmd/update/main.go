package main

import (
	"fmt"
	"os"
	"os/exec"
)

var (
	machines = []string{
		"node0",
		"node1",
		"node2",
		"node3",
		"node4",
		"node5",
		"node6",
		"node7",
		"worker0",
		"zstation",
	}

	version = "v0.2.0" // Update this to the latest version of your script
)

func main() {
	// fmt.Println("Sudo password")
	// pwd, err := term.ReadPassword(0)
	// if err != nil {
	// 	fmt.Println("Error reading password:", err)
	// 	os.Exit(1)
	// }

	for _, machine := range machines {
		fmt.Printf("Updating %s...\n", machine)
		cmd := exec.Command("ssh",
			"-A",
			machine,
			"-t",
			`sh -c "$(curl -fsSL https://github.com/mat285/linklan/releases/download/`+version+`/install.sh)"`,
		)
		cmd.Env = append(os.Environ(), `SUDO_OPTS="-S"`)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			fmt.Printf("Error running command on %s: %v\n", machine, err)
			os.Exit(1)
			continue
		}
		fmt.Printf("Successfully updated %s\n", machine)
	}
}
