package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
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

	version = "v0.2.1" // Update this to the latest version of your script
)

func main() {
	wg := &sync.WaitGroup{}
	lock := &sync.Mutex{}
	for _, machine := range machines {
		wg.Add(1)
		func(machine string) {
			defer wg.Done()
			lock.Lock()
			fmt.Printf("Updating %s...\n", machine)
			lock.Unlock()
			cmd := exec.Command("ssh",
				"-A",
				machine,
				"-t",
				`sh -c "$(curl -fsSL https://github.com/mat285/linklan/releases/download/`+version+`/install.sh)"`,
				// `sudo sh -c 'mkdir -p /etc/prometheus/node_exporter/textfile_collector'`,
			)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			cmd.Env = append(os.Environ(), `SUDO_OPTS="-S"`)
			err := cmd.Run()
			// output, err := cmd.CombinedOutput()
			// lock.Lock()
			// fmt.Println(string(output))
			// lock.Unlock()
			if err != nil {
				fmt.Printf("Error running command on %s: %v\n", machine, err)
				os.Exit(1)
			}
			lock.Lock()
			fmt.Printf("Successfully updated %s\n", machine)
			lock.Unlock()
		}(machine)
	}
	wg.Wait()
}
