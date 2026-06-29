package main

import (
	"os"

	"github.com/Shotafry/talos/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
