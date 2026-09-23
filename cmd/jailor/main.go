package main

import (
	"os"

	"jailor/internal/cli"
)

func main() {
	os.Exit(cli.New().Run(os.Args[1:]))
}
