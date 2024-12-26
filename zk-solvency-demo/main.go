// main.go
package main

import (
	"fmt"
	"os"

	"zk-solvency-demo/cmd/keygen"
	"zk-solvency-demo/cmd/prover"
	"zk-solvency-demo/cmd/verifier"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		keygen.Run(os.Args[2:])
	case "prove":
		prover.Run(os.Args[2:])
	case "verify":
		verifier.Run(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: zk-solvency-demo <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  keygen  Generate proving and verifying keys")
	fmt.Println("  prove   Generate zero-knowledge proof")
	fmt.Println("  verify  Verify zero-knowledge proof")
	fmt.Println("\nRun 'zk-solvency-demo <command> -h' for command specific help")
}
