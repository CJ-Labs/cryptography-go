// cmd/verifier/verifier.go
package verifier

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/consensys/gnark/backend/groth16"
)

func Run(args []string) {
	flags := flag.NewFlagSet("verifier", flag.ExitOnError)

	var (
		proofFile string
		keyFile   string
	)

	flags.StringVar(&proofFile, "proof", "proof.json", "proof file to verify")
	flags.StringVar(&keyFile, "key", "verifying.key", "verification key file")

	if err := flags.Parse(args); err != nil {
		fmt.Printf("failed to parse flags: %v\n", err)
		os.Exit(1)
	}

	// 1. 加载验证密钥
	vkBytes, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Printf("failed to read verification key: %v\n", err)
		os.Exit(1)
	}

	var vk groth16.VerifyingKey
	if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		fmt.Printf("failed to parse verification key: %v\n", err)
		os.Exit(1)
	}

	// 2. 加载证明
	proofBytes, err := os.ReadFile(proofFile)
	if err != nil {
		fmt.Printf("failed to read proof: %v\n", err)
		os.Exit(1)
	}

	var proof groth16.Proof
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		fmt.Printf("failed to parse proof: %v\n", err)
		os.Exit(1)
	}

	// 3. 验证证明
	if err := groth16.Verify(&proof, &vk, nil); err != nil {
		fmt.Printf("proof verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Proof verified successfully!")
}
