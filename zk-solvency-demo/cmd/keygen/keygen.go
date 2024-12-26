// cmd/keygen/keygen.go
package keygen

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zk-solvency-demo/internal/circuit"
	"zk-solvency-demo/pkg/types"
)

func Run(args []string) {
	flags := flag.NewFlagSet("keygen", flag.ExitOnError)

	var (
		outputDir   string
		batchSize   int
		merkleDepth int
	)

	flags.StringVar(&outputDir, "out", "keys", "output directory for keys")
	flags.IntVar(&batchSize, "batch", 100, "batch size for proof generation")
	flags.IntVar(&merkleDepth, "depth", types.MerkleTreeDepth, "merkle tree depth")

	if err := flags.Parse(args); err != nil {
		fmt.Printf("failed to parse flags: %v\n", err)
		os.Exit(1)
	}

	// 1. 创建输出目录
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// 2. 创建电路实例
	solvencyCircuit := &circuit.SolvencyCircuit{
		Users: make([]struct {
			Equity      frontend.Variable
			Debt        frontend.Variable
			Collateral  frontend.Variable
			Index       frontend.Variable
			MerkleProof []frontend.Variable
		}, batchSize),
	}

	// 为每个用户设置Merkle证明路径长度
	for i := range solvencyCircuit.Users {
		solvencyCircuit.Users[i].MerkleProof = make([]frontend.Variable, merkleDepth)
	}

	// 3. 编译电路
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, solvencyCircuit)
	if err != nil {
		fmt.Printf("circuit compilation failed: %v\n", err)
		os.Exit(1)
	}

	// 4. 生成Groth16密钥对
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Printf("setup failed: %v\n", err)
		os.Exit(1)
	}

	// 5. 序列化并保存密钥
	pkPath := filepath.Join(outputDir, fmt.Sprintf("proving_%d.key", batchSize))
	vkPath := filepath.Join(outputDir, fmt.Sprintf("verifying_%d.key", batchSize))

	// 序列化proving key
	var pkBuf bytes.Buffer
	if _, err := pk.WriteTo(&pkBuf); err != nil {
		fmt.Printf("failed to serialize proving key: %v\n", err)
		os.Exit(1)
	}

	// 序列化verification key
	var vkBuf bytes.Buffer
	if _, err := vk.WriteTo(&vkBuf); err != nil {
		fmt.Printf("failed to serialize verification key: %v\n", err)
		os.Exit(1)
	}

	// 保存密钥文件
	if err := os.WriteFile(pkPath, pkBuf.Bytes(), 0644); err != nil {
		fmt.Printf("failed to save proving key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(vkPath, vkBuf.Bytes(), 0644); err != nil {
		fmt.Printf("failed to save verification key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Keys generated successfully for batch size %d!\n", batchSize)
	fmt.Printf("Proving key: %s\n", pkPath)
	fmt.Printf("Verifying key: %s\n", vkPath)
}
