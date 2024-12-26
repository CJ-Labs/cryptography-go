// cmd/prover/prover.go
package prover

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark/backend/groth16"

	"zk-solvency-demo/internal/merkle"
	"zk-solvency-demo/internal/witness"
	"zk-solvency-demo/pkg/types"
)

func Run(args []string) {
	flags := flag.NewFlagSet("prover", flag.ExitOnError)

	var (
		inputFile  string
		keyDir     string
		outputFile string
		batchSize  int
	)

	flags.StringVar(&inputFile, "input", "input.json", "input data file")
	flags.StringVar(&keyDir, "keys", "keys", "directory containing proving keys")
	flags.StringVar(&outputFile, "output", "proof.json", "output proof file")
	flags.IntVar(&batchSize, "batch", 100, "batch size for proof generation")

	if err := flags.Parse(args); err != nil {
		fmt.Printf("failed to parse flags: %v\n", err)
		os.Exit(1)
	}

	// 1. 读取输入数据
	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("failed to read input file: %v\n", err)
		os.Exit(1)
	}

	var proofInput types.ProofInput
	if err := json.Unmarshal(inputData, &proofInput); err != nil {
		fmt.Printf("failed to parse input data: %v\n", err)
		os.Exit(1)
	}

	// 2. 构建Merkle树
	tree := merkle.NewMerkleTree(types.MerkleTreeDepth)
	for i, user := range proofInput.Users {
		if err := tree.AddLeaf(uint64(i), &user.Asset); err != nil {
			fmt.Printf("failed to add leaf: %v\n", err)
			os.Exit(1)
		}
	}

	// 3. 计算Merkle根和证明
	root := tree.CalculateRoot()
	for i := range proofInput.Users {
		proof, err := tree.GenerateProof(uint64(i))
		if err != nil {
			fmt.Printf("failed to generate proof: %v\n", err)
			os.Exit(1)
		}
		proofInput.Users[i].MerkleProof = proof
	}

	// 4. 生成witness
	witnessGen := witness.NewGenerator(nil) // TODO: 添加电路
	witness, err := witnessGen.GenerateWitness(&proofInput)
	if err != nil {
		fmt.Printf("failed to generate witness: %v\n", err)
		os.Exit(1)
	}

	// 5. 加载证明密钥
	pkPath := filepath.Join(keyDir, fmt.Sprintf("proving_%d.key", batchSize))
	pkBytes, err := os.ReadFile(pkPath)
	if err != nil {
		fmt.Printf("failed to read proving key: %v\n", err)
		os.Exit(1)
	}

	var pk groth16.ProvingKey
	if _, err := pk.ReadFrom(bytes.NewReader(pkBytes)); err != nil {
		fmt.Printf("failed to parse proving key: %v\n", err)
		os.Exit(1)
	}

	// 6. 生成证明
	proof, err := groth16.Prove(witness, pk)
	if err != nil {
		fmt.Printf("proof generation failed: %v\n", err)
		os.Exit(1)
	}

	// 7. 序列化并保存证明
	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		fmt.Printf("failed to serialize proof: %v\n", err)
		os.Exit(1)
	}

	proofOutput := types.ProofOutput{
		Proof: proofBuf.Bytes(),
		PublicData: struct {
			MerkleRoot      []byte
			TotalEquity     *big.Int
			TotalDebt       *big.Int
			TotalCollateral *big.Int
			BatchId         uint64
		}{
			MerkleRoot:      root,
			TotalEquity:     proofInput.Exchange.TotalEquity,
			TotalDebt:       proofInput.Exchange.TotalDebt,
			TotalCollateral: proofInput.Exchange.TotalCollateral,
			BatchId:         proofInput.BatchId,
		},
	}

	outputBytes, err := json.MarshalIndent(proofOutput, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal proof output: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outputFile, outputBytes, 0644); err != nil {
		fmt.Printf("failed to save proof: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Proof generated successfully!")
}
