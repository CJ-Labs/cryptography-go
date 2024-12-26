// internal/witness/generator.go
package witness

import (
	"zk-solvency-demo/internal/circuit"
	"zk-solvency-demo/pkg/types"

	"github.com/consensys/gnark/frontend"
)

// Generator Witness生成器
type Generator struct {
	circuit circuit.SolvencyCircuit
}

// NewGenerator 创建新的Witness生成器
func NewGenerator(circuit circuit.SolvencyCircuit) *Generator {
	return &Generator{
		circuit: circuit,
	}
}

// GenerateWitness 生成witness数据
func (g *Generator) GenerateWitness(input *types.ProofInput) (frontend.Circuit, error) {
	witness := g.circuit.New()

	// 1. 设置公开输入
	witness.TotalEquity = input.Exchange.TotalEquity
	witness.TotalDebt = input.Exchange.TotalDebt
	witness.TotalCollateral = input.Exchange.TotalCollateral
	witness.MerkleRoot = input.Exchange.MerkleRoot
	witness.BatchId = input.BatchId

	// 2. 设置私密输入
	for i, user := range input.Users {
		witness.Users[i].Equity = user.Asset.Equity
		witness.Users[i].Debt = user.Asset.Debt
		witness.Users[i].Collateral = user.Asset.Collateral
		witness.Users[i].Index = user.Index

		// 设置Merkle证明
		copy(witness.Users[i].MerkleProof, user.MerkleProof)
	}

	return witness, nil
}

// VerifyWitness 验证witness是否满足约束
func (g *Generator) VerifyWitness(witness frontend.Circuit) error {
	// 验证witness格式
	if err := frontend.CheckWitness(witness); err != nil {
		return err
	}

	return nil
}
