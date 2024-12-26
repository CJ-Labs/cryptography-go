// internal/r1cs/generator.go
package r1cs

import (
	"zk-solvency-demo/pkg/types"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/consensys/gnark/frontend"
)

// Generator R1CS约束系统生成器
type Generator struct {
	api     frontend.API
	circuit *types.Circuit
}

// NewGenerator 创建新的R1CS生成器
func NewGenerator(api frontend.API) *Generator {
	return &Generator{
		api: api,
	}
}

// GenerateConstraints 生成R1CS约束
func (g *Generator) GenerateConstraints(input *types.ProofInput) error {
	// 1. 资产平衡约束
	g.generateBalanceConstraints(input)

	// 2. 抵押率约束
	g.generateCollateralConstraints(input)

	// 3. Merkle树约束
	g.generateMerkleConstraints(input)

	return nil
}

// generateBalanceConstraints 生成资产平衡约束
func (g *Generator) generateBalanceConstraints(input *types.ProofInput) {
	sumEquity := frontend.Variable(0)
	sumDebt := frontend.Variable(0)
	sumCollateral := frontend.Variable(0)

	for _, user := range input.Users {
		// 累加用户资产
		sumEquity = g.api.Add(sumEquity, user.Asset.Equity)
		sumDebt = g.api.Add(sumDebt, user.Asset.Debt)
		sumCollateral = g.api.Add(sumCollateral, user.Asset.Collateral)
	}

	// 验证总和
	g.api.AssertIsEqual(sumEquity, input.Exchange.TotalEquity)
	g.api.AssertIsEqual(sumDebt, input.Exchange.TotalDebt)
	g.api.AssertIsEqual(sumCollateral, input.Exchange.TotalCollateral)
}

// generateCollateralConstraints 生成抵押率约束
func (g *Generator) generateCollateralConstraints(input *types.ProofInput) {
	for _, user := range input.Users {
		// 验证用户抵押率
		minCollateral := g.api.Mul(user.Asset.Debt, types.CollateralRate)
		g.api.AssertIsGreaterOrEqual(user.Asset.Collateral, minCollateral)
	}
}

// generateMerkleConstraints 生成Merkle树约束
func (g *Generator) generateMerkleConstraints(input *types.ProofInput) {
	poseidonHash := poseidon.NewPoseidon(g.api)

	for _, user := range input.Users {
		// 计算叶子节点哈希
		leaf := poseidonHash.Hash(
			user.Asset.Equity,
			user.Asset.Debt,
			user.Asset.Collateral,
		)

		// 验证Merkle路径
		currentHash := leaf
		for i, sibling := range user.MerkleProof {
			isLeft := (user.Index >> uint(i)) & 1
			if isLeft == 0 {
				currentHash = poseidonHash.Hash(currentHash, sibling)
			} else {
				currentHash = poseidonHash.Hash(sibling, currentHash)
			}
		}

		// 验证根哈希
		g.api.AssertIsEqual(currentHash, input.Exchange.MerkleRoot)
	}
}
