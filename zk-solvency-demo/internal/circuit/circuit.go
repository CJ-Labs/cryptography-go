// internal/circuit/circuit.go
package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/consensys/gnark/frontend"
)

// SolvencyCircuit 定义了偿付能力证明电路
type SolvencyCircuit struct {
	// 私密输入
	Users []struct {
		Equity      frontend.Variable   // 权益
		Debt        frontend.Variable   // 债务
		Collateral  frontend.Variable   // 抵押品
		Index       frontend.Variable   // Merkle树索引
		MerkleProof []frontend.Variable // Merkle证明路径
	}

	// 公开输入
	TotalEquity     frontend.Variable // 总权益
	TotalDebt       frontend.Variable // 总债务
	TotalCollateral frontend.Variable // 总抵押品
	MerkleRoot      frontend.Variable // Merkle树根
	BatchId         frontend.Variable // 批次ID
}

// Define 实现电路约束逻辑
func (c *SolvencyCircuit) Define(api frontend.API) error {
	// 1. 初始化哈希函数
	poseidonHash := poseidon.NewPoseidon()

	// 2. 初始化累加器
	sumEquity := frontend.Variable(0)
	sumDebt := frontend.Variable(0)
	sumCollateral := frontend.Variable(0)

	// 3. 验证每个用户
	for _, user := range c.Users {
		// 3.1 验证资产约束
		api.AssertIsLessOrEqual(user.Debt, user.Equity)

		// 3.2 验证抵押率
		minCollateral := api.Mul(user.Debt, 1.5)
		// 确保抵押品大于等于最小要求
		api.AssertIsLessOrEqual(minCollateral, user.Collateral)

		// 3.3 累加总和
		sumEquity = api.Add(sumEquity, user.Equity)
		sumDebt = api.Add(sumDebt, user.Debt)
		sumCollateral = api.Add(sumCollateral, user.Collateral)

		// 3.4 验证Merkle证明
		currentHash := poseidonHash.Hash(user.Equity, user.Debt, user.Collateral)

		// 根据索引位构建Merkle路径
		for i := 0; i < len(user.MerkleProof); i++ {
			// 获取索引的第i位
			// 使用除法和乘法来模拟位操作
			divisor := api.Sub(user.Index, api.Mul(api.Div(user.Index, frontend.Variable(1<<(i+1))), frontend.Variable(1<<(i+1))))
			indexBit := api.Div(divisor, frontend.Variable(1<<i))

			// 选择正确的哈希顺序
			leftInput := api.Select(indexBit, currentHash, user.MerkleProof[i])
			rightInput := api.Select(indexBit, user.MerkleProof[i], currentHash)
			currentHash = poseidonHash.Hash(leftInput, rightInput)
		}

		// 验证最终哈希等于根
		api.AssertIsEqual(currentHash, c.MerkleRoot)
	}

	// 4. 验证总量约束
	api.AssertIsEqual(sumEquity, c.TotalEquity)
	api.AssertIsEqual(sumDebt, c.TotalDebt)
	api.AssertIsEqual(sumCollateral, c.TotalCollateral)

	return nil
}

// New 创建新的电路实例
func (c *SolvencyCircuit) New() frontend.Circuit {
	return &SolvencyCircuit{
		Users: make([]struct {
			Equity      frontend.Variable
			Debt        frontend.Variable
			Collateral  frontend.Variable
			Index       frontend.Variable
			MerkleProof []frontend.Variable
		}, len(c.Users)),
	}
}
