// pkg/types/types.go
package types

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Constants
const (
	MerkleTreeDepth = 20   // Merkle树深度
	MaxUsers        = 1000 // 最大用户数
	CollateralRate  = 1.5  // 最低抵押率
)

// UserAsset 用户资产信息
type UserAsset struct {
	Equity     *big.Int // 权益
	Debt       *big.Int // 债务
	Collateral *big.Int // 抵押品
}

// UserInfo 用户完整信息
type UserInfo struct {
	UserId      string    // 用户ID
	Asset       UserAsset // 用户资产
	MerkleProof [][]byte  // Merkle证明路径
	Index       uint64    // 用户在Merkle树中的索引
}

// ExchangeInfo 交易所资产信息
type ExchangeInfo struct {
	TotalEquity     *big.Int            // 总权益
	TotalDebt       *big.Int            // 总债务
	TotalCollateral *big.Int            // 总抵押品
	MerkleRoot      []byte              // Merkle树根
	UserCount       uint64              // 用户总数
	AssetPrices     map[string]*big.Int // 资产价格
}

// ProofInput 证明输入数据
type ProofInput struct {
	Users    []UserInfo   // 用户列表
	Exchange ExchangeInfo // 交易所信息
	BatchId  uint64       // 批次ID
}

// ProofOutput 证明输出数据
type ProofOutput struct {
	Proof      []byte // 证明数据
	PublicData struct {
		MerkleRoot      []byte   // Merkle树根
		TotalEquity     *big.Int // 总权益
		TotalDebt       *big.Int // 总债务
		TotalCollateral *big.Int // 总抵押品
		BatchId         uint64   // 批次ID
	}
}

type Circuit interface {
	frontend.Circuit
	New() Circuit
}
