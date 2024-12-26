// internal/merkle/tree.go
package merkle

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/consensys/gnark-crypto/hash"

	"zk-solvency-demo/pkg/types"
)

// MerkleTree 实现了一个基于Poseidon哈希的Merkle树
type MerkleTree struct {
	depth  uint64
	leaves [][]byte
	nodes  [][][]byte
	hasher hash.Hash
}

// NewMerkleTree 创建一个新的Merkle树
func NewMerkleTree(depth uint64) *MerkleTree {
	nodes := make([][][]byte, depth+1)
	for i := range nodes {
		nodes[i] = make([][]byte, 1<<i)
	}

	return &MerkleTree{
		depth:  depth,
		nodes:  nodes,
		hasher: poseidon.New(),
	}
}

// AddLeaf 添加叶子节点
func (t *MerkleTree) AddLeaf(index uint64, data *types.UserAsset) error {
	if index >= 1<<t.depth {
		return errors.New("index out of range")
	}

	// 将用户资产转换为Field元素
	equity := new(fr.Element).SetBigInt(data.Equity)
	debt := new(fr.Element).SetBigInt(data.Debt)
	collateral := new(fr.Element).SetBigInt(data.Collateral)

	// 计算叶子节点哈希
	t.hasher.Reset()
	t.hasher.Write(equity.Bytes())
	t.hasher.Write(debt.Bytes())
	t.hasher.Write(collateral.Bytes())

	leaf := t.hasher.Sum(nil)
	t.leaves = append(t.leaves, leaf)
	t.nodes[t.depth][index] = leaf

	return nil
}

// CalculateRoot 计算Merkle树根
func (t *MerkleTree) CalculateRoot() []byte {
	for level := t.depth; level > 0; level-- {
		for i := uint64(0); i < 1<<(level-1); i++ {
			t.hasher.Reset()
			left := t.nodes[level][2*i]
			right := t.nodes[level][2*i+1]

			t.hasher.Write(left)
			t.hasher.Write(right)

			t.nodes[level-1][i] = t.hasher.Sum(nil)
		}
	}

	return t.nodes[0][0]
}

// GenerateProof 生成Merkle证明
func (t *MerkleTree) GenerateProof(index uint64) ([][]byte, error) {
	if index >= 1<<t.depth {
		return nil, errors.New("index out of range")
	}

	proof := make([][]byte, t.depth)
	for level := t.depth; level > 0; level-- {
		siblingIndex := index ^ 1 // 获取兄弟节点索引
		proof[level-1] = t.nodes[level][siblingIndex]
		index = index >> 1 // 移动到父节点
	}

	return proof, nil
}

// VerifyProof 验证Merkle证明
func (t *MerkleTree) VerifyProof(leaf []byte, index uint64, proof [][]byte, root []byte) bool {
	currentHash := leaf

	for i := 0; i < len(proof); i++ {
		t.hasher.Reset()
		if index&1 == 0 {
			t.hasher.Write(currentHash)
			t.hasher.Write(proof[i])
		} else {
			t.hasher.Write(proof[i])
			t.hasher.Write(currentHash)
		}
		currentHash = t.hasher.Sum(nil)
		index >>= 1
	}

	return string(currentHash) == string(root)
}
