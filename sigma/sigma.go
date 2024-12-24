package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// SigmaProtocol 实现零知识证明协议
type SigmaProtocol struct {
	G *bn254.G1Affine
}

// Prover 证明者结构体
type Prover struct {
	privateKey *fr.Element     // 是要证明知道但不泄露的私钥
	publicKey  *bn254.G1Affine // 是对应的公钥 Q = privateKey * G
	r          *fr.Element     // 随机数
	A          *bn254.G1Affine // 承诺值 A = r * G + Q
}

// 创建新的证明者
func NewProver(privateKey *fr.Element) *Prover {
	// 计算公钥
	var publickey bn254.G1Affine
	publickey.ScalarMultiplication(&bn254.G1Affine{}, privateKey.BigInt(new(big.Int)))

	return &Prover{
		privateKey: privateKey,
		publicKey:  &publickey,
	}
}

// Commit 承诺阶段
func (p *Prover) Commit() *bn254.G1Affine {
	// 生成随机数 r
	p.r, _ = new(fr.Element).SetRandom()

	// 计算承诺值 A = r * G
	var A bn254.G1Affine

	A.ScalarMultiplication(&bn254.G1Affine{}, p.r.BigInt(new(big.Int)))

	p.A = &A
	return p.A
}

// Response 响应阶段
func (p *Prover) Response(challenge *fr.Element) *fr.Element {
	// 计算响应值  z = r + e * privateKey
	z := new(fr.Element).Mul(challenge, p.privateKey)
	z.Add(z, p.r)
	return z
}

// Vertifier 验证者结构体
type Vertifier struct{}

// Challenge 生成随机挑战 随机数 e
func (v *Vertifier) Challenge() *fr.Element {
	challenge, _ := new(fr.Element).SetRandom()
	return challenge
}

// Verify 验证阶段
func (v *Vertifier) Verify(
	publicKey *bn254.G1Affine, // Q 公钥
	A *bn254.G1Affine, // 承诺值 A
	challenge *fr.Element, // 随机数 e
	response *fr.Element, // 响应值 z
) bool {
	// 验证 z * G == A + e * Q
	var left, right bn254.G1Affine
	// 计算左边
	left.ScalarMultiplication(&bn254.G1Affine{}, response.BigInt(new(big.Int)))
	// 计算右边 A + e * Q
	right.ScalarMultiplication(publicKey, challenge.BigInt(new(big.Int)))
	right.Add(&right, A)

	return left.Equal(&right)
}

func main() {
	// 1. 初始化
	privateKey, _ := new(fr.Element).SetRandom()
	prover := NewProver(privateKey)
	vertifier := &Vertifier{}

	// 2. 承诺阶段
	A := prover.Commit()

	// 3. 挑战
	challenge := vertifier.Challenge()
	// 4. 响应
	response := prover.Response(challenge)
	// 5. 验证
	isValid := vertifier.Verify(prover.publicKey, A, challenge, response)

	// 验证结果
	if isValid {
		println("验证通过!")
	} else {
		println("验证失败!")
	}
}
