package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// KZG 结构体存储承诺方案所需的参数
// G1Powers 存储 G1 群上的幂次序列：[G, τG, τ²G, ..., τⁿG]
// 其中 G 是 G1 群的生成元，τ 是可信设置的随机值
// G2Powers 存储 G2 群上的幂次：[H, τH]
// 其中 H 是 G2 群的生成元
// MaxDegree 表示支持的最大多项式度
// Modulus 存储有限域的模数
type KZG struct {
	G1Powers  []bn254.G1Affine
	G2Powers  []bn254.G2Affine
	MaxDegree int
	Modulus   *big.Int
}

// Polynomial 表示要承诺的多项式
// 例如：对于多项式 f(x) = 1 + 2x + 3x²
// Coefficients 将存储 [1, 2, 3]
type Polynomial struct {
	Coefficients []fr.Element
}

// Commitment 表示对多项式的承诺
// 这是一个 G1 群上的点，可以理解为多项式的"指纹"
type Commitment struct {
	Value bn254.G1Affine
}

// Proof 表示在某点的求值证明
// Value 多项式在指定点的值 f(z)
// ProofG1 证明值 π，用于验证 f(z) 的正确性
type Proof struct {
	Value   fr.Element
	ProofG1 bn254.G1Affine
}

// Setup 执行可信设置，生成 SRS (Structured Reference String)
// maxDegree: 支持的最大多项式度
// 返回：初始化的 KZG 结构体和可能的错误
func Setup(maxDegree int) (*KZG, error) {
	// 获取有限域的模数
	modulus := fr.Modulus()

	// 生成随机 τ (在实际场景中应通过可信设置仪式生成)
	// τ 是一个秘密值，生成后必须销毁，否则整个系统的安全性将被破坏
	tau, err := rand.Int(rand.Reader, modulus)
	if err != nil {
		return nil, err
	}

	kzg := &KZG{
		G1Powers:  make([]bn254.G1Affine, maxDegree+1),
		G2Powers:  make([]bn254.G2Affine, 2),
		MaxDegree: maxDegree,
		Modulus:   modulus,
	}

	// 生成 G1 幂次序列
	var g1Gen bn254.G1Affine
	// 使用 BN254 的标准生成器点
	g1Gen.X.SetString("1")
	g1Gen.Y.SetString("2")

	// 计算 [G, τG, τ²G, ..., τⁿG]
	currentTau := new(big.Int).SetInt64(1)
	for i := 0; i <= maxDegree; i++ {
		var tmp bn254.G1Affine
		tmp.ScalarMultiplication(&g1Gen, currentTau)
		kzg.G1Powers[i] = tmp
		currentTau.Mul(currentTau, tau)
		currentTau.Mod(currentTau, modulus)
	}

	// 生成 G2 幂次
	var g2Gen bn254.G2Affine
	// 使用 BN254 的标准生成器点
	g2Gen.X.SetString("10857046999023057135944570762232829481370756359578518086990519993285655852781", "11559732032986387107991004021392285783925812861821192530917403151452391805634")
	g2Gen.Y.SetString("8495653923123431417604973247489272438418190587263600148770280649306958101930", "4082367875863433681332203403145435568316851327593401208105741076214120093531")

	kzg.G2Powers[0] = g2Gen
	var tauG2 bn254.G2Affine
	tauG2.ScalarMultiplication(&g2Gen, tau)
	kzg.G2Powers[1] = tauG2

	return kzg, nil
}

// NewPolynomial 创建新的多项式
// coeffs: 多项式的系数数组，例如 [1, 2, 3] 表示 1 + 2x + 3x²
func NewPolynomial(coeffs []int64) *Polynomial {
	coefficients := make([]fr.Element, len(coeffs))
	for i, c := range coeffs {
		coefficients[i].SetInt64(c)
		// 打印每个系数的设置
		fmt.Printf("设置系数[%d] = %d, 结果: %s\n", i, c, coefficients[i].String())
	}
	return &Polynomial{Coefficients: coefficients}
}

// Evaluate 在指定点评估多项式的值
// z: 要评估的点
// 返回：f(z) 的值
func (poly *Polynomial) Evaluate(z *fr.Element) *fr.Element {
	result := new(fr.Element).SetZero()
	zPower := new(fr.Element).SetOne()

	fmt.Println("\n多项式求值过程：")
	for i, coeff := range poly.Coefficients {
		// 计算每一项 coeff * z^i
		tmp := new(fr.Element).Mul(&coeff, zPower)
		result.Add(result, tmp)
		fmt.Printf("项[%d]: coeff=%s * z^%d=%s = %s\n",
			i, coeff.String(), i, zPower.String(), tmp.String())
		zPower.Mul(zPower, z)
	}
	fmt.Printf("最终结果: %s\n\n", result.String())

	return result
}

// Commit 对多项式生成承诺
// poly: 要承诺的多项式
// 返回：承诺值和可能的错误
func (kzg *KZG) Commit(poly *Polynomial) (*Commitment, error) {
	if len(poly.Coefficients) > kzg.MaxDegree+1 {
		return nil, fmt.Errorf("polynomial degree too high")
	}

	var commitment bn254.G1Affine
	var acc bn254.G1Jac
	acc.Set(&bn254.G1Jac{})

	// 计算 Σ(cᵢ * τⁱG)
	for i, coeff := range poly.Coefficients {
		var tmp bn254.G1Jac
		tmp.FromAffine(&kzg.G1Powers[i])
		tmp.ScalarMultiplication(&tmp, coeff.BigInt(new(big.Int)))

		var tmpAffine bn254.G1Affine
		tmpAffine.FromJacobian(&tmp)
		acc.AddMixed(&tmpAffine)
	}

	commitment.FromJacobian(&acc)
	return &Commitment{Value: commitment}, nil
}

// CreateProof 为多项式在点 z 处的值创建证明
// poly: 原始多项式
// z: 要证明的点
// 返回：包含值和证明的 Proof 结构
func (kzg *KZG) CreateProof(poly *Polynomial, z *fr.Element) (*Proof, error) {
	// 计算 f(z)
	value := poly.Evaluate(z)

	// 对于 f(x) = ax² + bx + c
	// 商多项式 q(x) = (f(x) - f(z))/(x - z) = ax + (az + b)
	quotient := make([]fr.Element, len(poly.Coefficients)-1)

	// 对于二次多项式，商多项式的系数计算：
	// 最高次项系数保持不变：quotient[1] = 3
	quotient[1].Set(&poly.Coefficients[2])

	// 次高次项系数：quotient[0] = 2 + 3*2 = 8
	quotient[0].Set(&poly.Coefficients[1])
	var tmp fr.Element
	tmp.Mul(&poly.Coefficients[2], z)
	quotient[0].Add(&quotient[0], &tmp)

	fmt.Println("\n商多项式计算过程：")
	fmt.Printf("原始多项式系数: %v\n", poly.Coefficients)
	fmt.Printf("z = %v\n", z)
	fmt.Printf("f(z) = %v\n", value)
	fmt.Printf("商多项式系数: [%v, %v]\n", quotient[0], quotient[1])

	// 计算证明值
	quotientPoly := &Polynomial{Coefficients: quotient}
	proofCommitment, err := kzg.Commit(quotientPoly)
	if err != nil {
		return nil, err
	}

	return &Proof{
		Value:   *value,
		ProofG1: proofCommitment.Value,
	}, nil
}

// Verify 验证证明
// commitment: 原始多项式的承诺
// z: 要验证的点
// proof: 包含声称的值和证明的结构
// 返回：如果证明有效则返回 true
func (kzg *KZG) Verify(commitment *Commitment, z *fr.Element, proof *Proof) bool {
	// 计算 [z]₂
	var zG2 bn254.G2Affine
	zG2.ScalarMultiplication(&kzg.G2Powers[0], z.BigInt(new(big.Int)))

	// 计算 [τ]₂ - [z]₂
	var tauMinusZ bn254.G2Affine
	tauMinusZ.Sub(&kzg.G2Powers[1], &zG2)

	// 计算 [f(z)]₁
	var yG1 bn254.G1Affine
	yG1.ScalarMultiplication(&kzg.G1Powers[0], proof.Value.BigInt(new(big.Int)))

	// 计算 [C]₁ - [f(z)]₁
	var commitmentMinusY bn254.G1Affine
	commitmentMinusY.Sub(&commitment.Value, &yG1)

	// 计算配对并验证
	// e(π, [τ]₂ - [z]₂) = e(C - [f(z)]₁, [1]₂)
	pair1, err1 := bn254.Pair([]bn254.G1Affine{proof.ProofG1}, []bn254.G2Affine{tauMinusZ})
	pair2, err2 := bn254.Pair([]bn254.G1Affine{commitmentMinusY}, []bn254.G2Affine{kzg.G2Powers[0]})

	if err1 != nil || err2 != nil {
		return false
	}

	return pair1.Equal(&pair2)
}

func main() {
	// 初始化 KZG
	maxDegree := 10
	kzg, err := Setup(maxDegree)
	if err != nil {
		panic(err)
	}

	// 创建多项式 f(x) = 1 + 2x + 3x²
	poly := NewPolynomial([]int64{1, 2, 3})

	// 生成承诺
	commitment, err := kzg.Commit(poly)
	if err != nil {
		panic(err)
	}

	// 在点 z = 3 处生成证明
	z := new(fr.Element).SetInt64(3)
	proof, err := kzg.CreateProof(poly, z)
	if err != nil {
		panic(err)
	}

	// 打印调试信息
	fmt.Printf("多项式系数: %v\n", poly.Coefficients)
	fmt.Printf("评估点 z: %s\n", z.String())
	fmt.Printf("f(z): %s\n", proof.Value.String())

	// 打印商多项式的系数
	quotientPoly := &Polynomial{Coefficients: make([]fr.Element, len(poly.Coefficients)-1)}
	for i := 0; i < len(poly.Coefficients)-1; i++ {
		fmt.Printf("商多项式系数[%d]: %s\n", i, quotientPoly.Coefficients[i].String())
	}

	// 验证证明
	if kzg.Verify(commitment, z, proof) {
		fmt.Println("证明验证成功!")
	} else {
		fmt.Println("证明验证失败!")
	}
}
