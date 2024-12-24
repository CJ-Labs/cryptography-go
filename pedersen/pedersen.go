package pedersen

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Pedersen 承诺结构
type PedersenCommitment struct {
	// G, H 是两个生成元，且没人知道它们之间的离散对数关系
	G, H *bn254.G1Affine
}

// 承诺值结构
type Commitment struct {
	// P = m*G + r*H
	P *bn254.G1Affine
}

// 承诺打开值结构
type Opening struct {
	M *fr.Element // 原始值
	R *fr.Element // 随机数(blinding factor)
}

// 创建新的Pedersen承诺实例
func NewPedersen() (*PedersenCommitment, error) {
	// 使用曲线的标准生成元作为第一个生成元
	g := new(bn254.G1Affine)

	// BN254 曲线的标准生成元坐标
	g.X.SetString("1")
	g.Y.SetString("2")

	// 确保点在曲线上
	if !g.IsOnCurve() {
		// 如果基点不在曲线上，尝试使用另一种方式初始化
		g.X.SetString("1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")
		g.Y.SetString("1 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1")
	}

	// 再次验证点是否在曲线上
	if !g.IsOnCurve() {
		return nil, errors.New("failed to initialize generator point on curve")
	}

	// 安全地生成第二个生成元
	h, err := generateSecondGenerator(g)
	if err != nil {
		return nil, err
	}

	// 验证生成元
	if !g.IsOnCurve() || !h.IsOnCurve() {
		return nil, errors.New("invalid generators")
	}

	return &PedersenCommitment{
		G: g,
		H: h,
	}, nil
}

// 创建承诺
func (pc *PedersenCommitment) Commit(m *fr.Element) (*Commitment, *Opening, error) {
	// 生成随机数r
	r, _ := new(fr.Element).SetRandom()

	// 计算承诺 P = m*G + r*H
	P := new(bn254.G1Affine)

	// 计算 m*G
	mG := new(bn254.G1Affine).ScalarMultiplication(pc.G, m.BigInt(new(big.Int)))

	// 计算 r*H
	rH := new(bn254.G1Affine).ScalarMultiplication(pc.H, r.BigInt(new(big.Int)))

	// 计算 P = m*G + r*H
	P.Add(mG, rH)

	commitment := &Commitment{P: P}
	opening := &Opening{M: m, R: r}

	return commitment, opening, nil
}

// 验证承诺
func (pc *PedersenCommitment) Verify(
	commitment *Commitment,
	opening *Opening,
) bool {
	// 重新计算 P' = m*G + r*H
	expected := new(bn254.G1Affine)
	// 计算 m*G
	mG := new(bn254.G1Affine).ScalarMultiplication(pc.G, opening.M.BigInt(new(big.Int)))

	// 计算 r*H
	rH := new(bn254.G1Affine).ScalarMultiplication(pc.H, opening.R.BigInt(new(big.Int)))

	// 计算 P' = m*G + r*H
	expected.Add(mG, rH)

	// 检查 P == P'
	return expected.Equal(commitment.P)
}

// 同态加法
func (pc *PedersenCommitment) Add(c1 *Commitment, c2 *Commitment) *Commitment {
	sum := new(bn254.G1Affine)
	sum.Add(c1.P, c2.P)
	return &Commitment{P: sum}
}

// 打开承诺的和
func (pc *PedersenCommitment) OpenAdd(o1 *Opening, o2 *Opening) *Opening {
	m := new(fr.Element).Add(o1.M, o2.M)
	r := new(fr.Element).Add(o1.R, o2.R)
	return &Opening{M: m, R: r}
}

// 序列化承诺
func (c *Commitment) Serialize() []byte {
	bytes := c.P.Bytes()
	return bytes[:] // 将 [32]byte 转换为 []byte
}

// 反序列化承诺
func (pc *PedersenCommitment) Deserialize(data []byte) (*Commitment, error) {
	p := new(bn254.G1Affine)
	_, err := p.SetBytes(data)
	if err != nil {
		return nil, err
	}
	return &Commitment{P: p}, nil
}
