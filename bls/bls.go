package bls

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/crypto"
)

// G1Point 封装了BN254曲线上的G1点
type G1Point struct {
	*bn254.G1Affine
}

// newFpElement 将大整数转换为有限域Fp上的元素
func newFpElement(x *big.Int) fp.Element {
	var p fp.Element
	p.SetBigInt(x)
	return p
}

// NewG1Point 使用x和y坐标创建新的G1点
func NewG1Point(x, y *big.Int) *G1Point {
	return &G1Point{
		&bn254.G1Affine{
			X: newFpElement(x),
			Y: newFpElement(y),
		},
	}
}

// Add 将另一个G1点加到当前点上
func (p *G1Point) Add(p2 *G1Point) {
	p.G1Affine.Add(p.G1Affine, p2.G1Affine)
}

// Sub 从当前点减去另一个G1点
func (p *G1Point) Sub(p2 *G1Point) {
	p.G1Affine.Sub(p.G1Affine, p2.G1Affine)
}

// VerifyEquivalence 验证G1点与G2点是否具有相同的离散对数
func (p *G1Point) VerifyEquivalence(p2 *G2Point) (bool, error) {
	return CheckG1AndG2DiscreteLogEquality(p.G1Affine, p2.G2Affine)
}

// Serialize 将G1点序列化为字节数组
func (p *G1Point) Serialize() []byte {
	res := p.RawBytes()
	return res[:]
}

// Deserialize 从字节数组反序列化为G1点
func (p *G1Point) Deserialize(data []byte) (*G1Point, error) {
	var point bn254.G1Affine
	_, err := point.SetBytes(data)
	if err != nil {
		return nil, err
	}
	return &G1Point{&point}, nil
}

// Clone 创建G1点的深拷贝
func (p *G1Point) Clone() *G1Point {
	return &G1Point{&bn254.G1Affine{
		X: newFpElement(p.X.BigInt(new(big.Int))),
		Y: newFpElement(p.Y.BigInt(new(big.Int))),
	}}
}

// Hash 计算G1点的Keccak256哈希值
func (p *G1Point) Hash() [32]byte {
	return crypto.Keccak256Hash(p.Serialize())
}

// G2Point 封装了BN254曲线上的G2点
type G2Point struct {
	*bn254.G2Affine
}

// Add 将另一个G2点加到当前点上
func (p *G2Point) Add(p2 *G2Point) {
	p.G2Affine.Add(p.G2Affine, p2.G2Affine)
}

// Sub 从当前点减去另一个G2点
func (p *G2Point) Sub(p2 *G2Point) {
	p.G2Affine.Sub(p.G2Affine, p2.G2Affine)
}

// Serialize 将G2点序列化为字节数组
func (p *G2Point) Serialize() []byte {
	res := p.RawBytes()
	return res[:]
}

// Deserialize 从字节数组反序列化为G2点
func (p *G2Point) Deserialize(data []byte) (*G2Point, error) {
	var point bn254.G2Affine
	_, err := point.SetBytes(data)
	if err != nil {
		return nil, err
	}
	return &G2Point{&point}, nil
}

// Clone 创建G2点的深拷贝
func (p *G2Point) Clone() *G2Point {
	return &G2Point{&bn254.G2Affine{
		X: struct {
			A0, A1 fp.Element
		}{
			A0: newFpElement(p.X.A0.BigInt(new(big.Int))),
			A1: newFpElement(p.X.A1.BigInt(new(big.Int))),
		},
		Y: struct {
			A0, A1 fp.Element
		}{
			A0: newFpElement(p.Y.A0.BigInt(new(big.Int))),
			A1: newFpElement(p.Y.A1.BigInt(new(big.Int))),
		},
	}}
}

// Signature 表示BLS签名，本质是G1点
type Signature struct {
	*G1Point
}

// Verify 使用G2公钥验证消息签名
func (p *G1Point) Verify(pubKey *G2Point, message [32]byte) bool {
	ok, err := VerifySig(p.G1Affine, pubKey.G2Affine, message)
	if err != nil || ok == false {
		return false
	}
	return true
}

// PrivateKey 是Fr域上的元素，表示私钥
type PrivateKey = fr.Element

// KeyPair 包含BLS密钥对
type KeyPair struct {
	PrivKey *PrivateKey
	PubKey  *G1Point
}

// MakeKeyPair 从私钥创建密钥对
func MakeKeyPair(sk *PrivateKey) *KeyPair {
	pk := MulByGeneratorG1(sk)
	return &KeyPair{sk, &G1Point{pk}}
}

// MakeKeyPairFromString 从字符串创建密钥对
func MakeKeyPairFromString(sk string) (*KeyPair, error) {
	ele, err := new(fr.Element).SetString(sk)
	if err != nil {
		return nil, err
	}
	return MakeKeyPair(ele), nil
}

// GenRandomBlsKeys 生成随机BLS密钥对
func GenRandomBlsKeys() (*KeyPair, error) {
	// 最大随机值是曲线的阶
	max := new(big.Int)
	max.SetString(fr.Modulus().String(), 10)

	// 生成密码学安全的随机数
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}

	sk := new(PrivateKey).SetBigInt(n)
	return MakeKeyPair(sk), nil
}

// SignMessage 对消息进行BLS签名
func (k *KeyPair) SignMessage(message [32]byte) *Signature {
	H := MapToCurve(message)
	sig := new(bn254.G1Affine).ScalarMultiplication(H, k.PrivKey.BigInt(new(big.Int)))
	return &Signature{&G1Point{sig}}
}

// SignHashedToCurveMessage 对已经哈希到曲线上的消息进行签名
func (k *KeyPair) SignHashedToCurveMessage(g1HashedMsg *G1Point) *Signature {
	sig := new(bn254.G1Affine).ScalarMultiplication(g1HashedMsg.G1Affine, k.PrivKey.BigInt(new(big.Int)))
	return &Signature{&G1Point{sig}}
}

// GetPubKeyG2 获取G2上的公钥
func (k *KeyPair) GetPubKeyG2() *G2Point {
	return &G2Point{MulByGeneratorG2(k.PrivKey)}
}

// GetPubKeyG1 获取G1上的公钥
func (k *KeyPair) GetPubKeyG1() *G1Point {
	return k.PubKey
}
