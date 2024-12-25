package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sort"
)

// DHParams 存储 Diffie-Hellman 参数
type DHParams struct {
	P *big.Int // 大素数
	G *big.Int // 生成元
}

// Participant 表示参与方
type Participant struct {
	PrivateKey *big.Int
	PublicKey  *big.Int
	Random     *big.Int // 用于改进版本的随机数
}

// 生成 DH 参数
func NewDHParams(bits int) (*DHParams, error) {
	// 生成大素数 P
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	// 生成生成元 G
	g := big.NewInt(2)

	return &DHParams{
		P: p,
		G: g,
	}, nil
}

// 创建新的参与方
func NewParticipant(params *DHParams) (*Participant, error) {
	privateKey, err := rand.Int(rand.Reader, params.P)
	if err != nil {
		return nil, err
	}

	// 计算公钥: g^privateKey mod p
	publicKey := new(big.Int).Exp(params.G, privateKey, params.P)

	// 生成随机数
	random, err := rand.Int(rand.Reader, params.P)
	if err != nil {
		return nil, err
	}

	return &Participant{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Random:     random,
	}, nil
}

// 基本版本：计算共享密钥
func (p *Participant) ComputeSharedKey(params *DHParams, otherPublicKey *big.Int) []byte {
	// 计算共享密钥: (otherPublicKey)^privateKey mod p
	sharedSecret := new(big.Int).Exp(otherPublicKey, p.PrivateKey, params.P)

	// 使用 SHA-256 哈希共享密钥
	hash := sha256.New()
	hash.Write(sharedSecret.Bytes())
	return hash.Sum(nil)
}

// 改进版本：计算带随机数的共享密钥
func (p *Participant) ComputeSharedKeyWithRandom(params *DHParams, otherPublicKey, otherRandom *big.Int) []byte {
	// 计算基本的共享密钥
	sharedSecret := new(big.Int).Exp(otherPublicKey, p.PrivateKey, params.P)

	// 组合随机数和共享密钥
	hash := sha256.New()
	hash.Write(sharedSecret.Bytes())

	// 确保随机数按照固定顺序组合
	// 比较两个随机数，较小的先写入
	if p.Random.Cmp(otherRandom) < 0 {
		hash.Write(p.Random.Bytes())
		hash.Write(otherRandom.Bytes())
	} else {
		hash.Write(otherRandom.Bytes())
		hash.Write(p.Random.Bytes())
	}

	return hash.Sum(nil)
}

// 三方密钥交换
type ThreePartyDH struct {
	Params *DHParams
	Alice  *Participant
	Bob    *Participant
	Carol  *Participant
}

// 创建三方 DH 实例
func NewThreePartyDH(bits int) (*ThreePartyDH, error) {
	params, err := NewDHParams(bits)
	if err != nil {
		return nil, err
	}

	alice, err := NewParticipant(params)
	if err != nil {
		return nil, err
	}

	bob, err := NewParticipant(params)
	if err != nil {
		return nil, err
	}

	carol, err := NewParticipant(params)
	if err != nil {
		return nil, err
	}

	return &ThreePartyDH{
		Params: params,
		Alice:  alice,
		Bob:    bob,
		Carol:  carol,
	}, nil
}

// 修改三方密钥交换的实现
func (tdh *ThreePartyDH) ComputeThreePartyKey() []byte {
	// 每个参与方计算与其他两个参与方的共享密钥
	// Alice 与 Bob 的共享密钥
	aliceBobKey := tdh.Alice.ComputeSharedKey(tdh.Params, tdh.Bob.PublicKey)

	// Bob 与 Carol 的共享密钥
	bobCarolKey := tdh.Bob.ComputeSharedKey(tdh.Params, tdh.Carol.PublicKey)

	// Carol 与 Alice 的共享密钥
	carolAliceKey := tdh.Carol.ComputeSharedKey(tdh.Params, tdh.Alice.PublicKey)

	// 按照固定顺序组合三个共享密钥
	hash := sha256.New()
	// 确保所有参与方使用相同顺序组合密钥
	keys := [][32]byte{
		*(*[32]byte)(aliceBobKey),
		*(*[32]byte)(bobCarolKey),
		*(*[32]byte)(carolAliceKey),
	}

	// 对密钥进行排序，确保顺序一致
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i][:], keys[j][:]) < 0
	})

	// 按排序后的顺序写入哈希
	for _, key := range keys {
		hash.Write(key[:])
	}

	return hash.Sum(nil)
}

func main() {
	// 演示基本的双方密钥交换
	fmt.Println("=== 基本的双方 Diffie-Hellman 密钥交换 ===")
	params, _ := NewDHParams(256)
	alice, _ := NewParticipant(params)
	bob, _ := NewParticipant(params)

	aliceKey := alice.ComputeSharedKey(params, bob.PublicKey)
	bobKey := bob.ComputeSharedKey(params, alice.PublicKey)

	fmt.Printf("Alice 的共享密钥: %x\n", aliceKey)
	fmt.Printf("Bob 的共享密钥: %x\n", bobKey)
	fmt.Printf("Keys match:  %v\n\n", string(aliceKey) == string(bobKey))

	// 演示改进版本（带随机数）
	fmt.Println("=== 改进版本的双方 Diffie-Hellman 密钥交换（带随机数）===")
	aliceKeyWithRandom := alice.ComputeSharedKeyWithRandom(params, bob.PublicKey, bob.Random)
	bobKeyWithRandom := bob.ComputeSharedKeyWithRandom(params, alice.PublicKey, alice.Random)

	fmt.Printf("Alice's key with random: %x\n", aliceKeyWithRandom)
	fmt.Printf("Bob's key with random:   %x\n", bobKeyWithRandom)
	fmt.Printf("Keys match:              %v\n\n", string(aliceKeyWithRandom) == string(bobKeyWithRandom))

	// 演示三方密钥交换
	fmt.Println("=== 三方 Diffie-Hellman 密钥交换 ===")
	threeDH, _ := NewThreePartyDH(256)

	// 计算三方共享密钥
	aliceFinalKey := threeDH.ComputeThreePartyKey()
	bobFinalKey := threeDH.ComputeThreePartyKey()
	carolFinalKey := threeDH.ComputeThreePartyKey()

	fmt.Printf("Alice's three-party key: %x\n", aliceFinalKey)
	fmt.Printf("Bob's three-party key:   %x\n", bobFinalKey)
	fmt.Printf("Carol's three-party key: %x\n", carolFinalKey)
	fmt.Printf("Keys match: %v\n",
		bytes.Equal(aliceFinalKey, bobFinalKey) &&
			bytes.Equal(bobFinalKey, carolFinalKey))
}
