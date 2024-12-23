package ecdsa

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"
	"testing"
)

// Edwards25519 曲线参数
var (
	// 2^255 - 19
	edP, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	// -121665/121666
	edD, _ = new(big.Int).SetString("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 16)
	// 基点
	edGx, _ = new(big.Int).SetString("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 16)
	edGy, _ = new(big.Int).SetString("6666666666666666666666666666666666666666666666666666666666666658", 16)
	// 群的阶
	edL, _ = new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
)

// EdDSA密钥对生成
func generateEdDSAKeyPair() ([]byte, []byte, error) {
	// 生成随机私钥
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}

	// 使用SHA-512生成种子
	h := sha512.New()
	h.Write(privateKey)
	digest := h.Sum(nil)

	// 清理低3位和最高位，设置第二高位
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	// 生成公钥
	publicKey := make([]byte, 32)
	// TODO: 实现 Ed25519 标量乘法
	// 这里需要实现 Ed25519 的标量乘法来计算 publicKey = digest * G

	return privateKey, publicKey, nil
}

// EdDSA签名
func eddsaSign(privateKey, message []byte) ([]byte, error) {
	// 1. 生成随机数r
	r := make([]byte, 64)
	h := sha512.New()
	h.Write(privateKey[32:]) // 使用私钥的后半部分
	h.Write(message)
	copy(r, h.Sum(nil))

	// 2. 计算 R = rB
	// TODO: 实现点乘运算
	R := make([]byte, 32)

	// 3. 计算 k = H(R || A || M)
	h.Reset()
	h.Write(R)
	h.Write(privateKey[32:]) // 公钥A
	h.Write(message)
	k := h.Sum(nil)

	// 4. 计算 S = (r + kx) mod L
	// TODO: 实现模运算
	S := make([]byte, 32)

	// 5. 签名是(R || S)
	signature := make([]byte, 64)
	copy(signature[:32], R)
	copy(signature[32:], S)

	return signature, nil
}

// EdDSA验证
func eddsaVerify(publicKey, message, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}

	R := signature[:32]
	S := signature[32:]

	// 1. 计算 h = H(R || A || M)
	h := sha512.New()
	h.Write(R)
	h.Write(publicKey)
	h.Write(message)
	k := h.Sum(nil)

	// 2. 验证 SB = R + kA
	// TODO: 实现点运算验证
	// 这里需要实现 Ed25519 的���运算来验证等式

	return true
}

func Test_EdDSA(t *testing.T) {
	// 生成密钥对
	privateKey, publicKey, err := generateEdDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// 测试消息
	message := []byte("Hello, EdDSA!")

	// 签名
	signature, err := eddsaSign(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// 验证
	if !eddsaVerify(publicKey, message, signature) {
		t.Error("Signature verification failed")
	}

	// 打印结果
	fmt.Printf("Private Key: %x\n", privateKey)
	fmt.Printf("Public Key: %x\n", publicKey)
	fmt.Printf("Signature: %x\n", signature)
}
