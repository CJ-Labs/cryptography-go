package ecdsa

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// 生成以太坊地址
func generateEthereumAddress(pubKeyX, pubKeyY *big.Int) string {
	// 将公钥的 X 和 Y 坐标组合成字节
	pubKeyBytes := append(pubKeyX.Bytes(), pubKeyY.Bytes()...)

	// 计算 Keccak-256 哈希
	hash := keccak256(pubKeyBytes)

	// 取哈希的最后 20 字节
	address := hash[len(hash)-20:]

	// 转换为十六进制字符串
	return hex.EncodeToString(address)
}

func generateEthereumAddressCore() string {
	// 生成 ECDSA 私钥
	privKey, err := generatePrivateKey()
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return ""
	}
	pubKeyX, pubKeyY := calculatePublicKey(privKey)

	// 生成以太坊地址
	address := generateEthereumAddress(pubKeyX, pubKeyY)
	fmt.Println("Ethereum Address:", address)
	return address
}

// 修改签名生成函数
func generateDeterministicSignature(privateKey *big.Int, message []byte) (*big.Int, *big.Int, uint8, error) {
	messageHash := hashMessage(message)

	// 使用确定性 k 值
	k := generateDeterministicK(privateKey, messageHash[:])

	// 计算曲线点 R = k*G
	rx, ry := ellipticCurveMultiply(Gx, Gy, k)

	// r = rx mod n
	r := new(big.Int).Mod(rx, curveOrder)

	// s = k⁻¹(hash + r*privateKey) mod n
	kInv := new(big.Int).ModInverse(k, curveOrder)
	s := new(big.Int).Mul(privateKey, r)
	s.Add(s, new(big.Int).SetBytes(messageHash[:]))
	s.Mul(s, kInv)
	s.Mod(s, curveOrder)

	// 计算 v 值
	v := uint8(27 + ry.Bit(0))

	return r, s, v, nil
}

// 添加新的函数，用于生成确定性的 k 值
// 使用 RFC 6979 实现确定性 k 值生成
func generateDeterministicK(privateKey *big.Int, message []byte) *big.Int {
	// 1. 初始化
	h := sha256.New()
	h.Write(privateKey.Bytes())
	h.Write(message)
	v := make([]byte, h.Size())
	k := make([]byte, h.Size())

	// 2. 生成初始值
	for i := 0; i < len(v); i++ {
		v[i] = 0x01
	}

	// 3. 迭代计算
	temp := make([]byte, 0, len(v)+1+len(privateKey.Bytes())+len(message))
	temp = append(temp, v...)
	temp = append(temp, 0x00)
	temp = append(temp, privateKey.Bytes()...)
	temp = append(temp, message...)

	h.Reset()
	h.Write(temp)
	k = h.Sum(nil)

	// 4. 转换为大整数并确保在正确范围内
	kInt := new(big.Int).SetBytes(k)
	kInt.Mod(kInt, curveOrder)

	if kInt.Sign() == 0 {
		kInt.SetInt64(1)
	}

	return kInt
}

// 修改 recoverPublicKey 函数
func recoverPublicKey(messageHash [32]byte, r, s *big.Int, v uint8) (*big.Int, *big.Int) {
	// 1. 验证签名参数
	if r.Cmp(big.NewInt(0)) <= 0 || r.Cmp(curveOrder) >= 0 ||
		s.Cmp(big.NewInt(0)) <= 0 || s.Cmp(curveOrder) >= 0 {
		return nil, nil
	}

	// 2. 计算 R 点
	rx := new(big.Int).Set(r)
	ry := new(big.Int)

	// 计算 y² = x³ + 7
	{
		x3 := new(big.Int).Mul(rx, rx)
		x3.Mul(x3, rx)
		x3.Add(x3, big.NewInt(7))
		x3.Mod(x3, p)

		ry = new(big.Int).ModSqrt(x3, p)
		if ry == nil {
			return nil, nil
		}

		// 根据 v 选择正确的 y 值
		if ry.Bit(0) != uint(v-27) {
			ry.Sub(p, ry)
		}
	}

	// 3. 计算 e = -hash mod n
	e := new(big.Int).SetBytes(messageHash[:])
	e.Neg(e)
	e.Mod(e, curveOrder)

	// 4. 计算 r⁻¹
	rInv := new(big.Int).ModInverse(r, curveOrder)
	if rInv == nil {
		return nil, nil
	}

	// 5. 计算 u1 和 u2
	u1 := new(big.Int).Mul(e, rInv)
	u1.Mod(u1, curveOrder)

	u2 := new(big.Int).Mul(s, rInv)
	u2.Mod(u2, curveOrder)

	// 6. 计算 Q = u1G + u2R
	x1, y1 := ellipticCurveMultiply(Gx, Gy, u1)
	x2, y2 := ellipticCurveMultiply(rx, ry, u2)
	qx, qy := ellipticCurveAdd(x1, y1, x2, y2)

	return qx, qy
}

func verifySignatureEthereum(messageHash [32]byte, r, s *big.Int, v uint8, pubKeyX, pubKeyY *big.Int) bool {
	// 1. 提前验证 v 值是否合法
	if v != 27 && v != 28 {
		return false
	}

	// 2. 使用一个统一的检查来验证 r 和 s 的范围
	secp256k1N := crypto.S256().Params().N
	if !crypto.ValidateSignatureValues(v, r, s, true) {
		return false
	}

	// 3. 计算 w = s^(-1) mod N
	w := new(big.Int).ModInverse(s, secp256k1N)
	if w == nil {
		return false
	}

	// 4. 优化 u1 和 u2 的计算
	u1 := new(big.Int).Mul(new(big.Int).SetBytes(messageHash[:]), w)
	u1.Mod(u1, secp256k1N)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, secp256k1N)

	// 5. 使用标准库的曲线操作
	curve := crypto.S256()
	x1, y1 := curve.ScalarBaseMult(u1.Bytes())
	x2, y2 := curve.ScalarMult(pubKeyX, pubKeyY, u2.Bytes())

	// 6. 计算最终点并验证
	x, y := curve.Add(x1, y1, x2, y2)

	// 7. 验证 y 的奇偶性与 v 匹配
	if y.Bit(0) != uint(v-27) {
		return false
	}

	// 8. 验证 x 坐标
	xModN := new(big.Int).Mod(x, secp256k1N)
	return xModN.Cmp(r) == 0
}

// 验证以太坊签名（不需要公钥）
func verifySignatureEthereumNoPubKey(messageHash [32]byte, r, s *big.Int, v uint8) bool {
	// 1. 基础参数检查
	if r.Cmp(big.NewInt(0)) <= 0 || r.Cmp(curveOrder) >= 0 ||
		s.Cmp(big.NewInt(0)) <= 0 || s.Cmp(curveOrder) >= 0 {
		return false
	}

	// 2. 检查 s 值是否符合 EIP-2
	halfOrder := new(big.Int).Div(curveOrder, big.NewInt(2))
	if s.Cmp(halfOrder) > 0 {
		return false
	}

	// 3. 从签名中恢复公钥
	pubKeyX, pubKeyY := recoverPublicKey(messageHash, r, s, v)
	if pubKeyX == nil || pubKeyY == nil {
		return false
	}

	secp256k1N := crypto.S256().Params().N
	if !crypto.ValidateSignatureValues(v, r, s, true) {
		return false
	}

	// 4. 计算 w = s^(-1)
	w := new(big.Int).ModInverse(s, curveOrder)
	if w == nil {
		return false
	}

	// 5. 计算 u1 = hash * w
	u1 := new(big.Int).SetBytes(messageHash[:])
	u1.Mul(u1, w)
	u1.Mod(u1, curveOrder)

	// 6. 计算 u2 = r * w
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, curveOrder)

	// 7. 计算 point1 = u1 * G
	x1, y1 := ellipticCurveMultiply(Gx, Gy, u1)

	// 8. 计算 point2 = u2 * pubKey
	x2, y2 := ellipticCurveMultiply(pubKeyX, pubKeyY, u2)

	// 9. 计算 point = point1 + point2
	x, y := ellipticCurveAdd(x1, y1, x2, y2)

	// 10. 验证 y 的奇偶性与 v 匹配
	if y.Bit(0) != uint(v-27) {
		return false
	}

	// 11. 验证 x 坐标
	xModN := new(big.Int).Mod(x, secp256k1N)
	return xModN.Cmp(r) == 0
}

// 测试确定性签名
func Test_deterministic_signature(t *testing.T) {
	// 使用固定的私钥进行测试
	privKey, _ := new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)

	message := []byte("Hello, Ethereum!")

	// 第一次签名
	r1, s1, v1, err := generateDeterministicSignature(privKey, message)
	if err != nil {
		t.Fatal(err)
	}

	// 第二次签名
	r2, s2, v2, err := generateDeterministicSignature(privKey, message)
	if err != nil {
		t.Fatal(err)
	}

	// 验证两次签名是否相同
	if r1.Cmp(r2) != 0 || s1.Cmp(s2) != 0 || v1 != v2 {
		t.Error("Signatures are not deterministic")
	} else {
		fmt.Printf("Deterministic Signature:\nr=%x\ns=%x\nv=%d\n", r1, s1, v1)
	}
}

func Test_generate_ethereum_ecdsa(t *testing.T) {
	// 生成以太坊地址
	address := generateEthereumAddressCore()
	fmt.Println("Ethereum Address:", address)
}

func Test_signature_recovery_flow(t *testing.T) {
	// 1. 生成私钥
	privKey, err := generatePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// 2. 计算原始公钥
	origPubX, origPubY := calculatePublicKey(privKey)

	// 3. 签名消息
	message := []byte("Test message")
	r, s, v, err := generateDeterministicSignature(privKey, message)
	if err != nil {
		t.Fatalf("Failed to generate signature: %v", err)
	}

	// 4. 恢复公钥
	msgHash := hashMessage(message)
	// recoveredPubX, recoveredPubY, err := RecoverPublicKey(msgHash[:], r, s, v)
	recoveredPubX, recoveredPubY := recoverPublicKey(msgHash, r, s, v)
	if err != nil {
		t.Fatalf("Failed to recover public key: %v", err)
	}

	// 5. 验证恢复的公钥
	if origPubX.Cmp(recoveredPubX) != 0 || origPubY.Cmp(recoveredPubY) != 0 {
		t.Error("Recovered public key does not match original")
	}
}

// 添加新的测试用例
func Test_signature_verification(t *testing.T) {
	message := []byte("Test message")
	privKey, _ := generatePrivateKey()
	pubX, pubY := calculatePublicKey(privKey)

	// 生成签名
	r, s, v, err := generateDeterministicSignature(privKey, message)
	if err != nil {
		t.Fatalf("Failed to generate signature: %v", err)
	}

	// 验证签名
	messageHash := hashMessage(message)
	recoveredPubX, recoveredPubY := recoverPublicKey(messageHash, r, s, v)

	if recoveredPubX == nil || recoveredPubY == nil {
		t.Fatal("Failed to recover public key")
	}

	if pubX.Cmp(recoveredPubX) != 0 || pubY.Cmp(recoveredPubY) != 0 {
		t.Error("Recovered public key does not match original")
	}
}

// 测试验证签名
//
//	测试失败
func Test_verify_signature(t *testing.T) {
	// 1. 生成私钥和公钥
	privKey, _ := generatePrivateKey()
	pubX, pubY := calculatePublicKey(privKey)

	// 2. 准备消息
	message := []byte("Test message")
	messageHash := hashMessage(message)

	// 3. 生成签名
	r, s, v, err := generateDeterministicSignature(privKey, message)
	if err != nil {
		t.Fatalf("Failed to generate signature: %v", err)
	}

	// 4. 验证签名
	isValid := verifySignatureEthereum(messageHash, r, s, v, pubX, pubY)
	if !isValid {
		t.Error("Signature verification failed")
	}

	// 5. 测试无效签名
	invalidS := new(big.Int).Add(s, big.NewInt(1))
	isValid = verifySignatureEthereum(messageHash, r, invalidS, v, pubX, pubY)
	if isValid {
		t.Error("Invalid signature was accepted")
	}
}
