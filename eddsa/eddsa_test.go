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

// 扭曲爱德华曲线点加法
func edwardsAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	// x = (x1*y2 + y1*x2)/(1 + d*x1*x2*y1*y2)
	// y = (y1*y2 - a*x1*x2)/(1 - d*x1*x2*y1*y2)

	// 计算分子和分母
	x1y2 := new(big.Int).Mul(x1, y2)
	y1x2 := new(big.Int).Mul(y1, x2)
	dx1x2y1y2 := new(big.Int).Mul(edD, new(big.Int).Mul(x1y2, y1x2))

	// 计算 x3
	numerX := new(big.Int).Add(x1y2, y1x2)
	denomX := new(big.Int).Add(big.NewInt(1), dx1x2y1y2)
	x3 := new(big.Int).Mul(numerX, new(big.Int).ModInverse(denomX, edP))
	x3.Mod(x3, edP)

	// 计算 y3
	y1y2 := new(big.Int).Mul(y1, y2)
	x1x2 := new(big.Int).Mul(x1, x2)
	numerY := new(big.Int).Sub(y1y2, x1x2)
	denomY := new(big.Int).Sub(big.NewInt(1), dx1x2y1y2)
	y3 := new(big.Int).Mul(numerY, new(big.Int).ModInverse(denomY, edP))
	y3.Mod(y3, edP)

	return x3, y3
}

// 标量乘法
func edwardsScalarMult(x, y *big.Int, scalar []byte) (*big.Int, *big.Int) {
	resultX := new(big.Int).SetInt64(0)
	resultY := new(big.Int).SetInt64(1)
	tempX := new(big.Int).Set(x)
	tempY := new(big.Int).Set(y)

	for i := 0; i < len(scalar); i++ {
		for bit := 0; bit < 8; bit++ {
			if scalar[i]&(1<<uint(bit)) != 0 {
				resultX, resultY = edwardsAdd(resultX, resultY, tempX, tempY)
			}
			tempX, tempY = edwardsAdd(tempX, tempY, tempX, tempY)
		}
	}

	return resultX, resultY
}

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
	x, y := edwardsScalarMult(edGx, edGy, digest[:32])

	// 编码公钥
	publicKey := make([]byte, 32)
	copy(publicKey, x.Bytes())
	if y.Bit(0) == 1 {
		publicKey[31] |= 0x80
	}

	return privateKey, publicKey, nil
}

// EdDSA签名
func eddsaSign(privateKey, message []byte) ([]byte, error) {
	// 1. 生成随机数r
	h := sha512.New()
	h.Write(privateKey[32:]) // 使用私钥的后半部分
	h.Write(message)
	r := h.Sum(nil)

	// 2. 计算 R = rB
	Rx, Ry := edwardsScalarMult(edGx, edGy, r[:32])
	R := make([]byte, 32)
	copy(R, Rx.Bytes())
	if Ry.Bit(0) == 1 {
		R[31] |= 0x80
	}

	// 3. 计算 k = H(R || A || M)
	h.Reset()
	h.Write(R)
	h.Write(privateKey[32:]) // 公钥A
	h.Write(message)
	k := h.Sum(nil)

	// 4. 计算 S = (r + kx) mod L
	kInt := new(big.Int).SetBytes(k)
	rInt := new(big.Int).SetBytes(r[:32])
	x := new(big.Int).SetBytes(privateKey[:32])

	S := new(big.Int).Mul(kInt, x)
	S.Add(S, rInt)
	S.Mod(S, edL)

	// 5. 签名是(R || S)
	signature := make([]byte, 64)
	copy(signature[:32], R)
	copy(signature[32:], S.Bytes())

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
	sBx, sBy := edwardsScalarMult(edGx, edGy, S)

	// 解码 R 点
	Rx := new(big.Int).SetBytes(R[:31])
	Ry := new(big.Int).SetInt64(0)
	if R[31]&0x80 != 0 {
		Ry.SetBit(Ry, 0, 1)
	}

	// 解码公钥点 A
	Ax := new(big.Int).SetBytes(publicKey[:31])
	Ay := new(big.Int).SetInt64(0)
	if publicKey[31]&0x80 != 0 {
		Ay.SetBit(Ay, 0, 1)
	}

	kAx, kAy := edwardsScalarMult(Ax, Ay, k)
	rightX, rightY := edwardsAdd(Rx, Ry, kAx, kAy)

	return sBx.Cmp(rightX) == 0 && sBy.Cmp(rightY) == 0
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
