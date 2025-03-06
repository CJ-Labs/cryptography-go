package ecdsa

import (
	"fmt"
	"math/big"
	"testing"
)

func RecoverPublicKey(msgHash []byte, r, s *big.Int, v uint8) (*big.Int, *big.Int, error) {
	if len(msgHash) != 32 {
		return nil, nil, fmt.Errorf("message hash must be 32 bytes")
	}

	// 验证 r, s 范围
	if r.Cmp(curveOrder) >= 0 || s.Cmp(curveOrder) >= 0 {
		return nil, nil, fmt.Errorf("r or s value too large")
	}

	// 调整 v 值
	v = v - 27
	if v != 0 && v != 1 {
		return nil, nil, fmt.Errorf("invalid recovery id")
	}

	// 计算曲线点 R
	rx := new(big.Int).Set(r)
	ry := calculateY(rx, v)
	if ry == nil {
		return nil, nil, fmt.Errorf("invalid curve point")
	}

	// 计算 e = -hash mod n
	e := new(big.Int).SetBytes(msgHash)
	e.Neg(e)
	e.Mod(e, curveOrder)

	// 计算 r⁻¹
	rInv := new(big.Int).ModInverse(r, curveOrder)
	if rInv == nil {
		return nil, nil, fmt.Errorf("r has no modular inverse")
	}

	// 计算公钥
	u1 := new(big.Int).Mul(e, rInv)
	u1.Mod(u1, curveOrder)
	u2 := new(big.Int).Mul(s, rInv)
	u2.Mod(u2, curveOrder)

	// Q = u1*G + u2*R
	x1, y1 := ellipticCurveMultiply(Gx, Gy, u1)
	x2, y2 := ellipticCurveMultiply(rx, ry, u2)
	qx, qy := ellipticCurveAdd(x1, y1, x2, y2)

	return qx, qy, nil
}

// 添加辅助函数计算 y 坐标
func calculateY(x *big.Int, v uint8) *big.Int {
	// y² = x³ + 7 (secp256k1 曲线方程)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, big.NewInt(7))
	x3.Mod(x3, p)

	y := modSqrt(x3, p)
	if y == nil {
		return nil
	}

	// 根据 v 选择正确的 y 值
	if y.Bit(0) != uint(v) {
		y.Sub(p, y)
	}

	return y
}

// 辅助函数：计算模平方根
func modSqrt(a, p *big.Int) *big.Int {
	if legendre(a, p) != 1 {
		return nil
	}

	// 对于 p ≡ 3 (mod 4) 的情况，可以直接计算
	if new(big.Int).Mod(p, big.NewInt(4)).Int64() == 3 {
		exp := new(big.Int).Add(p, big.NewInt(1))
		exp.Rsh(exp, 2)
		return new(big.Int).Exp(a, exp, p)
	}

	return nil // 其他情况需要实现更复杂的算法
}

// 辅助函数：计算勒让德符号
func legendre(a, p *big.Int) int {
	if a.Sign() == 0 {
		return 0
	}

	res := new(big.Int).Exp(a, new(big.Int).Rsh(p, 1), p)
	if res.Cmp(big.NewInt(1)) == 0 {
		return 1
	}
	return -1
}

// RecoverPublicKeyFromRSV 从 r, s, v 值恢复公钥
func RecoverPublicKeyFromRSV(msgHash []byte, r, s *big.Int, v uint8) (*big.Int, *big.Int, error) {
	// 验证输入参数
	if len(msgHash) != 32 {
		return nil, nil, fmt.Errorf("message hash must be 32 bytes")
	}

	// 验证 r, s 的范围
	if r.Cmp(curveOrder) >= 0 || s.Cmp(curveOrder) >= 0 {
		return nil, nil, fmt.Errorf("r or s value too large")
	}

	// 验证 v 值
	if v != 27 && v != 28 {
		return nil, nil, fmt.Errorf("invalid v value: must be 27 or 28")
	}

	// 直接调用 RecoverPublicKey 函数
	return RecoverPublicKey(msgHash, r, s, v)
}
func Test_RecoverPublicKeyFromRSV(t *testing.T) {
	// 1.准备测试数据
	privKey, _ := generatePrivateKey()
	originalPubX, originalPubY := calculatePublicKey(privKey)
	message := []byte("Test message")

	// 生成签名
	r, s, v, err := ethereumSign(privKey, message)
	if err != nil {
		t.Fatalf("Failed to generate signature: %v", err)
	}

	// 3. 从签名恢复公钥
	msgHash := MessageToHash(message)
	recoveredPubX, recoveredPubY, err := RecoverPublicKeyFromRSV(msgHash[:], r, s, v)
	if err != nil {
		t.Fatalf("Failed to recover public key: %v", err)
	}

	// 4. 验证恢复的公钥是否正确
	if recoveredPubX.Cmp(originalPubX) != 0 || recoveredPubY.Cmp(originalPubY) != 0 {
		t.Error("Recovered public key does not match original")
	}
}
