package ecdsa

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

// 椭圆曲线参数（P256）
// 修改椭圆曲线参数为 secp256k1 的标准参数
// Gx 和 Gy：这两个值定义了椭圆曲线上的生成点 G 的坐标。生成点是用于密钥生成和签名过程的基础点。
// n：这是生成点 G 的阶数，表示通过 G 生成的所有点的数量。这个值对于确保曲线的安全性和有效性至关重要。

var (
	// secp256k1 curve parameters
	p, _       = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	a          = big.NewInt(0) // secp256k1 的 a = 0
	b          = big.NewInt(7) // secp256k1 的 b = 7
	Gx, _      = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	Gy, _      = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	n, _       = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	curveOrder = n // 更新曲线阶数
)

// 生成私钥
func generatePrivateKey() (*big.Int, error) {
	return rand.Int(rand.Reader, n)
}

// 计算公钥
func calculatePublicKey(privKey *big.Int) (*big.Int, *big.Int) {
	return ellipticCurveMultiply(Gx, Gy, privKey)
}

func ellipticCurveMultiply(x, y *big.Int, k *big.Int) (*big.Int, *big.Int) {
	// 处理特殊情况
	if k.Sign() == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	// 使用 NAF（Non-Adjacent Form）表示来优化计算
	resultX, resultY := big.NewInt(0), big.NewInt(0)
	tmpX, tmpY := new(big.Int).Set(x), new(big.Int).Set(y)

	for i := k.BitLen() - 1; i >= 0; i-- {
		resultX, resultY = ellipticCurveAdd(resultX, resultY, resultX, resultY)

		if k.Bit(i) == 1 {
			resultX, resultY = ellipticCurveAdd(resultX, resultY, tmpX, tmpY)
		}
	}

	return resultX, resultY
}

// 修改椭圆曲线加法函数，处理特殊情况
func ellipticCurveAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	// 处理无穷远点
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}

	// 处理点相加为无穷远点的情况
	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) == 0 {
			if y1.Sign() == 0 {
				return big.NewInt(0), big.NewInt(0)
			}
		} else {
			return big.NewInt(0), big.NewInt(0)
		}
	}

	// 计算斜率
	var slope *big.Int
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		// 点倍乘
		temp := new(big.Int).Mul(x1, x1)
		temp.Mul(temp, big.NewInt(3))
		temp.Mod(temp, p)

		denom := new(big.Int).Mul(y1, big.NewInt(2))
		denom.Mod(denom, p)

		slope = new(big.Int).ModInverse(denom, p)
		slope.Mul(slope, temp)
		slope.Mod(slope, p)
	} else {
		// 点加法
		num := new(big.Int).Sub(y2, y1)
		num.Mod(num, p)

		denom := new(big.Int).Sub(x2, x1)
		denom.Mod(denom, p)

		slope = new(big.Int).ModInverse(denom, p)
		slope.Mul(slope, num)
		slope.Mod(slope, p)
	}

	// 计算新的 x 坐标
	x3 := new(big.Int).Mul(slope, slope)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, p)

	// 计算新的 y 坐标
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, slope)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)

	return x3, y3
}

// 生成地址
func PubKeyToAddress(publicKeyX, publicKeyY *big.Int) string {
	return publicKeyX.Text(16) // 简单使用公钥的 X 值作为地址
}

// 生成 ECDSA 签名
func sign(privateKey *big.Int, message []byte) (*big.Int, *big.Int, error) {
	// 使用 sha-256 河西函数对输入的消息进行哈希处理，生成一个固定长度的哈希值（32字节）
	messageHash := sha256.Sum256(message)

	var r, s, randomK *big.Int
	var err error

	for {
		//生成随机数 k
		// 在循环中生成一个随机数k 范围在曲线的顺序 curveOrder 之内
		randomK, err = rand.Int(rand.Reader, curveOrder)
		if err != nil {
			return nil, nil, err
		}

		// 生成的 xCoordinate， yCoordinate 是几点G 经过 k 布 椭圆曲线乘法得到的点
		xCoordinate, yCoordinate := ellipticCurveMultiply(Gx, Gy, randomK)
		println("generateSignature ellipticCurveMultiply Gx =", Gx.Text(16))
		println("generateSignature ellipticCurveMultiply Gy =", Gy.Text(16))
		println("generateSignature ellipticCurveMultiply curveOrder =", curveOrder.Text(16))
		println("generateSignature ellipticCurveMultiply x =", xCoordinate.Text(16))
		println("generateSignature ellipticCurveMultiply y =", yCoordinate.Text(16))

		// r = x mod n
		r = new(big.Int).Mod(xCoordinate, curveOrder)

		if r.Sign() == 0 {
			continue // r 不能为 0
		}

		kInverse := new(big.Int).ModInverse(randomK, curveOrder)       // k 的模逆
		s = new(big.Int).Mul(privateKey, r)                            // s = privateKey * r
		s = new(big.Int).Add(s, new(big.Int).SetBytes(messageHash[:])) // s += hash
		s = new(big.Int).Mul(s, kInverse)                              // s = s * k^(-1) mod n
		s = new(big.Int).Mod(s, curveOrder)                            // s = s mod n

		if s.Sign() == 0 {
			continue // s 不能为 0
		}

		break // 成功生成签名
	}

	return r, s, nil
}

func verifySignature(pubKeyX, pubKeyY *big.Int, message []byte, r, s *big.Int) bool {
	// 使用 SHA-256 哈希函数对输入的消息进行哈希处理
	messageHash := sha256.Sum256(message)

	// 检查 r 和 s 是否在有效范围内
	if r.Sign() <= 0 || r.Cmp(curveOrder) >= 0 || s.Sign() <= 0 || s.Cmp(curveOrder) >= 0 {
		return false
	}

	// 计算 w = s ^ (-1) mod n
	w := new(big.Int).ModInverse(s, curveOrder)

	// 计算 u1 = (H(m) * w) mod n
	u1 := new(big.Int).Mul(new(big.Int).SetBytes(messageHash[:]), w)
	u1.Mod(u1, curveOrder)

	// 计算 u2 = (r * w) mod n
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, curveOrder)

	// 计算椭圆曲线点 (x1, y1) = u1 * G + u2 * P
	x1, y1 := ellipticCurveMultiply(Gx, Gy, u1)           // u1 * G
	x2, y2 := ellipticCurveMultiply(pubKeyX, pubKeyY, u2) // u2 * P
	x1, y1 = ellipticCurveAdd(x1, y1, x2, y2)             // 点相加

	// 计算 v = x1 mod n
	v := new(big.Int).Mod(x1, curveOrder)

	// 签名有效性检查
	return v.Cmp(r) == 0
}

func Test_generate_ecdsa(t *testing.T) {
	privKey, err := generatePrivateKey() // 生成私钥
	if err != nil {
		t.Fatalf("Error generating private key: %v", err)
	}

	// 计算公钥
	pubKeyX, pubKeyY := calculatePublicKey(privKey)

	// 打印私钥和公钥
	fmt.Println("Private Key:", privKey.Text(16))
	fmt.Println("Public Key X:", pubKeyX.Text(16))
	fmt.Println("Public Key Y:", pubKeyY.Text(16))

	address := PubKeyToAddress(pubKeyX, pubKeyY) // 生成地址
	fmt.Println("Address:", address)

	message := []byte("Hello, Ethereum!") // 生成签名
	r, s, err := sign(privKey, message)

	if err != nil {
		t.Errorf("Error generating signature: %v", err)
		return
	}
	fmt.Printf("Signature: r=%x, s=%x\n", r, s)

	// 验证签名
	if verifySignature(pubKeyX, pubKeyY, message, r, s) {
		fmt.Println("Signature is valid.")
	} else {
		t.Error("Signature is invalid.")
	}
	fmt.Println("Test completed successfully.")
}
