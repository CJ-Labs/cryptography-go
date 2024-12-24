package bls

// fp: 用于点的坐标（x,y）
// fr: 用于标量（私钥、倍数等）
import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// VerifySig 验证BLS签名
// 参数:
// - sig: G1上的签名点
// - pubkey: G2上的公钥点
// - msgBytes: 32字节消息
func VerifySig(sig *bn254.G1Affine, pubkey *bn254.G2Affine, msgBytes [32]byte) (bool, error) {
	// 获取G2群的生成元
	g2Gen := GetG2Generator()
	// 将消息哈希映射到曲线G1上的点
	msgPoint := MapToCurve(msgBytes)
	// 计算签名点的负值
	var negSig bn254.G1Affine
	negSig.Neg((*bn254.G1Affine)(sig))

	// 配对检查: e(H(m), pk) == e(sig, g2)
	// 等价于检查: e(H(m), pk) * e(-sig, g2) == 1
	// 这利用了双线性对的性质
	P := [2]bn254.G1Affine{*msgPoint, negSig}
	Q := [2]bn254.G2Affine{*pubkey, *g2Gen}

	ok, err := bn254.PairingCheck(P[:], Q[:])
	if err != nil {
		return false, nil
	}
	return ok, nil

}

// MapToCurve 实现try-and-increment方法将消息哈希映射到曲线上
// 这是一个简单的确定性哈希到曲线的方法
func MapToCurve(digest [32]byte) *bn254.G1Affine {
	// 初始化常量
	one := new(big.Int).SetUint64(1)
	three := new(big.Int).SetUint64(3)
	x := new(big.Int)
	x.SetBytes(digest[:])

	// 使用try-and-increment方法找到有效的曲线点
	for {
		// 计算 y² = x³ + 3 (曲线方程)
		xP3 := new(big.Int).Exp(x, big.NewInt(3), fp.Modulus())
		y := new(big.Int).Add(xP3, three)
		y.Mod(y, fp.Modulus())

		// 尝试求平方根，如果成功则找到了有效点
		if y.ModSqrt(y, fp.Modulus()) == nil {
			// 未找到平方根，增加x继续尝试
			x.Add(x, one).Mod(x, fp.Modulus())
		} else {
			// 找到有效点，转换为曲线点格式
			var fpX, fpY fp.Element
			fpX.SetBigInt(x)
			fpY.SetBigInt(y)
			return &bn254.G1Affine{X: fpX, Y: fpY}
		}
	}
}

// CheckG1AndG2DiscreteLogEquality 检查G1点和G2点是否具有相同的离散对数
func CheckG1AndG2DiscreteLogEquality(pointG1 *bn254.G1Affine, pointG2 *bn254.G2Affine) (bool, error) {
	// 计算G1生成元的负值
	negGenG1 := new(bn254.G1Affine).Neg(GetG1Generator())
	// 使用配对检查离散对数相等性
	return bn254.PairingCheck(
		[]bn254.G1Affine{*pointG1, *negGenG1},
		[]bn254.G2Affine{*GetG2Generator(), *pointG2},
	)
}

// GetG1Generator 返回G1群的生成元
func GetG1Generator() *bn254.G1Affine {
	g1Gen := new(bn254.G1Affine)
	// 设置生成元坐标 (1, 2)
	g1Gen.X.SetString("1")
	g1Gen.Y.SetString("2")
	return g1Gen
}

// GetG2Generator 返回G2群的生成元
func GetG2Generator() *bn254.G2Affine {
	g2Gen := new(bn254.G2Affine)
	// 设置G2生成元的x和y坐标（每个坐标都是二次扩域元素）
	g2Gen.X.SetString(
		"10857046999023057135944570762232829481370756359578518086990519993285655852781",
		"11559732032986387107991004021392285783925812861821192530917403151452391805634",
	)
	g2Gen.Y.SetString(
		"8495653923123431417604973247489272438418190587263600148770280649306958101930",
		"4082367875863433681332203403145435568316851327593401208105741076214120093531",
	)
	return g2Gen
}

// MulByGeneratorG1 计算 G1生成元的标量乘法
func MulByGeneratorG1(a *fr.Element) *bn254.G1Affine {
	g1Gen := GetG1Generator()
	return new(bn254.G1Affine).ScalarMultiplication(g1Gen, a.BigInt(new(big.Int)))
}

// MulByGeneratorG2 计算 G2生成元的标量乘法
func MulByGeneratorG2(a *fr.Element) *bn254.G2Affine {
	g2Gen := GetG2Generator()
	return new(bn254.G2Affine).ScalarMultiplication(g2Gen, a.BigInt(new(big.Int)))
}
