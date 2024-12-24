package pedersen

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// 安全地生成第二个生成元 H
func generateSecondGenerator(firstGen *bn254.G1Affine) (*bn254.G1Affine, error) {
	h := new(bn254.G1Affine)

	// 使用一个唯一的种子
	seed := []byte("pedersen_commitment_second_generator_v1")

	// 添加一些随机性
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}

	// 组合种子
	hasher := sha256.New()
	hasher.Write(seed)
	hasher.Write(randomBytes)
	firstGenBytes := firstGen.Bytes()
	hasher.Write(firstGenBytes[:]) // 修复: 使用切片语法
	hash := hasher.Sum(nil)

	// 尝试将哈希值映射到曲线上
	maxTries := 100
	for i := 0; i < maxTries; i++ {
		// 更新哈希
		hasher := sha256.New()
		hasher.Write(hash)
		hash = hasher.Sum(nil)

		// 尝试将哈希值转换为曲线上的点
		var err error
		h, err = HashToCurvePoint(hash)
		if err == nil && !h.Equal(&bn254.G1Affine{}) && !h.Equal(firstGen) { // 修复: 使用 Equal 检查零点
			return h, nil
		}
	}

	return nil, errors.New("failed to generate valid second generator")
}

// 将字节哈希到曲线上的点
func HashToCurvePoint(hash []byte) (*bn254.G1Affine, error) {
	// 初始化常量
	one := new(big.Int).SetUint64(1)
	three := new(big.Int).SetUint64(3)

	// 将哈希转换为大整数作为初始 x 坐标
	x := new(big.Int).SetBytes(hash)

	// 创建返回点
	point := new(bn254.G1Affine)

	// 最大尝试次数
	maxTries := 100
	for i := 0; i < maxTries; i++ {
		// 计算 y² = x³ + 3 (曲线方程)
		xP3 := new(big.Int).Exp(x, big.NewInt(3), fp.Modulus())
		y := new(big.Int).Add(xP3, three)
		y.Mod(y, fp.Modulus())

		// 尝试求平方根
		if y.ModSqrt(y, fp.Modulus()) != nil {
			// 找到有效点，转换为曲线点格式
			var fpX, fpY fp.Element
			fpX.SetBigInt(x)
			fpY.SetBigInt(y)
			point.X = fpX
			point.Y = fpY

			// 验证点是否在曲线上
			if point.IsOnCurve() && !point.IsInfinity() {
				return point, nil
			}
		}

		// 未找到有效点，增加x继续尝试
		x.Add(x, one).Mod(x, fp.Modulus())
	}

	return nil, errors.New("failed to find valid curve point")
}
