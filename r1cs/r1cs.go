package main

import (
	"fmt"
	"math/big"
)

// Vector 表示R1CS中的向量
type Vector struct {
	elements []*big.Int
}

// NewVector 创建新向量
func NewVector(size int) *Vector {
	v := &Vector{
		elements: make([]*big.Int, size),
	}
	fmt.Println("NewVector 000", v)
	for i := 0; i < size; i++ {
		v.elements[i] = big.NewInt(0)
	}
	fmt.Println("NewVector 111", v)

	return v
}

// DotProduct 计算两个向量的点积
// 参数 other: 要进行点积运算的另一个向量
// 返回值: 两个向量的点积结果（大整数）
func (v *Vector) DotProduct(other *Vector) *big.Int {
	// 检查两个向量的维度是否相同
	// 如果维度不同，无法计算点积，抛出panic
	if len(v.elements) != len(other.elements) {
		panic("Vector dimensions do not match")
	}

	// 创建一个大整数用于存储最终的点积结果
	// 初始值设为0
	result := big.NewInt(0)

	// 创建一个临时大整数用于存储每次相乘的中间结果
	// 避免在循环中重复创建对象
	temp := big.NewInt(0)

	// 遍历两个向量的所有元素
	for i := 0; i < len(v.elements); i++ {
		// 计算当前位置两个元素的乘积
		// temp = v[i] * other[i]
		// Mul方法将两个大整数相乘，结果存储在temp中
		temp.Mul(v.elements[i], other.elements[i])

		// 将乘积累加到结果中
		// result += temp
		// Add方法将result和temp相加，结果存储在result中
		result.Add(result, temp)
	}

	// 返回最终的点积结果
	return result
}

// R1CSConstraint 表示一个R1CS约束
type R1CSConstraint struct {
	a *Vector
	b *Vector
	c *Vector
}

// R1CS 表示一个完整的R1CS系统
type R1CS struct {
	constraints []*R1CSConstraint
	witness     *Vector
}

// NewR1CS 创建新的R1CS系统
func NewR1CS(numConstraints, witnessSize int) *R1CS {
	return &R1CS{
		constraints: make([]*R1CSConstraint, numConstraints),
		witness:     NewVector(witnessSize),
	}
}

// Verify 验证R1CS约束是否满足
func (r *R1CS) Verify() bool {
	for i, constraint := range r.constraints {
		// 计算 (a·w)(b·w) = (c·w)
		// 创建一个大整数用于存储左手边(LHS)的计算结果
		lhs := big.NewInt(0)
		// 1. constraint.a.DotProduct(r.witness) 计算向量a和witness的点积
		// 2. constraint.b.DotProduct(r.witness) 计算向量b和witness的点积
		// 3. lhs.Mul(...) 将两个点积相乘
		lhs.Mul(
			constraint.a.DotProduct(r.witness),
			constraint.b.DotProduct(r.witness),
		)

		// 计算右手边(RHS)：c·w
		// 计算向量c和witness的点积
		rhs := constraint.c.DotProduct(r.witness)

		if lhs.Cmp(rhs) != 0 {
			fmt.Printf("Constraint %d failed\n", i)
			fmt.Printf("LHS: %s\n", lhs.String())
			fmt.Printf("RHS: %s\n", rhs.String())
			return false
		}
	}
	return true
}

// 示例：实现 result = (a + b) * c
func main() {
	// 创建R1CS系统，参数说明：
	// - 2: 需要2个约束（一个用于加法，一个用于乘法）
	// - 6: witness向量长度（包含：1, a, b, c, temp, result）
	r1cs := NewR1CS(2, 6)

	// 设置witness值（示例值）
	r1cs.witness.elements[0] = big.NewInt(1)  // 常数1
	r1cs.witness.elements[1] = big.NewInt(2)  // a = 2
	r1cs.witness.elements[2] = big.NewInt(3)  // b = 3
	r1cs.witness.elements[3] = big.NewInt(4)  // c = 4
	r1cs.witness.elements[4] = big.NewInt(5)  // temp = a + b = 5
	r1cs.witness.elements[5] = big.NewInt(20) // result = temp * c = 20

	// 第一个约束：实现 temp = a + b
	// 	约束1（加法）工作原理：
	// (a·w)(b·w) = (c·w)
	// (1)([a + b]) = (temp)
	// 验证 temp 确实等于 a + b
	constraint1 := &R1CSConstraint{
		a: NewVector(6), // 创建长度为6的向量
		b: NewVector(6),
		c: NewVector(6),
	}
	// 1. 设置a向量：[1, 0, 0, 0, 0, 0]
	// 这个1将用于构建加法运算
	constraint1.a.elements[0] = big.NewInt(1)
	// 2. 设置b向量：[0, 1, 1, 0, 0, 0]
	// 表示要相加的两个变量a和b
	constraint1.b.elements[1] = big.NewInt(1)
	constraint1.b.elements[2] = big.NewInt(1)
	// 3. 设置c向量：[0, 0, 0, 0, 1, 0]
	// 结果存储在temp位置
	constraint1.c.elements[4] = big.NewInt(1)

	// 第二个约束：实现 result = temp * c
	constraint2 := &R1CSConstraint{
		a: NewVector(6),
		b: NewVector(6),
		c: NewVector(6),
	}
	// 设置a向量：[0, 0, 0, 1, 0, 0]
	// 选择变量c作为第一个乘数
	constraint2.a.elements[3] = big.NewInt(1)

	// 设置b向量：[0, 0, 0, 0, 1, 0]
	// 选择temp作为第二个乘数
	constraint2.b.elements[4] = big.NewInt(1)

	// 设置c向量：[0, 0, 0, 0, 0, 1]
	// 结果存储在result位置
	constraint2.c.elements[5] = big.NewInt(1)

	// 将约束添加到R1CS系统
	r1cs.constraints[0] = constraint1 // 加法约束
	r1cs.constraints[1] = constraint2 // 乘法约束

	// 验证所有约束是否满足
	if r1cs.Verify() {
		fmt.Println("All constraints satisfied!")                     // 所有约束都满足
		fmt.Printf("Result: %s\n", r1cs.witness.elements[5].String()) // 打印结果
	} else {
		fmt.Println("Constraints not satisfied!") // 约束不满足
	}
}
