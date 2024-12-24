package pedersen

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestPedersenCommitment(t *testing.T) {
	// 1. 创建Pedersen承诺实例
	pc, err := NewPedersen()
	if err != nil {
		t.Fatalf("Failed to create Pedersen commitment: %v", err)
	}

	// 2. 测试基本承诺和验证
	t.Run("Basic Commit and Verify", func(t *testing.T) {
		// 创建值
		m := new(fr.Element).SetInt64(100)

		// 创建承诺
		commitment, opening, err := pc.Commit(m)
		if err != nil {
			t.Fatalf("Failed to create commitment: %v", err)
		}

		// 验证承诺
		if !pc.Verify(commitment, opening) {
			t.Fatal("Commitment verification failed")
		}

		t.Log("Basic commitment test passed")
	})

	// 3. 测试同态性质
	t.Run("Homomorphic Addition", func(t *testing.T) {
		// 创建两个承诺
		m1 := new(fr.Element).SetInt64(100)
		m2 := new(fr.Element).SetInt64(50)

		c1, o1, _ := pc.Commit(m1)
		c2, o2, _ := pc.Commit(m2)

		// 计算承诺的和
		sumCommitment := pc.Add(c1, c2)
		sumOpening := pc.OpenAdd(o1, o2)

		// 验证和的承诺
		if !pc.Verify(sumCommitment, sumOpening) {
			t.Fatal("Homomorphic addition verification failed")
		}

		t.Log("Homomorphic addition test passed")
	})

	// 4. 测试不同值的承诺
	t.Run("Different Values", func(t *testing.T) {
		m1 := new(fr.Element).SetInt64(100)
		m2 := new(fr.Element).SetInt64(100)

		c1, _, _ := pc.Commit(m1)
		c2, _, _ := pc.Commit(m2)

		// 即使值相同，承诺也应该不同（因为随机数不同）
		if c1.P.Equal(c2.P) {
			t.Fatal("Commitments to same value should be different")
		}

		t.Log("Different values test passed")
	})

	// 5. 测试序列化
	t.Run("Serialization", func(t *testing.T) {
		m := new(fr.Element).SetInt64(100)
		commitment, _, _ := pc.Commit(m)

		// 序列化
		data := commitment.Serialize()

		// 反序列化
		recovered, err := pc.Deserialize(data)
		if err != nil {
			t.Fatalf("Failed to deserialize commitment: %v", err)
		}

		if !recovered.P.Equal(commitment.P) {
			t.Fatal("Serialization/deserialization failed")
		}

		t.Log("Serialization test passed")
	})
}
