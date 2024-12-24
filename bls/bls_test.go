package bls

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// 辅助函数：生成随机消息
func generateRandomMessage() ([32]byte, error) {
	var msg [32]byte
	_, err := rand.Read(msg[:])
	return msg, err
}

func TestBasicSignAndVerify(t *testing.T) {
	// 1. 生成密钥对
	keyPair, err := GenRandomBlsKeys()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// 打印密钥信息
	t.Logf("Private Key: %v", keyPair.PrivKey.String())
	t.Logf("Public Key G1 - X: %v", keyPair.PubKey.X.String())
	t.Logf("Public Key G1 - Y: %v", keyPair.PubKey.Y.String())

	// 2. 生成随机消息
	message, err := generateRandomMessage()
	if err != nil {
		t.Fatalf("Failed to generate random message: %v", err)
	}
	t.Logf("Message (hex): %s", hex.EncodeToString(message[:]))

	// 3. 签名消息
	signature := keyPair.SignMessage(message)
	t.Logf("Signature G1 - X: %v", signature.X.String())
	t.Logf("Signature G1 - Y: %v", signature.Y.String())

	// 4. 获取G2上的公钥并验证签名
	pubKeyG2 := keyPair.GetPubKeyG2()
	isValid := signature.Verify(pubKeyG2, message)
	if !isValid {
		t.Fatal("Signature verification failed")
	}
	t.Log("Signature verified successfully")

	// 5. 测试错误消息
	wrongMessage := [32]byte{1, 2, 3}
	isValidWrong := signature.Verify(pubKeyG2, wrongMessage)
	if isValidWrong {
		t.Fatal("Signature verification should fail with wrong message")
	}
	t.Log("Wrong message verification failed as expected")
}

func TestSignatureAggregation(t *testing.T) {
	// 1. 生成多个密钥对和消息
	n := 3 // 测试3个签名者
	keyPairs := make([]*KeyPair, n)
	signatures := make([]*Signature, n)
	messages := make([][32]byte, n)
	pubKeysG2 := make([]*G2Point, n)

	// 2. 为每个签名者生成密钥和签名
	for i := 0; i < n; i++ {
		// 生成密钥对
		var err error
		keyPairs[i], err = GenRandomBlsKeys()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}

		// 生成随机消息
		messages[i], err = generateRandomMessage()
		if err != nil {
			t.Fatalf("Failed to generate message %d: %v", i, err)
		}

		// 签名消息
		signatures[i] = keyPairs[i].SignMessage(messages[i])
		pubKeysG2[i] = keyPairs[i].GetPubKeyG2()

		t.Logf("Signer %d:", i)
		t.Logf("  Message: %s", hex.EncodeToString(messages[i][:]))
		t.Logf("  Signature - X: %v", signatures[i].X.String())
		t.Logf("  Public Key G2 - X.A0: %v", pubKeysG2[i].X.A0.String())
	}

	// 3. 聚合签名
	// 先克隆第一个签名
	aggregatedSig := &Signature{signatures[0].G1Point.Clone()}
	// 添加其他签名
	for i := 1; i < n; i++ {
		aggregatedSig.G1Point.Add(signatures[i].G1Point)
	}
	t.Logf("Aggregated Signature - X: %v", aggregatedSig.X.String())

	// 4. 验证每个原始签名
	for i := 0; i < n; i++ {
		if !signatures[i].Verify(pubKeysG2[i], messages[i]) {
			t.Fatalf("Individual signature %d verification failed", i)
		}
		t.Logf("Individual signature %d verified successfully", i)
	}
}

func TestSerializeDeserialize(t *testing.T) {
	// 1. 生成密钥对
	keyPair, err := GenRandomBlsKeys()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// 2. 序列化和反序列化公钥
	pubKeyBytes := keyPair.PubKey.Serialize()
	recoveredPubKey := new(G1Point)
	recoveredPubKey, err = recoveredPubKey.Deserialize(pubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize public key: %v", err)
	}

	// 3. 验证序列化/反序列化的正确性
	if recoveredPubKey.X.String() != keyPair.PubKey.X.String() ||
		recoveredPubKey.Y.String() != keyPair.PubKey.Y.String() {
		t.Fatal("Public key serialization/deserialization failed")
	}
	t.Log("Public key serialization/deserialization successful")

	// 4. 测试签名的序列化
	message, _ := generateRandomMessage()
	signature := keyPair.SignMessage(message)
	sigBytes := signature.Serialize()

	recoveredSig := new(G1Point)
	recoveredSig, err = recoveredSig.Deserialize(sigBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize signature: %v", err)
	}

	if recoveredSig.X.String() != signature.X.String() ||
		recoveredSig.Y.String() != signature.Y.String() {
		t.Fatal("Signature serialization/deserialization failed")
	}
	t.Log("Signature serialization/deserialization successful")
}

func TestTamperAttempts(t *testing.T) {
	// 1. 生成原始密钥对和消息
	keyPair, err := GenRandomBlsKeys()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message, err := generateRandomMessage()
	if err != nil {
		t.Fatalf("Failed to generate random message: %v", err)
	}

	// 生成签名
	signature := keyPair.SignMessage(message)
	pubKeyG2 := keyPair.GetPubKeyG2()

	// 验证原始签名（确保基本功能正常）
	if !signature.Verify(pubKeyG2, message) {
		t.Fatal("Original signature verification failed")
	}
	t.Log("Original signature verified successfully")

	// 2. 测试消息篡改
	t.Run("Tampered Message", func(t *testing.T) {
		tamperedMsg := message
		tamperedMsg[0] ^= 0xFF // 修改第一个字节
		if signature.Verify(pubKeyG2, tamperedMsg) {
			t.Fatal("Verification should fail with tampered message")
		}
		t.Log("Tampered message verification failed as expected")
	})

	// 3. 测试签名篡改
	t.Run("Tampered Signature", func(t *testing.T) {
		// 创建篡改的签名（使用不同的私钥）
		tamperedKeyPair, _ := GenRandomBlsKeys()
		tamperedSig := tamperedKeyPair.SignMessage(message)

		if tamperedSig.Verify(pubKeyG2, message) {
			t.Fatal("Verification should fail with tampered signature")
		}
		t.Log("Tampered signature verification failed as expected")
	})

	// 4. 测试公钥篡改
	t.Run("Tampered Public Key", func(t *testing.T) {
		// 创建篡改的公钥（使用不同的密钥对）
		tamperedKeyPair, _ := GenRandomBlsKeys()
		tamperedPubKey := tamperedKeyPair.GetPubKeyG2()

		if signature.Verify(tamperedPubKey, message) {
			t.Fatal("Verification should fail with tampered public key")
		}
		t.Log("Tampered public key verification failed as expected")
	})

	// 5. 测试聚合签名篡改
	t.Run("Tampered Aggregate Signature", func(t *testing.T) {
		// 创建两个正常的签名
		keyPair1, _ := GenRandomBlsKeys()
		keyPair2, _ := GenRandomBlsKeys()
		msg1, _ := generateRandomMessage()
		msg2, _ := generateRandomMessage()

		sig1 := keyPair1.SignMessage(msg1)
		sig2 := keyPair2.SignMessage(msg2)

		// 创建聚合签名
		aggregatedSig := &Signature{sig1.G1Point.Clone()}
		aggregatedSig.G1Point.Add(sig2.G1Point)

		// 尝试用错误的消息验证
		wrongMsg, _ := generateRandomMessage()
		if aggregatedSig.Verify(keyPair1.GetPubKeyG2(), wrongMsg) {
			t.Fatal("Aggregate signature verification should fail with wrong message")
		}
		t.Log("Tampered aggregate signature verification failed as expected")
	})

	// 6. 测试零签名
	t.Run("Zero Signature", func(t *testing.T) {
		zeroSig := &Signature{&G1Point{&bn254.G1Affine{}}}
		if zeroSig.Verify(pubKeyG2, message) {
			t.Fatal("Verification should fail with zero signature")
		}
		t.Log("Zero signature verification failed as expected")
	})

	// 7. 测试签名重放
	t.Run("Signature Replay", func(t *testing.T) {
		// 尝试将一个消息的签名用于另一个消息
		newMessage, _ := generateRandomMessage()
		if signature.Verify(pubKeyG2, newMessage) {
			t.Fatal("Verification should fail when signature is reused for different message")
		}
		t.Log("Signature replay attack failed as expected")
	})
}

// 运行测试：
// go test -v ./bls
