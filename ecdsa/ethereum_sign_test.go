package ecdsa

import (
	"crypto/ecdsa"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func Test_EthereumLibSign(t *testing.T) {
	// 1. 生成以太坊私钥
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// 2. 获取公钥和地址
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Failed to get public key")
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	// 3. 准备消息
	message := []byte("Hello Ethereum!")

	// 4. 计算消息哈希
	// 添加以太坊特定前缀
	prefixedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := crypto.Keccak256Hash([]byte(prefixedMessage))

	// 5. 签名消息
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// 6. 从签名中恢复公钥
	recoveredPubKey, err := crypto.SigToPub(hash.Bytes(), signature)
	if err != nil {
		t.Fatalf("Failed to recover public key: %v", err)
	}
	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey)

	// 7. 验证地址是否匹配
	if address != recoveredAddress {
		t.Error("Recovered address doesn't match original")
	}

	// 8. 打印详细信息
	fmt.Printf("Message: %s\n", message)
	fmt.Printf("Hash: 0x%x\n", hash)
	fmt.Printf("Signature: 0x%s\n", hexutil.Encode(signature))
	fmt.Printf("Address: %s\n", address.Hex())
	fmt.Printf("Recovered Address: %s\n", recoveredAddress.Hex())
}

func Test_EthereumLibSignMultipleMessages(t *testing.T) {
	// 1. 使用固定私钥（仅用于测试）
	privateKey, err := crypto.HexToECDSA("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}

	// 2. 获取地址
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	fmt.Printf("Signing with address: %s\n", address.Hex())

	// 3. 准备多个测试消息
	messages := []string{
		"Message 1",
		"Message 2",
		"Hello Ethereum!",
		"Test message",
	}

	fmt.Println("\nTesting multiple message signatures:")
	for _, msg := range messages {
		// 计算消息哈希
		prefixedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)
		hash := crypto.Keccak256Hash([]byte(prefixedMessage))

		// 签名消息
		signature, err := crypto.Sign(hash.Bytes(), privateKey)
		if err != nil {
			t.Errorf("Failed to sign message '%s': %v", msg, err)
			continue
		}

		// 恢复公钥
		recoveredPubKey, err := crypto.SigToPub(hash.Bytes(), signature)
		if err != nil {
			t.Errorf("Failed to recover public key for message '%s': %v", msg, err)
			continue
		}
		recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey)

		// 验证地址
		if address != recoveredAddress {
			t.Errorf("Recovered address doesn't match for message '%s'", msg)
		}

		// 打印详细信息
		fmt.Printf("\nMessage: %s\n", msg)
		fmt.Printf("Hash: 0x%x\n", hash)
		fmt.Printf("Signature: 0x%s\n", hexutil.Encode(signature))
		fmt.Printf("Recovered Address: %s\n", recoveredAddress.Hex())

		// 提取 r, s, v 值（用于调试）
		r := hexutil.Encode(signature[:32])
		s := hexutil.Encode(signature[32:64])
		v := signature[64]
		fmt.Printf("r: %s\n", r)
		fmt.Printf("s: %s\n", s)
		fmt.Printf("v: %d\n", v)
	}
}
