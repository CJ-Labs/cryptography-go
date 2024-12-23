package ecdsa

import (
	"crypto/ecdsa"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// go test -v -timeout 30s -run ^Test_EthereumLibSign$ cryptography/ecdsa
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
	t.Logf("Message: %s\n", message)
	t.Logf("Hash: 0x%x\n", hash)
	t.Logf("Signature: 0x%s\n", hexutil.Encode(signature))
	t.Logf("Address: %s\n", address.Hex())
	t.Logf("Recovered Address: %s\n", recoveredAddress.Hex())
}

// go test -v -timeout 30s -run ^Test_EthereumLibSignMultipleMessages$ cryptography/ecdsa
func Test_EthereumLibSignMultipleMessages(t *testing.T) {
	// 1. 使用固定私钥（仅用于测试）
	privateKey, err := crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	// 2. 获取地址
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	t.Logf("Signing with address: %s\n", address.Hex())

	// 3. 准备多个测试消息
	messages := []string{
		"Message 1",
		"Message 2",
		"Hello Ethereum!",
		"Test message",
	}

	t.Logf("\nTesting multiple message signatures:")
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
		t.Logf("\nMessage: %s\n", msg)
		t.Logf("Hash: 0x%x\n", hash)
		t.Logf("Signature: 0x%s\n", hexutil.Encode(signature))
		t.Logf("Recovered Address: %s\n", recoveredAddress.Hex())

		// 提取 r, s, v 值（用于调试）
		r := hexutil.Encode(signature[:32])
		s := hexutil.Encode(signature[32:64])
		v := signature[64]
		t.Logf("r: %s\n", r)
		t.Logf("s: %s\n", s)
		t.Logf("Raw v: %d\n", v)
		t.Logf("Ethereum v: %d\n", v+27)
	}
}

// go test -v -timeout 30s -run ^Test_EthereumLibSignWithChainID$ cryptography/ecdsa
func Test_EthereumLibSignWithChainID(t *testing.T) {
	privateKey, err := crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}

	message := "Hello Ethereum!"
	prefixedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := crypto.Keccak256Hash([]byte(prefixedMessage))

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	v := signature[64]
	t.Logf("Raw v: %d", v)
	t.Logf("Legacy Ethereum v (v+27): %d", v+27)

	// 展示不同 chainID 的 v 值
	chainIDs := []uint64{1, 3, 4, 5} // 主网, Ropsten, Rinkeby, Goerli
	for _, chainID := range chainIDs {
		eip155V := chainID*2 + 35 + uint64(v)
		t.Logf("ChainID %d -> EIP-155 v: %d", chainID, eip155V)
	}
}
