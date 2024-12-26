package ecdsa

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func Test_generate_ethereum_verify_ecdsa(t *testing.T) {
	// 生成以太坊地址
	address := generateEthereumAddressCore()
	fmt.Println("Ethereum Address:", address)

	// 校验地址是否有效
	if !common.IsHexAddress(address) {
		t.Errorf("Generated address is not valid: %s", address)
	} else {
		fmt.Println("Generated address is valid.")
	}
}
