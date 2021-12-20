package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// I SKIDDED FROM THE DOCS
// ISSUE: I SKIDDED FROM THE DOCS.
import (
	"bytes"
	"encoding/base64"
)

func AesEncrypt(orig string, key string) string {
	// Convert to byte array
	origData := []byte(orig)
	k := []byte(key)

	// Group secret key
	block, err := aes.NewCipher(k)
	if err != nil {
		// wtf man Imma kms brb
		panic(fmt.Sprintf("key The length must be 16/24/32 length: %s", err.Error()))
	}
	// Gets the length of the secret key block
	blockSize := block.BlockSize()
	// Complement code
	origData = PKCS7Padding(origData, blockSize)
	// Encryption mode
	blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])
	// Create array
	cryted := make([]byte, len(origData))
	// encryption
	blockMode.CryptBlocks(cryted, origData)
	//Use RawURLEncoding instead of StdEncoding
	//Do not use StdEncoding in the url parameter to cause errors
	return base64.RawURLEncoding.EncodeToString(cryted)

}

func AesDecrypt(cryted string, key string) string {
	//Use RawURLEncoding instead of StdEncoding
	//Do not use StdEncoding in the url parameter to cause errors
	crytedByte, _ := base64.RawURLEncoding.DecodeString(cryted)
	k := []byte(key)

	// Group secret key
	block, err := aes.NewCipher(k)
	if err != nil {
		panic(fmt.Sprintf("key The length must be 16/24/32 length: %s", err.Error()))
	}
	// Gets the length of the secret key block
	blockSize := block.BlockSize()
	// Encryption mode
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	// Create array
	orig := make([]byte, len(crytedByte))
	// decrypt
	blockMode.CryptBlocks(orig, crytedByte)
	// De completion code
	orig = PKCS7UnPadding(orig)
	return string(orig)
}

//Complement
func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
	padding := blocksize - len(ciphertext)%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//De coding
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
