package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/salrashid123/tpmaead"
)

var (
	tpmPath           = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	keyfilepath       = flag.String("keyfilepath", "/tmp/key.json", "Path to save keyfiles")
	encryptedfilepath = flag.String("encryptedfilepath", "/tmp/encrypted.bin", "Path to save the encryptedfilepath")
	aad               = flag.String("aad", "user-id-10029", "AAD")
)

func main() {
	flag.Parse()

	// ***************************

	ciphertext, err := os.ReadFile(*encryptedfilepath)
	if err != nil {
		fmt.Printf("go-kms-wrapping:  Could not get PCRMap: %s", err)
		return
	}

	var kfs tpmaead.AESCTRHMACKeyFile

	kfbytes, err := os.ReadFile(*keyfilepath)
	if err != nil {
		fmt.Printf("go-kms-wrapping:  Could not read keyfile: %s", err)
		return
	}
	err = json.Unmarshal(kfbytes, &kfs)
	if err != nil {
		fmt.Printf("go-kms-wrapping:  Error parsing JSON: %v", err)
		return
	}

	a, err := keyfile.Decode([]byte(kfs.AESKey))
	if err != nil {
		fmt.Printf("go-kms-wrapping:   error loading external key: %v", err)
		return
	}

	h, err := keyfile.Decode([]byte(kfs.HMACKey))
	if err != nil {
		fmt.Printf("go-kms-wrapping:   error loading external key: %v", err)
		return
	}

	policySession, err := tpmaead.NewNoPolicySession()
	if err != nil {
		fmt.Printf("go-kms-wrapping:  Could not get PCRMap: %s", err)
		return
	}

	aead, err := tpmaead.NewAESCTRHMAC(*tpmPath, nil, a, h, policySession)
	if err != nil {
		panic(err)
	}

	associatedData := []byte(*aad)

	nonceSize := aead.NonceSize()
	retrievedNonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// // Decrypt
	decrypted, err := aead.Open(nil, retrievedNonce, actualCiphertext, associatedData)
	if err != nil {
		fmt.Println("Decryption Failure:", err)
		return
	}
	fmt.Printf("Decrypted plaintext: %s\n", string(decrypted))
}
