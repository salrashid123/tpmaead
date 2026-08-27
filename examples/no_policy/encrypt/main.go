package main

import (
	"crypto/rand"
	"encoding/base64"
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
	parentPass        = flag.String("parentPass", "", "Passphrase for the owner handle (will use TPM_PARENT_AUTH env var)")
	dataToEncrypt     = flag.String("dataToEncrypt", "Highly confidential data payload goes here.", "data to encrypt")
	aad               = flag.String("aad", "user-id-10029", "AAD")
)

func main() {
	flag.Parse()

	// ***************************

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

	aead, err := tpmaead.NewAESCTRHMAC(*tpmPath, []byte(*parentPass), a, h, policySession)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	plaintext := []byte(*dataToEncrypt)
	associatedData := []byte(*aad)

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, associatedData)

	fmt.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(ciphertext))

	err = os.WriteFile(*encryptedfilepath, ciphertext, 0644)
	if err != nil {
		fmt.Printf("go-kms-wrapping: JSON indenting failed: %s", err)
		return
	}

}
