package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/salrashid123/tpmaead"
)

var (
	tpmPath           = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	keyfilepath       = flag.String("keyfilepath", "/tmp/key.json", "Path to save keyfiles")
	encryptedfilepath = flag.String("encryptedfilepath", "/tmp/encrypted.bin", "Path to save the encryptedfilepath")
	parentPass        = flag.String("parentPass", "", "Passphrase for the owner handle (will use TPM_PARENT_AUTH env var)")
	dataToEncrypt     = flag.String("dataToEncrypt", "Highly confidential data payload goes here.", "data to encrypt")
	aad               = flag.String("aad", "user-id-10029", "AAD")

	keyPass = flag.String("keyPass", "foo", "Passphrase for the key handle (will use TPM_KEY_AUTH env var)")
	pcrs    = flag.String("pcrs", "23:0000000000000000000000000000000000000000000000000000000000000000", "PCR Bound value (increasing order, comma separated)")
)

func main() {
	flag.Parse()

	// ***************************

	_, pcrList, pcrHash, err := tpmaead.GetPCRMap(tpm2.TPMAlgSHA256, *pcrs)
	if err != nil {
		fmt.Printf("go-kms-wrapping:  Could not get PCRMap: %s", err)
		return
	}

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
			},
		},
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

	fmt.Printf("%s\n", kfs.AESKey)
	fmt.Printf("%s\n", kfs.HMACKey)

	wrappedSecretjson, err := json.Marshal(kfs)
	if err != nil {
		fmt.Printf("go-kms-wrapping:  Error marshaling to JSON: %v", err)
		return
	}

	var prettyJSON bytes.Buffer
	// Arguments: target buffer, source bytes, prefix for every line, indent characters
	err = json.Indent(&prettyJSON, wrappedSecretjson, "", "    ")
	if err != nil {
		fmt.Printf("go-kms-wrapping: JSON indenting failed: %s", err)
		return
	}

	fmt.Println(prettyJSON.String())

	/// *********************************************************************

	var wrappb tpmaead.AESCTRHMACKeyFile
	err = json.Unmarshal(wrappedSecretjson, &wrappb)
	if err != nil {
		fmt.Printf("go-kms-wrapping:  Error parsing JSON: %v", err)
		return
	}

	a, err := keyfile.Decode([]byte(wrappb.AESKey))
	if err != nil {
		fmt.Printf("go-kms-wrapping:   error loading external key: %v", err)
		return
	}

	h, err := keyfile.Decode([]byte(wrappb.HMACKey))
	if err != nil {
		fmt.Printf("go-kms-wrapping:   error loading external key: %v", err)
		return
	}

	policySession, err := tpmaead.NewPCRAndAuthValueSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash}, []byte(*keyPass))
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
