package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/salrashid123/tpmaead"
)

/*

Verifies the TestVector AES256-CTR-HMAC from

https://boringssl.googlesource.com/boringssl.git/+/09f7078f953362d5c5afdd224118845327b60fb4/src/crypto/cipher_extra/test/aes_256_ctr_hmac_sha256.txt#106

given:

KEY: e787fdeca1095f2f2760a1c5e0f302e07d6b08de39ce31fe6a0db2f76e4626eb0968768ae04d37082c114573c307699707630b8c7ceef60abe3b7831d2adcd6e
NONCE: 9dc9bcfe8b4e2ea059e349bb
IN: 3ad57105144e544f95b82d485f80bb
AD: 96bce5dcaf4a90f6638a7e30cfd840a1e8dbc60cb70ab9592803f8799f909cafe71a83c2d884e1e289cc61e7
CT: e504109cdbf57b0e8a87080379e00d
TAG: 1798a64b5261761ecd88f36eaf7f86ed3db62100aed20dc6e337bc93c459487e

Essentially, the following commands seeds a known AES and HMAC key into the TPM and then encrypts  plaintext (IN) with the additional data (AD) with a known Nonce (NONCE)

The expected output is the (NONCE+CT+TAG)=9dc9bcfe8b4e2ea059e349bbe504109cdbf57b0e8a87080379e00d1798a64b5261761ecd88f36eaf7f86ed3db62100aed20dc6e337bc93c459487e

---

### first setup the keys

echo -n "e787fdeca1095f2f2760a1c5e0f302e07d6b08de39ce31fe6a0db2f76e4626eb" | xxd -r -p > sym.key
echo -n "0968768ae04d37082c114573c307699707630b8c7ceef60abe3b7831d2adcd6e" | xxd -r -p > hmac.key

### import AES key

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_startauthsession   -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_import -C primary.ctx -G aes256ctr -i sym.key -u aes.pub -r aes.priv -L policy.dat -pfoo
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_encodeobject -C primary.ctx -u aes.pub -r  aes.priv -o aes.pem

### import HMAC Key

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_startauthsession   -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2 import -C primary.ctx -G hmac -g sha256 -i hmac.key -u hmac.pub -r hmac.priv  -L policy.dat -pfoo
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_encodeobject -C primary.ctx -u hmac.pub -r  hmac.priv -o hmac.pem

### create key json

export AES_KEY="$(awk '{printf "%s\\n", $0}' aes.pem)"
export HMAC_KEY="$(awk '{printf "%s\\n", $0}' hmac.pem)"

echo -n '{"aesKey":"$AES_KEY","hmacKey":"$HMAC_KEY"}' > key.json.tmpl
envsubst < "key.json.tmpl" > "/tmp/key_test_vector.json"

$ go run encrypt_vector/main.go
*/

var (
	tpmPath           = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	keyfilepath       = flag.String("keyfilepath", "/tmp/key_test_vector.json", "Path to save keyfiles")
	encryptedfilepath = flag.String("encryptedfilepath", "/tmp/encrypted.bin", "Path to save the encryptedfilepath")
	parentPass        = flag.String("parentPass", "", "Passphrase for the owner handle (will use TPM_PARENT_AUTH env var)")

	keyPass = flag.String("keyPass", "foo", "Passphrase for the key handle (will use TPM_KEY_AUTH env var)")
	pcrs    = flag.String("pcrs", "23:0000000000000000000000000000000000000000000000000000000000000000", "PCR Bound value (increasing order, comma separated)")
)

const (
	hexNonce     = "9dc9bcfe8b4e2ea059e349bb"
	hexPlainText = "3ad57105144e544f95b82d485f80bb"
	hexAAD       = "96bce5dcaf4a90f6638a7e30cfd840a1e8dbc60cb70ab9592803f8799f909cafe71a83c2d884e1e289cc61e7"
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

	nonce, _ := hex.DecodeString(hexNonce)
	plaintext, _ := hex.DecodeString(hexPlainText)
	associatedData, _ := hex.DecodeString(hexAAD)

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, associatedData)

	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

	err = os.WriteFile(*encryptedfilepath, ciphertext, 0644)
	if err != nil {
		fmt.Printf("go-kms-wrapping: JSON indenting failed: %s", err)
		return
	}

	// // Decrypt
	nonceSize := aead.NonceSize()
	retrievedNonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	decrypted, err := aead.Open(nil, retrievedNonce, actualCiphertext, associatedData)
	if err != nil {
		fmt.Println("Decryption Failure:", err)
		return
	}
	fmt.Printf("Decrypted plaintext: %s\n", hex.EncodeToString(decrypted))
}
