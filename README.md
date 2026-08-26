## AEAD Encryption with Trusted Platform Module

go library which implements `AES256_CTR_HMAC_SHA256` for Trusted Platform Module (TPM).

This serves to provide a form of AEAD encryption for TPMs which do not support AES GCM or other native AEAD schemes.   TPM AES encryption only support [limited operation modes](https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/alg.md#modes) such as `ctr|ofb|cbc|cfb|ecb`.  

However, you can sythesize AEAD using `AES-CTR` an `HMAC-256` keys together provides AEAD on a TPM.  For more information on AES-CTR-HMAC, see documentation for [Google TINK encryption](https://developers.google.com/tink/aead).

---

### Setup

The following shows how you can create both `AES256-CTR` and `HMAC-256` keys on a TPM.

The keys will be saved in PEM format and wrapped in a cleartext JSON file.

Then the keys will be read in and used for encrypting some data which will later get decrypted

#### Start swtpm

The following uses a software tpm (`swtpm`), in your case you will use a real tpm (eg `--tpm-path=/dev/tpmrm0`)

First stat the TPM and in a new window export the variables used by `tpm2_tools

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm && swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5

export TPM2TOOLS_TCTI="swtpm:port=2321"
```

The basic end to end sample with no policy constraint can be found in `examples/no_policy`

To use run

```bash
go run examples/no_policy/newkey/main.go
go run examples/no_policy/encrypt/main.go
go run examples/no_policy/decrypt/main.go
```

#### Create key

```golang
    // start a basic trial session
	trialSession, err := NewNoPolicySession()

    // create a keypair wihthout any policies or password constraints
	kfs, err := NewKey(swTPMPath, []byte(nil), []byte(nil), trialSession)

    // retrieve the keys.
	a, err := keyfile.Decode([]byte(kfs.AESKey))
	h, err := keyfile.Decode([]byte(kfs.HMACKey))

	fmt.Printf("%s\n", kfs.AESKey)
	fmt.Printf("%s\n", kfs.HMACKey)

    // you can then save them to a file for later us
	wrappedSecretjson, err := json.Marshal(kfs)
	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, wrappedSecretjson, "", "    ")
	fmt.Println(prettyJSON.String())
```

The TPM based keys are in PEM format described in [go-tpm-keyfiles](https://github.com/Foxboron/go-tpm-keyfiles)

```bash
$ cat /tmp/key.json | jq '.'
{
  "aesKey": "-----BEGIN TSS2 PRIVATE KEY-----\nMIIBDAYGZ4EFCgEDoAMBAf8CBEAAAAEEVABSACUACwAGADIAIAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAABAACC5SeLvsQSY9kyELbdSnFtCtqTR\nU8KOjZlnVPHhKaA2hgSBoACeACCBNCqAUV269PXihf/MPRkcAfhgEdg+h0GcxsuD\nFnvdFwAQXzyAz0zLzclIH4MuAN9AvPpWLgl0L+Ze3LT7hvL6dR73QI1L6XTm/+hl\n4ZsqLMbj+rL/X6cemh2zLQ3fFdCLn+csMyKcskDAsoHNGk1SUJKwoOuwnTtAiDzx\n/9OdvHH5TxZ5+OHBxBiCpi/nbz2gNPJXg++sUYL93uI=\n-----END TSS2 PRIVATE KEY-----\n",
  "hmacKey": "-----BEGIN TSS2 PRIVATE KEY-----\nMIIBCgYGZ4EFCgEDoAMBAf8CBEAAAAEEUgBQAAgACwAEADIAIAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUACwAgmdSTDBAbgiFhG2PS152SAC1BMuJ3\nF59uFpPNzSSWCh8EgaAAngAgrDjJYM8eq38/bcFvHqrb3i+lR9gqwzOUcb+c8DGD\nPw0AEGOW/qFzSxjlBKq/kzfgWi+nZE1BWjnnpEiwK3uURkbrvx6lYxik8BOEiqOP\nymtVXNqkjneSzHEWkFwBBK9t+gxYmBD9a1imF+nSH5hfqQsNbWgnqMxNAll5gW3/\nwiauXUWFJ8rRLjvBmtAS48lJSDWHRPDkRQx9VRZD\n-----END TSS2 PRIVATE KEY-----\n"
}
```

#### Encrypt

To encrypt, load the keys and supply the cleartext and AAD

```golang
    // read the key file and unmarshal it
	kfbytes, err := os.ReadFile(*keyfilepath)
	err = json.Unmarshal(kfbytes, &kfs)

	fmt.Printf("%s\n", kfs.AESKey)
	fmt.Printf("%s\n", kfs.HMACKey)
	wrappedSecretjson, err := json.Marshal(kfs)

    // load it into the struct to extract the aes and hmac key
	var wrappb tpmaead.AESCTRHMACKeyFile
	err = json.Unmarshal(wrappedSecretjson, &wrappb)

	a, err := keyfile.Decode([]byte(wrappb.AESKey))
	h, err := keyfile.Decode([]byte(wrappb.HMACKey))

    // now create a policy session to apply to the key operations, in this case, no policy
	policySession, err := tpmaead.NewNoPolicySession()

    // initialize the AEAD
	aead, err := tpmaead.NewAESCTRHMAC(*tpmPath, []byte(*parentPass), a, h, policySession)

    // create a nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	plaintext := []byte(*dataToEncrypt)
	associatedData := []byte(*aad)

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, associatedData)

	fmt.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(ciphertext))
```

#### Decrypt

To decrypt, run a similar sequence 

```golang
    // read the key file and unmarshal it
	kfbytes, err := os.ReadFile(*keyfilepath)
	err = json.Unmarshal(kfbytes, &kfs)

	fmt.Printf("%s\n", kfs.AESKey)
	fmt.Printf("%s\n", kfs.HMACKey)
	wrappedSecretjson, err := json.Marshal(kfs)

    // load it into the struct to extract the aes and hmac key
	var wrappb tpmaead.AESCTRHMACKeyFile
	err = json.Unmarshal(wrappedSecretjson, &wrappb)

	a, err := keyfile.Decode([]byte(wrappb.AESKey))
	h, err := keyfile.Decode([]byte(wrappb.HMACKey))

    // load the ciphertext
	ciphertext, err := os.ReadFile(*encryptedfilepath)

    // create a defaul tpolicy
	policySession, err := tpmaead.NewNoPolicySession()

    // initialize the AEAD
	aead, err := tpmaead.NewAESCTRHMAC(*tpmPath, []byte(nil), a, h, policySession)

    // set the AAD, extract just the ciphertext and decrypt
	associatedData := []byte(*aad)
	nonceSize := aead.NonceSize()
	retrievedNonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	decrypted, err := aead.Open(nil, retrievedNonce, actualCiphertext, associatedData)
	fmt.Printf("Decrypted plaintext: %s\n", string(decrypted))
```

##### With PCR and AuthValue Policy

The `examples/policy/` folder contains similar examples to the above except that you can apply a PCR and AuthValue (passowrd) to the keys.

What this allows you to do is to set PCR and password conditions whenever you encrypt or decrypt data.

This repo contains 

* `NoPolicySession()`
* `NewPCRAndAuthValueSession()`

but you can define you rown policy sequence using a similar pattern by implementing the following interface 

```golang
type Session interface {
	GetSession(rwr transport.TPM, setTrial bool) (auth tpm2.Session, closer func() error, err error)
}
```

### Test Vector

This repo was validated against a testVector from [boringssl aes_256_ctr_hmac_sha256.txt](https://boringssl.googlesource.com/boringssl.git/+/09f7078f953362d5c5afdd224118845327b60fb4/src/crypto/cipher_extra/test/aes_256_ctr_hmac_sha256.txt#106)

where the following key, nonce, input, aad would result in a given ciphertext and tag

```
KEY: e787fdeca1095f2f2760a1c5e0f302e07d6b08de39ce31fe6a0db2f76e4626eb0968768ae04d37082c114573c307699707630b8c7ceef60abe3b7831d2adcd6e
NONCE: 9dc9bcfe8b4e2ea059e349bb
IN: 3ad57105144e544f95b82d485f80bb
AD: 96bce5dcaf4a90f6638a7e30cfd840a1e8dbc60cb70ab9592803f8799f909cafe71a83c2d884e1e289cc61e7
CT: e504109cdbf57b0e8a87080379e00d
TAG: 1798a64b5261761ecd88f36eaf7f86ed3db62100aed20dc6e337bc93c459487e
```

the expected output would be in the form

`Output = (NONCE+CT+TAG) = 9dc9bcfe8b4e2ea059e349bbe504109cdbf57b0e8a87080379e00d1798a64b5261761ecd88f36eaf7f86ed3db62100aed20dc6e337bc93c459487e`

which is what we see in the unittests and when the known aes and hmac keys are imported into the TPM in the `examples/test_vector` folder

```bash
$ go test -v -run=TestVector/basic
=== RUN   TestVector
=== RUN   TestVector/basic
    tpmaead_test.go:402: CipherText: 9dc9bcfe8b4e2ea059e349bbe504109cdbf57b0e8a87080379e00d1798a64b5261761ecd88f36eaf7f86ed3db62100aed20dc6e337bc93c459487e
--- PASS: TestVector (0.02s)
    --- PASS: TestVector/basic (0.02s)
PASS
ok  	github.com/salrashid123/tpmaead	0.032s
```

### Generate External Key

If you want, you can generate or import an external key as well using `tpm2_tools`:

The fillwoing creates an AES key with PCR and AuthValue constraints and then creates the PEM format of those keys for import


#### AES

```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_startauthsession   -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  

## to import a key
# dd if=/dev/urandom of=sym.key bs=1 count=32
# tpm2_import -C primary.ctx -G aes256ctr -i sym.key -u aes.pub -r aes.priv -L policy.dat -pfoo
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  

## to create a key
tpm2_create -g sha256 -G aes256ctr -u aes.pub -r aes.priv -C primary.ctx   -L policy.dat -pfoo
tpm2_flushcontext -t

# then load
tpm2_load -C primary.ctx -u aes.pub -r aes.priv -n aes.name -c decrypt.ctx

# encrypt
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_startauthsession  --policy-session  -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat
tpm2_encryptdecrypt -Q --iv iv.bin -c decrypt.ctx -o encrypt.out secret.dat  -p"session:session.dat+foo"


# decrypt
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
tpm2_startauthsession  --policy-session  -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat
tpm2_encryptdecrypt -Q --iv iv.bin -c decrypt.ctx -d -o decrypt.out encrypt.out -p"session:session.dat+foo"

tpm2_encodeobject -C primary.ctx -u aes.pub -r  aes.priv -o aes.pem
```

#### HMAC

```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_startauthsession   -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  

### to import a key
# echo -n "change this password to a secret" > hmac.key
# hexkey=$(xxd -p -c 256 < hmac.key)
# tpm2 import -C primary.ctx -G hmac -g sha256 -i hmac.key -u hmac.pub -r hmac.priv  -L policy.dat -pfoo
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  

### to create a key
tpm2_create -G hmac:sha256  -g sha256  -u hmac.pub -r hmac.priv -C primary.ctx -L policy.dat -pfoo
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  


### to test hmac
tpm2 load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx

echo "foo" > secret.dat

tpm2_startauthsession  --policy-session  -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat
tpm2_hmac -g sha256 -c hmac.ctx  -p"session:session.dat+foo" --hex secret.dat

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l 

tpm2_encodeobject -C primary.ctx -u hmac.pub -r  hmac.priv -o hmac.pem
```

```bash
export AES_KEY="$(awk '{printf "%s\\n", $0}' aes.pem)"
export HMAC_KEY="$(awk '{printf "%s\\n", $0}' hmac.pem)"

echo -n '{"aesKey":"$AES_KEY","hmacKey":"$HMAC_KEY"}' > key.json.tmpl
envsubst < "key.json.tmpl" > "/tmp/key_test_vector.json"
```

### References

* [RFC3686: Using Advanced Encryption Standard (AES) Counter Mode](https://www.rfc-editor.org/info/rfc3686/)
* [https://github.com/tmthrgd/aes-ctr-hmac-sha256](https://github.com/tmthrgd/aes-ctr-hmac-sha256)
