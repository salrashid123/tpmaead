package tpmaead

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

const (
	swTPMPath = "127.0.0.1:2321"
)

var (
	rsaTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}
)

func TestPolicyPCRAndAuthValueSession(t *testing.T) {

	tests := []struct {
		name          string
		dataToEncrypt string
		aad           string
		pcrs          string
		keyPass       string
		parentPass    string
	}{
		{"pcr_and_authvalue", "foo", "myaad", "23:0000000000000000000000000000000000000000000000000000000000000000", "bar", ""},
		{"authvalue", "bar", "myaad", "", "bar", ""},
		{"pcr", "bar", "myaad", "23:0000000000000000000000000000000000000000000000000000000000000000", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, pcrList, pcrHash, err := GetPCRMap(tpm2.TPMAlgSHA256, tc.pcrs)

			require.NoError(t, err)

			sel := tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
					},
				},
			}

			trialSession, err := NewPCRAndAuthValueSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash}, nil)
			require.NoError(t, err)

			kfs, err := NewKey(swTPMPath, []byte(tc.keyPass), []byte(tc.parentPass), trialSession)
			require.NoError(t, err)

			/// *********************************************************************

			a, err := keyfile.Decode([]byte(kfs.AESKey))
			require.NoError(t, err)

			h, err := keyfile.Decode([]byte(kfs.HMACKey))
			require.NoError(t, err)

			policySessionEncrypt, err := NewPCRAndAuthValueSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash}, []byte(tc.keyPass))
			require.NoError(t, err)

			aeadE, err := NewAESCTRHMAC(swTPMPath, []byte(tc.parentPass), a, h, policySessionEncrypt)
			require.NoError(t, err)

			nonce := make([]byte, aeadE.NonceSize())
			_, err = rand.Read(nonce)
			require.NoError(t, err)

			plaintext := []byte(tc.dataToEncrypt)
			associatedData := []byte(tc.aad)

			// Encrypt
			ciphertext := aeadE.Seal(nil, nonce, plaintext, associatedData)

			// Decrypt
			policySessionDecrypt, err := NewPCRAndAuthValueSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash}, []byte(tc.keyPass))
			require.NoError(t, err)

			aeadD, err := NewAESCTRHMAC(swTPMPath, []byte(tc.parentPass), a, h, policySessionDecrypt)
			require.NoError(t, err)

			nonceSize := aeadD.NonceSize()
			retrievedNonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

			// // Decrypt
			decrypted, err := aeadD.Open(nil, retrievedNonce, actualCiphertext, associatedData)
			require.NoError(t, err)
			require.Equal(t, tc.dataToEncrypt, string(decrypted))

		})
	}
}

func TestNoPolicy(t *testing.T) {

	dataToEncrypt := "foo"
	aad := "myaad"
	trialSession, err := NewNoPolicySession()
	require.NoError(t, err)

	kfs, err := NewKey(swTPMPath, []byte(nil), []byte(nil), trialSession)
	require.NoError(t, err)

	a, err := keyfile.Decode([]byte(kfs.AESKey))
	require.NoError(t, err)

	h, err := keyfile.Decode([]byte(kfs.HMACKey))
	require.NoError(t, err)

	policySessionEncrypt, err := NewNoPolicySession()
	require.NoError(t, err)

	aeadE, err := NewAESCTRHMAC(swTPMPath, []byte(nil), a, h, policySessionEncrypt)
	require.NoError(t, err)

	nonce := make([]byte, aeadE.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	plaintext := []byte(dataToEncrypt)
	associatedData := []byte(aad)

	// Encrypt
	ciphertext := aeadE.Seal(nil, nonce, plaintext, associatedData)

	// Decrypt
	policySessionDecrypt, err := NewNoPolicySession()
	require.NoError(t, err)

	aeadD, err := NewAESCTRHMAC(swTPMPath, []byte(nil), a, h, policySessionDecrypt)
	require.NoError(t, err)

	nonceSize := aeadD.NonceSize()
	retrievedNonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// // Decrypt
	decrypted, err := aeadD.Open(nil, retrievedNonce, actualCiphertext, associatedData)
	require.NoError(t, err)
	require.Equal(t, dataToEncrypt, string(decrypted))

}

func TestPolicyAuthValue(t *testing.T) {

	dataToEncrypt := []byte("bar")
	passwd := []byte("foo")
	trialSession, err := NewPolicyAuthValueSession(passwd)
	require.NoError(t, err)

	kfs, err := NewKey(swTPMPath, []byte(passwd), []byte(nil), trialSession)
	require.NoError(t, err)

	/// *********************************************************************

	a, err := keyfile.Decode([]byte(kfs.AESKey))
	require.NoError(t, err)

	h, err := keyfile.Decode([]byte(kfs.HMACKey))
	require.NoError(t, err)

	policySessionEncrypt, err := NewPolicyAuthValueSession(passwd)
	require.NoError(t, err)

	aeadE, err := NewAESCTRHMAC(swTPMPath, nil, a, h, policySessionEncrypt)
	require.NoError(t, err)

	nonce := make([]byte, aeadE.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	plaintext := dataToEncrypt
	associatedData := []byte("aad")

	// Encrypt
	ciphertext := aeadE.Seal(nil, nonce, plaintext, associatedData)

	// Decrypt
	policySessionDecrypt, err := NewPolicyAuthValueSession(passwd)
	require.NoError(t, err)

	aeadD, err := NewAESCTRHMAC(swTPMPath, nil, a, h, policySessionDecrypt)
	require.NoError(t, err)

	nonceSize := aeadD.NonceSize()
	retrievedNonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// // Decrypt
	decrypted, err := aeadD.Open(nil, retrievedNonce, actualCiphertext, associatedData)
	require.NoError(t, err)
	require.Equal(t, string(dataToEncrypt), string(decrypted))
}

func TestPolicyPCR(t *testing.T) {

	dataToEncrypt := []byte("bar")

	_, pcrList, pcrHash, err := GetPCRMap(tpm2.TPMAlgSHA256, "23:0000000000000000000000000000000000000000000000000000000000000000")

	require.NoError(t, err)

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
			},
		},
	}

	trialSession, err := NewPCRSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash})
	require.NoError(t, err)

	kfs, err := NewKey(swTPMPath, []byte(nil), []byte(nil), trialSession)
	require.NoError(t, err)

	/// *********************************************************************

	a, err := keyfile.Decode([]byte(kfs.AESKey))
	require.NoError(t, err)

	h, err := keyfile.Decode([]byte(kfs.HMACKey))
	require.NoError(t, err)

	policySessionEncrypt, err := NewPCRSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash})
	require.NoError(t, err)

	aeadE, err := NewAESCTRHMAC(swTPMPath, nil, a, h, policySessionEncrypt)
	require.NoError(t, err)

	nonce := make([]byte, aeadE.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	plaintext := dataToEncrypt
	associatedData := []byte("aad")

	// Encrypt
	ciphertext := aeadE.Seal(nil, nonce, plaintext, associatedData)

	// Decrypt
	policySessionDecrypt, err := NewPCRSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash})
	require.NoError(t, err)

	aeadD, err := NewAESCTRHMAC(swTPMPath, nil, a, h, policySessionDecrypt)
	require.NoError(t, err)

	nonceSize := aeadD.NonceSize()
	retrievedNonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// // Decrypt
	decrypted, err := aeadD.Open(nil, retrievedNonce, actualCiphertext, associatedData)
	require.NoError(t, err)
	require.Equal(t, string(dataToEncrypt), string(decrypted))
}

func TestVector(t *testing.T) {

	// https://boringssl.googlesource.com/boringssl.git/+/09f7078f953362d5c5afdd224118845327b60fb4/src/crypto/cipher_extra/test/aes_256_ctr_hmac_sha256.txt#106
	// KEY: e787fdeca1095f2f2760a1c5e0f302e07d6b08de39ce31fe6a0db2f76e4626eb0968768ae04d37082c114573c307699707630b8c7ceef60abe3b7831d2adcd6e
	// NONCE: 9dc9bcfe8b4e2ea059e349bb
	// IN: 3ad57105144e544f95b82d485f80bb
	// AD: 96bce5dcaf4a90f6638a7e30cfd840a1e8dbc60cb70ab9592803f8799f909cafe71a83c2d884e1e289cc61e7
	// CT: e504109cdbf57b0e8a87080379e00d
	// TAG: 1798a64b5261761ecd88f36eaf7f86ed3db62100aed20dc6e337bc93c459487e

	tests := []struct {
		name          string
		dataToEncrypt string
		aesKey        string
		hmacKey       string
		aad           string
		nonce         string
		ciphertext    string
		tag           string
	}{
		{"basic", "3ad57105144e544f95b82d485f80bb", "e787fdeca1095f2f2760a1c5e0f302e07d6b08de39ce31fe6a0db2f76e4626eb",
			"0968768ae04d37082c114573c307699707630b8c7ceef60abe3b7831d2adcd6e",
			"96bce5dcaf4a90f6638a7e30cfd840a1e8dbc60cb70ab9592803f8799f909cafe71a83c2d884e1e289cc61e7", "9dc9bcfe8b4e2ea059e349bb",
			"e504109cdbf57b0e8a87080379e00d", "1798a64b5261761ecd88f36eaf7f86ed3db62100aed20dc6e337bc93c459487e"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			rwc, err := openTPM(swTPMPath)
			require.NoError(t, err)
			defer rwc.Close()
			rwr := transport.FromReadWriter(rwc)

			aKey, err := hex.DecodeString(tc.aesKey)
			require.NoError(t, err)
			hKey, err := hex.DecodeString(tc.hmacKey)
			require.NoError(t, err)
			nvB, err := hex.DecodeString(tc.nonce)
			require.NoError(t, err)
			plaintextB, err := hex.DecodeString(tc.dataToEncrypt)
			require.NoError(t, err)
			aadB, err := hex.DecodeString(tc.aad)
			require.NoError(t, err)
			ciphterTextB, err := hex.DecodeString(tc.ciphertext)
			require.NoError(t, err)
			tagB, err := hex.DecodeString(tc.tag)
			require.NoError(t, err)

			_, pcrList, pcrHash, err := GetPCRMap(tpm2.TPMAlgSHA256, "")
			require.NoError(t, err)

			sel := tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
					},
				},
			}

			primaryKey, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHOwner,
					Auth:   tpm2.PasswordAuth(nil),
				},
				InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
			}.Execute(rwr)
			require.NoError(t, err)
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			sessTrial, err := NewPCRAndAuthValueSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash}, nil)
			require.NoError(t, err)

			trialSession, trialSessionCloser, err := sessTrial.GetSession(rwr, true)
			require.NoError(t, err)
			defer trialSessionCloser()

			dgst, err := tpm2.PolicyGetDigest{
				PolicySession: trialSession.Handle(),
			}.Execute(rwr)
			require.NoError(t, err)

			authPolicy := dgst.PolicyDigest

			sv := make([]byte, 32)
			io.ReadFull(rand.Reader, sv)
			privHash := crypto.SHA256.New()
			privHash.Write(sv)
			privHash.Write(aKey)

			aesTemplate := tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgSymCipher,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:            false,
					FixedParent:         false,
					SensitiveDataOrigin: false,
					UserWithAuth:        true,
					SignEncrypt:         true,
					Decrypt:             true,
				},
				AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy.Buffer},
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgSymCipher,
					&tpm2.TPMSSymCipherParms{
						Sym: tpm2.TPMTSymDefObject{
							Algorithm: tpm2.TPMAlgAES,
							Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCTR),
							KeyBits: tpm2.NewTPMUSymKeyBits(
								tpm2.TPMAlgAES,
								tpm2.TPMKeyBits(256),
							),
						},
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgSymCipher,
					&tpm2.TPM2BDigest{
						Buffer: privHash.Sum(nil),
					},
				),
			}

			sens2B := tpm2.Marshal(tpm2.TPMTSensitive{
				SensitiveType: tpm2.TPMAlgSymCipher,
				AuthValue: tpm2.TPM2BAuth{
					Buffer: nil,
				},
				SeedValue: tpm2.TPM2BDigest{
					Buffer: sv,
				},
				Sensitive: tpm2.NewTPMUSensitiveComposite(
					tpm2.TPMAlgSymCipher,
					&tpm2.TPM2BSymKey{Buffer: aKey},
				),
			})

			l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

			importResponse, err := tpm2.Import{
				ParentHandle: tpm2.AuthHandle{
					Handle: primaryKey.ObjectHandle,
					Name:   primaryKey.Name,
					Auth:   tpm2.PasswordAuth(nil),
				},
				ObjectPublic: tpm2.New2B(aesTemplate),
				Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
			}.Execute(rwr)
			require.NoError(t, err)

			/// *********************************************************************

			a := &keyfile.TPMKey{
				Keytype: keyfile.OIDLoadableKey,
				Parent:  tpm2.TPMRHFWOwner,
				Pubkey:  tpm2.New2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](aesTemplate),
				Privkey: importResponse.OutPrivate,
			}

			/// hMAC

			svh := make([]byte, 32)
			io.ReadFull(rand.Reader, svh)
			privHashH := crypto.SHA256.New()
			privHashH.Write(svh)
			privHashH.Write(hKey)

			hmackeyTemplate := tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgKeyedHash,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:            false,
					FixedParent:         false,
					SensitiveDataOrigin: false,
					UserWithAuth:        true,
					SignEncrypt:         true,
				},
				AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy.Buffer},
				Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
					&tpm2.TPMSKeyedHashParms{
						Scheme: tpm2.TPMTKeyedHashScheme{
							Scheme: tpm2.TPMAlgHMAC,
							Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
								&tpm2.TPMSSchemeHMAC{
									HashAlg: tpm2.TPMAlgSHA256,
								}),
						},
					}),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgKeyedHash,
					&tpm2.TPM2BDigest{
						Buffer: privHashH.Sum(nil),
					},
				),
			}

			sens2BH := tpm2.Marshal(tpm2.TPMTSensitive{
				SensitiveType: tpm2.TPMAlgKeyedHash,
				AuthValue: tpm2.TPM2BAuth{
					Buffer: nil,
				},
				SeedValue: tpm2.TPM2BDigest{
					Buffer: svh,
				},
				Sensitive: tpm2.NewTPMUSensitiveComposite(
					tpm2.TPMAlgKeyedHash,
					&tpm2.TPM2BSensitiveData{Buffer: hKey},
				),
			})

			lh := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2BH})

			importResponseH, err := tpm2.Import{
				ParentHandle: tpm2.AuthHandle{
					Handle: primaryKey.ObjectHandle,
					Name:   primaryKey.Name,
					Auth:   tpm2.PasswordAuth(nil),
				},
				ObjectPublic: tpm2.New2B(hmackeyTemplate),
				Duplicate:    tpm2.TPM2BPrivate{Buffer: lh},
			}.Execute(rwr)
			require.NoError(t, err)

			/// *********************************************************************

			h := &keyfile.TPMKey{
				Keytype: keyfile.OIDLoadableKey,
				Parent:  tpm2.TPMRHFWOwner,
				Pubkey:  tpm2.New2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](hmackeyTemplate),
				Privkey: importResponseH.OutPrivate,
			}

			// now close it all
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, err = flushContextCmd.Execute(rwr)
			require.NoError(t, err)

			err = trialSessionCloser()
			require.NoError(t, err)
			rwc.Close()

			// now start the actual tests

			policySessionEncrypt, err := NewPCRAndAuthValueSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash}, []byte(nil))
			require.NoError(t, err)

			aeadE, err := NewAESCTRHMAC(swTPMPath, []byte(nil), a, h, policySessionEncrypt)
			require.NoError(t, err)

			// Encrypt
			ciphertext := aeadE.Seal(nil, nvB, plaintextB, aadB)

			// KEY: e787fdeca1095f2f2760a1c5e0f302e07d6b08de39ce31fe6a0db2f76e4626eb0968768ae04d37082c114573c307699707630b8c7ceef60abe3b7831d2adcd6e
			// NONCE: 9dc9bcfe8b4e2ea059e349bb
			// IN: 3ad57105144e544f95b82d485f80bb
			// AD: 96bce5dcaf4a90f6638a7e30cfd840a1e8dbc60cb70ab9592803f8799f909cafe71a83c2d884e1e289cc61e7
			// CT: e504109cdbf57b0e8a87080379e00d
			// TAG: 1798a64b5261761ecd88f36eaf7f86ed3db62100aed20dc6e337bc93c459487e
			t.Logf("CipherText: %s\n", hex.EncodeToString(ciphertext))

			var buf bytes.Buffer
			buf.Write(nvB)
			buf.Write(ciphterTextB)
			buf.Write(tagB)
			require.Equal(t, hex.EncodeToString(buf.Bytes()), hex.EncodeToString(ciphertext))

			// Decrypt
			policySessionDecrypt, err := NewPCRAndAuthValueSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash}, []byte(nil))
			require.NoError(t, err)

			aeadD, err := NewAESCTRHMAC(swTPMPath, []byte(nil), a, h, policySessionDecrypt)
			require.NoError(t, err)

			nonceSize := aeadD.NonceSize()
			retrievedNonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

			decrypted, err := aeadD.Open(nil, retrievedNonce, actualCiphertext, aadB)
			require.NoError(t, err)
			require.Equal(t, tc.dataToEncrypt, hex.EncodeToString(decrypted))

		})
	}
}

func TestAAD(t *testing.T) {

	tests := []struct {
		name          string
		dataToEncrypt string
		aadSeal       string
		aadOpen       string
	}{
		{"aad_match", "foo", "myaad", "myaad"},
		{"aad_mismatch", "foo", "myaad", "badaad"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, pcrList, pcrHash, err := GetPCRMap(tpm2.TPMAlgSHA256, "")

			require.NoError(t, err)

			sel := tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
					},
				},
			}

			trialSession, err := NewPCRAndAuthValueSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash}, nil)
			require.NoError(t, err)

			kfs, err := NewKey(swTPMPath, []byte(nil), []byte(nil), trialSession)
			require.NoError(t, err)

			/// *********************************************************************

			a, err := keyfile.Decode([]byte(kfs.AESKey))
			require.NoError(t, err)

			h, err := keyfile.Decode([]byte(kfs.HMACKey))
			require.NoError(t, err)

			policySessionEncrypt, err := NewPCRAndAuthValueSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash}, []byte(nil))
			require.NoError(t, err)

			aeadE, err := NewAESCTRHMAC(swTPMPath, []byte(nil), a, h, policySessionEncrypt)
			require.NoError(t, err)

			nonce := make([]byte, aeadE.NonceSize())
			_, err = rand.Read(nonce)
			require.NoError(t, err)

			plaintext := []byte(tc.dataToEncrypt)
			associatedData := []byte(tc.aadSeal)

			// Encrypt
			ciphertext := aeadE.Seal(nil, nonce, plaintext, associatedData)

			// Decrypt
			policySessionDecrypt, err := NewPCRAndAuthValueSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash}, []byte(nil))
			require.NoError(t, err)

			aeadD, err := NewAESCTRHMAC(swTPMPath, []byte(nil), a, h, policySessionDecrypt)
			require.NoError(t, err)

			nonceSize := aeadD.NonceSize()
			retrievedNonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

			// // Decrypt
			decrypted, err := aeadD.Open(nil, retrievedNonce, actualCiphertext, []byte(tc.aadOpen))
			if tc.aadSeal == tc.aadOpen {
				require.NoError(t, err)
				require.Equal(t, tc.dataToEncrypt, string(decrypted))
			} else {
				require.Error(t, err)
			}

		})
	}
}
