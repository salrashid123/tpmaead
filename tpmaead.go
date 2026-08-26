package tpmaead

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	nonceSize = 12 // Standard 96-bit nonce for CTR
	tagSize   = 32 // SHA-256 tag size
)

// CipherEtM implements the cipher.AEAD interface using AES-CTR and HMAC-SHA256
type TPMAEAD struct {
	tpmPath    string
	keyPass    []byte
	parentPass []byte
	aesKey     keyfile.TPMKey
	hmacKey    keyfile.TPMKey
	session    Session
}

// Generates a new AES+HMAC set of keys where
// tpmPath: the string path to the tpm device
// keypass:  the authPassword for both keys
// parentpass:  the password for the parent key (this is rare to specify)
// session:  tpmaead.Session implementation which describes any TPM policies to apply to the keys
// returns  a struct where both the AES and HMAC keys in keyfile format which can be exported as PEM
func NewKey(tpmPath string, keyPass []byte, parentPass []byte, session Session) (kf AESCTRHMACKeyFile, err error) {
	// open the tpm
	rwc, err := openTPM(tpmPath)
	if err != nil {
		return AESCTRHMACKeyFile{}, fmt.Errorf("tpmaead: can't open TPM %v", err)
	}
	defer rwc.Close()

	rwr := transport.FromReadWriter(rwc)

	// create a trial session to create the keys
	trialSession, trialSessionCloser, err := session.GetSession(rwr, true)
	if err != nil {
		return AESCTRHMACKeyFile{}, fmt.Errorf("tpmaead: can't get trial session %v", err)
	}
	defer trialSessionCloser()

	// get the session's digest for the policy
	dgst, err := tpm2.PolicyGetDigest{
		PolicySession: trialSession.Handle(),
	}.Execute(rwr)
	if err != nil {
		return AESCTRHMACKeyFile{}, err
	}
	authPolicy := dgst.PolicyDigest

	// create the H2 primary key
	// https://github.com/salrashid123/tpm2/tree/master/h2_primary_template
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth([]byte(parentPass)),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return AESCTRHMACKeyFile{}, fmt.Errorf("tpmaead:  can't create primary %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	// now create the AES256 CTR key
	aCreate, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgSymCipher,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				UserWithAuth:        false,
				SensitiveDataOrigin: true,
				Decrypt:             true,
				SignEncrypt:         true,
			},
			AuthPolicy: authPolicy,
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
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(keyPass), // set the userAuth password for the AES Key
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		return AESCTRHMACKeyFile{}, fmt.Errorf("tpmaead:  error creating key object  %v", err)
	}

	// aesPrivate := aCreate.OutPrivate
	// aesPublic := aCreate.OutPublic
	// ak, err := tpm2.Load{
	// 	ParentHandle: tpm2.NamedHandle{
	// 		Handle: cPrimary.ObjectHandle,
	// 		Name:   cPrimary.Name,
	// 	},
	// 	InPrivate: aesPrivate,
	// 	InPublic:  aesPublic,
	// }.Execute(rwr)
	// if err != nil {
	// 	return AESCTRHMACKeyFile{}, fmt.Errorf("tpmaead:  can't load object  %v", err)
	// }
	// defer func() {
	// 	flushContextCmd := tpm2.FlushContext{
	// 		FlushHandle: ak.ObjectHandle,
	// 	}
	// 	_, err = flushContextCmd.Execute(rwr)
	// }()

	// set the keyfile.TPMKey format
	aeskf := keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		aCreate.OutPublic,
		aCreate.OutPrivate,
		keyfile.WithParent(tpm2.TPMRHOwner),
		keyfile.WithUserAuth(keyPass),
	)

	// now crate the HMAC key
	hCreate, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				UserWithAuth:        false,
				SensitiveDataOrigin: true,
				SignEncrypt:         true,
			},
			AuthPolicy: authPolicy,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgHMAC,
						Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
							&tpm2.TPMSSchemeHMAC{
								HashAlg: tpm2.TPMAlgSHA256,
							}),
					},
				},
			),
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(keyPass), // set the userAuth password for the AES Key
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		return AESCTRHMACKeyFile{}, fmt.Errorf("tpmaead:  error creating key object  %v", err)
	}

	// hPrivate := hCreate.OutPrivate
	// hPublic := hCreate.OutPublic

	// hk, err := tpm2.Load{
	// 	ParentHandle: tpm2.NamedHandle{
	// 		Handle: cPrimary.ObjectHandle,
	// 		Name:   cPrimary.Name,
	// 	},
	// 	InPrivate: hPrivate,
	// 	InPublic:  hPublic,
	// }.Execute(rwr)
	// if err != nil {
	// 	return AESCTRHMACKeyFile{}, fmt.Errorf("tpmaead:  can't load object  %v", err)
	// }
	// defer func() {
	// 	flushContextCmd := tpm2.FlushContext{
	// 		FlushHandle: hk.ObjectHandle,
	// 	}
	// 	_, err = flushContextCmd.Execute(rwr)
	// }()

	/// set the TPMKey format
	hmackf := keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		hCreate.OutPublic,
		hCreate.OutPrivate,
		keyfile.WithParent(tpm2.TPMRHOwner),
		keyfile.WithUserAuth(keyPass),
	)

	// create a struct and specify the PEM format for each key
	kfs := AESCTRHMACKeyFile{
		AESKey:  string(aeskf.Bytes()),
		HMACKey: string(hmackf.Bytes()),
	}
	return kfs, nil
}

// NewAESCTRHMAC returns a new AEAD instance.
// Expects the keyfile.TPMKey format of the AES and HMAC key
//
//	the sesion object specifies any TPM polcies applied during key genration which must get fulfilled when using the key for any operation
func NewAESCTRHMAC(tpmPath string, parentPass []byte, aesKey *keyfile.TPMKey, hmacKey *keyfile.TPMKey, session Session) (cipher.AEAD, error) {
	rwc, err := openTPM(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("tpmaead: can't open TPM %v", err)
	}
	defer rwc.Close()

	if aesKey == nil || hmacKey == nil {
		return nil, errors.New("combined key must be exactly 64 bytes long")
	}
	return &TPMAEAD{
		tpmPath:    tpmPath,
		parentPass: parentPass,
		aesKey:     *aesKey,
		hmacKey:    *hmacKey,
		session:    session,
	}, nil
}

func (c *TPMAEAD) NonceSize() int {
	return nonceSize
}

func (c *TPMAEAD) Overhead() int {
	return tagSize
}

// Seal encrypts and authenticates plaintext.
func (c *TPMAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != nonceSize {
		panic("crypto/cipher: incorrect nonce length given to AES-CTR-HMAC")
	}
	rwc, err := openTPM(c.tpmPath)
	if err != nil {
		panic(fmt.Sprintf("tpmaead: can't open TPM %v", err))
	}
	defer rwc.Close()
	rwr := transport.FromReadWriter(rwc)

	// 1. Allocate response space: existing dst + ciphertext + tag
	ret, out := extendSlice(dst, len(plaintext)+tagSize)
	ciphertext := out[:len(plaintext)]
	tagDst := out[len(plaintext):]

	// Start AES Encrypt "plaintext" using "nonce"
	// create the h2 primary
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth(c.parentPass),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		panic(fmt.Sprintf("tpmaead: can't create primary %v", err))
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	// load the aes key
	aesKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: c.aesKey.Privkey,
		InPublic:  c.aesKey.Pubkey,
	}.Execute(rwr)
	if err != nil {
		panic(fmt.Sprintf("tpmaead: can't load aesKey object  %v", err))
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: aesKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	// setup a real session to encrypt
	policySessionEncrypt, policySessionEncryptCleanup, err := c.session.GetSession(rwr, false)
	if err != nil {
		panic(fmt.Sprintf("tpmaead: can't get policy session %v", err))
	}
	defer policySessionEncryptCleanup()

	// Create an IV by padding our 12-byte nonce with 4 zero bytes for the 16-byte AES block
	iv := make([]byte, 16)
	copy(iv, nonce)

	// now encrypt the data
	keyAuth := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   policySessionEncrypt,
	}
	rciphertext, err := encryptDecryptSymmetric(rwr, keyAuth, iv, plaintext, false)
	if err != nil {
		panic(fmt.Sprintf("tpmaead: encryptSymmetric %v", err))
	}

	// cleanup
	flushContextCmd := tpm2.FlushContext{
		FlushHandle: aesKey.ObjectHandle,
	}
	_, err = flushContextCmd.Execute(rwr)

	policySessionEncryptCleanup()
	copy(ciphertext, rciphertext)

	// now load the HMAC key
	hmacKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: c.hmacKey.Privkey,
		InPublic:  c.hmacKey.Pubkey,
	}.Execute(rwr)
	if err != nil {
		panic(fmt.Sprintf("tpmaead: can't load hmacKey object  %v", err))
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	// setup a real session to hmac
	policySessionHmac, policySessionHmacCleanup, err := c.session.GetSession(rwr, false)
	if err != nil {
		panic(fmt.Sprintf("tpmaead: can't get policy session %v", err))
	}
	defer policySessionHmacCleanup()

	// 3. Authenticate: MAC = HMAC(Nonce || AdditionalData || Ciphertext)

	buf := new(bytes.Buffer)
	var padding [sha256.BlockSize]byte
	binary.Write(buf, binary.LittleEndian, uint64(len(additionalData)))
	binary.Write(buf, binary.LittleEndian, uint64(len(ciphertext)))

	buf.Write(nonce)
	buf.Write(additionalData)

	buf.Write(padding[:(sha256.BlockSize-
		((8*2+len(nonce)+len(additionalData))%sha256.BlockSize))%
		sha256.BlockSize])

	buf.Write(ciphertext)

	// setup auth for the hmac sequence
	pss := make([]byte, 32)
	_, err = rand.Read(pss)
	if err != nil {
		panic(fmt.Sprintf("tpmaead: failed to generate random for hash %v", err))
	}

	// read the public part of the key
	pub, err := tpm2.ReadPublic{
		ObjectHandle: hmacKey.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		panic(fmt.Sprintf("tpmaead:  error getting public %v", err))
	}

	nh := tpm2.NamedHandle{
		Handle: hmacKey.ObjectHandle,
		Name:   pub.Name,
	}

	objAuth := &tpm2.TPM2BAuth{
		Buffer: pss,
	}

	// now do the hmac
	hm, err := tpmhmac(rwr, buf.Bytes(), nh, *objAuth, policySessionHmac)
	if err != nil {
		panic(fmt.Sprintf("tpmaead: can't hmac  %v", err))
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()
	// compute the tag and copy in mem
	computedTag := hm[:tagSize]
	copy(tagDst, computedTag)

	// return the ciphertext
	return append(nonce, ret...)
}

// Open decrypts and verifies ciphertext.
func (c *TPMAEAD) Open(dst, nonce, ciphertextWithTag, additionalData []byte) ([]byte, error) {
	if len(nonce) != nonceSize {
		return nil, errors.New("crypto/cipher: incorrect nonce length given to AES-CTR-HMAC")
	}
	if len(ciphertextWithTag) < tagSize {
		return nil, errors.New("crypto/cipher: ciphertext too short")
	}

	rwc, err := openTPM(c.tpmPath)
	if err != nil {
		return nil, fmt.Errorf("tpmaead: can't open TPM %v", err)
	}
	defer rwc.Close()
	rwr := transport.FromReadWriter(rwc)

	// create the h2 primary
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth(c.parentPass),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("tpmaead: can't create primary %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	// load the HMAC key
	hmacKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: c.hmacKey.Privkey,
		InPublic:  c.hmacKey.Pubkey,
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("tpmaead: can't load hmacKey object  %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	// Split ciphertext and authentication tag
	splitIdx := len(ciphertextWithTag) - tagSize
	ciphertext := ciphertextWithTag[:splitIdx]
	expectedTag := ciphertextWithTag[splitIdx:]

	// 1. Verify MAC first (Constant Time)
	// first crate the policy session to apply to this key
	policySessionHmac, policySessionHmacCleanup, err := c.session.GetSession(rwr, false)
	if err != nil {
		return nil, fmt.Errorf("tpmaead: can't get policy session %v", err)
	}
	defer policySessionHmacCleanup()

	// 3. Authenticate: MAC = HMAC(Nonce || AdditionalData || Ciphertext)
	buf := new(bytes.Buffer)
	var padding [sha256.BlockSize]byte
	binary.Write(buf, binary.LittleEndian, uint64(len(additionalData)))
	binary.Write(buf, binary.LittleEndian, uint64(len(ciphertext)))

	buf.Write(nonce)
	buf.Write(additionalData)

	buf.Write(padding[:(sha256.BlockSize-
		((8*2+len(nonce)+len(additionalData))%sha256.BlockSize))%
		sha256.BlockSize])

	buf.Write(ciphertext)

	// now prepare to do the hmac auth
	pss := make([]byte, 32)
	_, err = rand.Read(pss)
	if err != nil {
		return nil, fmt.Errorf("tpmaead: failed to generate random for hash %v", err)
	}

	// read the public key for auth
	pub, err := tpm2.ReadPublic{
		ObjectHandle: hmacKey.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("tpmaead: error getting public %v", err)
	}

	nh := tpm2.NamedHandle{
		Handle: hmacKey.ObjectHandle,
		Name:   pub.Name,
	}

	objAuth := &tpm2.TPM2BAuth{
		Buffer: pss,
	}

	// do the hmac
	hm, err := tpmhmac(rwr, buf.Bytes(), nh, *objAuth, policySessionHmac)
	if err != nil {
		return nil, fmt.Errorf("tpmaead: can't hmac  %v", err)
	}

	// cleanup
	policySessionHmacCleanup()
	flushContextCmd := tpm2.FlushContext{
		FlushHandle: hmacKey.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	// compute the tag, validate
	computedTag := hm[:tagSize]

	if subtle.ConstantTimeCompare(expectedTag, computedTag) != 1 {
		return nil, errors.New("crypto/cipher: message authentication failed")
	}

	// 2. Allocate output space for plaintext
	ret, plaintext := extendSlice(dst, len(ciphertext))

	// now for AES part
	iv := make([]byte, 16)
	copy(iv, nonce)

	// load the aes key
	aesKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: c.aesKey.Privkey,
		InPublic:  c.aesKey.Pubkey,
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("tpmaead: can't load aesKey object  %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: aesKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	// setup a real session to decrypt
	policySessionEncrypt, policySessionEncryptCleanup, err := c.session.GetSession(rwr, false)
	if err != nil {
		return nil, fmt.Errorf("tpmaead: can't get policy session %v", err)
	}
	defer policySessionEncryptCleanup()

	keyAuth := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   policySessionEncrypt,
	}

	// decrypt
	rplainText, err := encryptDecryptSymmetric(rwr, keyAuth, iv, ciphertext, true)
	if err != nil {
		return nil, fmt.Errorf("tpmaead:encryptSymmetric %v", err)
	}
	copy(plaintext, rplainText)

	return ret, nil
}
