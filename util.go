package tpmaead

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

type AESCTRHMACKeyFile struct {
	AESKey  string `json:"aesKey"`
	HMACKey string `json:"hmacKey"`
}

const (
	// todo: derive the max digest buffer by looking up the TPM's capability
	// TPM's have a min buffer of 1024
	// section 10.3.8:  https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf
	maxDigestBuffer = 1024
	maxInputBuffer  = 1024
)

func openTPM(path string) (io.ReadWriteCloser, error) {
	// first check if we're dealing with a device.  If not, try a socket
	_, err := os.Stat(path)
	if err == nil {
		return tpmutil.OpenTPM(path)
	}
	return net.Dial("tcp", path)
}

// symmetric encryption and decryption routine
func encryptDecryptSymmetric(rwr transport.TPM, keyAuth tpm2.AuthHandle, iv, data []byte, decrypt bool) ([]byte, error) {
	var out, block []byte

	for rest := data; len(rest) > 0; {
		if len(rest) > maxDigestBuffer {
			block, rest = rest[:maxDigestBuffer], rest[maxDigestBuffer:]
		} else {
			block, rest = rest, nil
		}
		r, err := tpm2.EncryptDecrypt2{
			KeyHandle: keyAuth,
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    tpm2.TPMAlgCTR,
			Decrypt: decrypt,
			IV: tpm2.TPM2BIV{
				Buffer: iv,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		block = r.OutData.Buffer
		iv = r.IV.Buffer
		out = append(out, block...)
	}
	return out, nil
}

// parses the pcr [index:sha256_hex_value] string array for the PCRs to bind to.
// each pcr bank must comma separated and formatted as int(index):hex(sha256_pcr_value)
//
//	so to bind to pcrs 15, 23 for the following:
//
// $ tpm2_pcrread sha256:15,23
// sha256:
//
//	15: 0x0000000000000000000000000000000000000000000000000000000000000000
//	23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
//
// the expectedPCRMap would be
// 15:0000000000000000000000000000000000000000000000000000000000000000,23:F5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
//
// the return value is
//  1. map of pcr_bank and its value (map[uint][]byte)
//  2. list of the pcr_banks alone ([]uint)
//  3. the hash of the pcrs taken together in order ([]byte);  This value is used when defining a PolicyPCR
//     https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
func GetPCRMap(algo tpm2.TPMAlgID, expectedPCRMap string) (map[uint][]byte, []uint, []byte, error) {

	pcrMap := make(map[uint][]byte)

	if expectedPCRMap == "" {
		return pcrMap, nil, nil, nil
	}
	var hsh hash.Hash
	switch algo {
	case tpm2.TPMAlgSHA1:
		hsh = sha1.New()
	case tpm2.TPMAlgSHA256:
		hsh = sha256.New()
	case tpm2.TPMAlgSHA384:
		hsh = sha256.New()
	default:
		return nil, nil, nil, fmt.Errorf("unsupported Hash Algorithm for TPM PCRs %v", algo)
	}

	if algo == tpm2.TPMAlgSHA1 || algo == tpm2.TPMAlgSHA256 || algo == tpm2.TPMAlgSHA384 {
		for _, v := range strings.Split(expectedPCRMap, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					return nil, nil, nil, fmt.Errorf(" PCR key:value is invalid in parsing %s", v)
				}
				hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
				if err != nil {
					return nil, nil, nil, fmt.Errorf(" PCR key:value is invalid in encoding %s", v)
				}
				pcrMap[uint(uv)] = hexEncodedPCR
				hsh.Write(hexEncodedPCR)
			} else {
				return nil, nil, nil, fmt.Errorf(" PCR key:value is invalid %s", v)
			}
		}
	} else {
		return nil, nil, nil, fmt.Errorf("unknown Hash Algorithm for TPM PCRs %v", algo)
	}

	pcrs := make([]uint, 0, len(pcrMap))
	for k := range pcrMap {
		pcrs = append(pcrs, k)
	}

	return pcrMap, pcrs, hsh.Sum(nil), nil
}

// performs hmac operations
func tpmhmac(rwr transport.TPM, data []byte, objNamedHandle tpm2.NamedHandle, objAuth tpm2.TPM2BAuth, sess tpm2.Session) ([]byte, error) {

	rspHS, err := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: objNamedHandle.Handle,
			Name:   objNamedHandle.Name,
			Auth:   sess,
		},
		Auth:    objAuth,
		HashAlg: tpm2.TPMAlgNull,
	}.Execute(rwr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing HMAC sequenceStart  %v\n", err)
		return nil, err
	}

	authHandle := tpm2.AuthHandle{
		Name:   objNamedHandle.Name,
		Handle: rspHS.SequenceHandle,
		Auth:   tpm2.PasswordAuth(objAuth.Buffer),
	}
	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error executing HMAC sequenceUpdate  %v\n", err)
			return nil, err
		}
		data = data[maxInputBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHOwner,
	}

	rspSC, err := sequenceComplete.Execute(rwr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing HMAC sequenceComplete  %v\n", err)
		return nil, err
	}
	return rspSC.Result.Buffer, nil
}

// Helper to grow slices efficiently mirroring standard library behavior
func extendSlice(dst []byte, n int) ([]byte, []byte) {
	outIdx := len(dst)
	if cap(dst)-len(dst) >= n {
		dst = dst[:len(dst)+n]
	} else {
		newDst := make([]byte, len(dst)+n)
		copy(newDst, dst)
		dst = newDst
	}
	return dst, dst[outIdx:]
}
