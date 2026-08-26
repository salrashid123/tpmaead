package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/salrashid123/tpmaead"
)

var (
	tpmPath     = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	keyfilepath = flag.String("keyfilepath", "/tmp/key.json", "Path to save keyfiles")
	parentPass  = flag.String("parentPass", "", "Passphrase for the owner handle (will use TPM_PARENT_AUTH env var)")
	keyPass     = flag.String("keyPass", "foo", "Passphrase for the key handle (will use TPM_KEY_AUTH env var)")
	pcrs        = flag.String("pcrs", "23:0000000000000000000000000000000000000000000000000000000000000000", "PCR Bound value (increasing order, comma separated)")
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

	trialSession, err := tpmaead.NewPCRAndAuthValueSession(sel, tpm2.TPM2BDigest{Buffer: pcrHash}, nil)
	if err != nil {
		fmt.Printf("go-kms-wrapping:  Could not get PCRMap: %s", err)
		return
	}

	kfs, err := tpmaead.NewKey(*tpmPath, []byte(*keyPass), []byte(*parentPass), trialSession)
	if err != nil {
		fmt.Printf("go-kms-wrapping:  Could not get PCRMap: %s", err)
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

	err = os.WriteFile(*keyfilepath, wrappedSecretjson, 0644)
	if err != nil {
		fmt.Printf("go-kms-wrapping: JSON indenting failed: %s", err)
		return
	}

}
