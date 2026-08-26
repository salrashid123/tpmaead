package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/salrashid123/tpmaead"
)

var (
	tpmPath     = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	keyfilepath = flag.String("keyfilepath", "/tmp/key.json", "Path to save keyfiles")
	parentPass  = flag.String("parentPass", "", "Passphrase for the owner handle (will use TPM_PARENT_AUTH env var)")
)

func main() {
	flag.Parse()

	// ***************************

	trialSession, err := tpmaead.NewNoPolicySession()
	if err != nil {
		fmt.Printf("go-kms-wrapping:  Could not create NewNoPolicySession: %s", err)
		return
	}

	kfs, err := tpmaead.NewKey(*tpmPath, []byte(nil), []byte(*parentPass), trialSession)
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
