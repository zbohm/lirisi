// This is a simple console application as an example how to use library.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/zbohm/lirisi/client"
	"github.com/zbohm/lirisi/ring"
)

func printHelp() {
	fmt.Println(`Lirisi is a command line tool for creating a "Linkable ring signature".
Version: 0.0.0 (pre-release)

Commands:

  fold-pub    - Fold public keys into one file.
  sign        - Sign a message or file.
  verify      - Verify signature.
  key-image   - Output the linkable value to specify a new signer.
  pub-dgst    - Output the digest of folded public keys.
  pub-xy      - Outputs X,Y coordinates of public key (binary).
  restore-pub - Decompose public keys from folded file into separate files.
  list-curves - List of available curve types.
  list-hashes - List of available hash functions.
  help        - This help or help for a specific command.

Type "lirisi help COMMAND" for a specific command help. E.g. "lirisi help fold-pub".

For more see https://github.com/zbohm/lirisi.`)
}

func printHelpCommand(commandName string) {
	switch commandName {
	case "fold-pub":
		fmt.Println(`Command "fold-pub" folds public keys into one file.

Parameters:

  hash    - Name of hash function. Default is "sha3-256".
  inpath  - Folder with public keys. Only these keys must be in the folder. Nothing else.
  out     - The name of the output file.
  outform - Format of output. Can be "PEM" or "DER". Default is "PEM".
  order   - Order of public keys. It can be by hashes or alphabetical. Default is "hashes". See README for more.

Examples:

  # If you have public keys stored in the "public-keys" folder:
  lirisi fold-pub -inpath public-keys -out folded-public-keys.pem`)

	case "sign":
		fmt.Println(`Command "sign" makes ring signature for a message or file.

Parameters:

  message - A text message or the name of the file to be signed.
  case    - Case identifier. Optional. See README for more.
  inpub   - Filename of folded public keys. The file, that was created by the command "fold-pub".
  inkey   - Filename with your private key.
  out     - The name of the signature file.
  outform - Format of output. Can be "PEM" or "DER". Default is "PEM".

Examples:

  lirisi sign -message 'Hello, world!' -inpub folded-public-keys.pem -inkey my-private-key.pem -out signature.pem
  lirisi sign -message my-document.pdf -inpub folded-public-keys.pem -inkey my-private-key.pem -out signature.pem`)

	case "verify":
		fmt.Println(`Command "verify" verifies ring signature for the given message or file.

Parameters:

  in      - The name of the signature file.
  message - A text message or the name of the file to be verified.
  case    - Case identifier. Optional. See README for more.
  inpub   - Filename of folded public keys. The file, that was created by the command "fold-pub".

Examples:

  lirisi verify -message 'Hello, world!' -inpub folded-public-keys.pem -in signature.pem
  lirisi verify -message my-document.pdf -inpub folded-public-keys.pem -in signature.pem`)

	case "key-image":
		fmt.Println(`Command "key-image" outputs the linkable value to specify a new signer.

Parameters:
  in  - The name of the signature file.
  c   - Add a ":" delimiter to the value for better readability.
  out - Filename of the output file. Optional. If not specified, the value is written to standard output.

Examples:

  lirisi key-image -in signature.pem
  lirisi key-image -c -in signature.pem`)

	case "pub-dgst":
		fmt.Println(`Command "pub-dgst" outputs the digest of folded public keys.

Parameters:
  in  - The name of the file with folded public keys.
  c   - Add a ":" delimiter to the value for better readability.
  out - Filename of the output file. Optional. If not specified, the value is written to standard output.

Examples:

  lirisi pub-dgst -in folded-public-keys.pem
  lirisi pub-dgst -c -in folded-public-keys.pem`)

	case "pub-xy":
		fmt.Println(`Command "pub-xy" outputs X,Y coordinates of public key (binary).

Parameters:
  in  - The name of the file with folded public keys.
  out - Filename of the output file. Optional. If not specified, the value is written to standard output.

Examples:

lirisi pub-xy -in public-key.pem | hexdump -C

Compare with: openssl ec -text -noout -in private-key.pem`)

	case "restore-pub":
		fmt.Println(`Command "restore-pub" decomposes public keys from folded file into separate files.

Parameters:
  in  - The name of the file with folded public keys.
  outpath - The name of the folder in which the public keys will be stored.
  outform - Format of output. Can be "PEM" or "DER". Default is "PEM".

Examples:

  lirisi restore-pub -in folded-public-keys.pem -outpath /tmp/
  lirisi restore-pub -in folded-public-keys.pem`)

	default:
		fmt.Println("A command with this name was not found.")
		fmt.Println("Run the command without parameters to display main help.")
	}
}

func helpNote() {
	fmt.Println(`
Caution! For curve secp256k1 can be used only sha3-224 and sha3-256.
See README for examples.`)
}

func helpListCurves() {
	curveCodes := make([]string, 0, len(ring.CurveCodes))
	for k := range ring.CurveCodes {
		curveCodes = append(curveCodes, k)
	}
	sort.Strings(curveCodes)
	fmt.Println("Available curve types:")
	fmt.Println()
	for _, code := range curveCodes {
		fmt.Printf("  %s\n", code)
	}
	helpNote()
}

func helpListHashes() {
	hashCodes := make([]string, 0, len(ring.HashCodes))
	for k := range ring.HashCodes {
		hashCodes = append(hashCodes, k)
	}
	sort.Strings(hashCodes)
	fmt.Println("Available hash functions:")
	fmt.Println()
	for _, code := range hashCodes {
		fmt.Printf("  %s\n", code)
	}
	helpNote()
}

func commandMakeSignature(
	signCmd *flag.FlagSet,
	signFoldedPubs, signPrivate, signMessage, signCase, signFormat, signOutput *string,
) {
	if err := signCmd.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
	foldedPublicKeys, err := ioutil.ReadFile(*signFoldedPubs)
	if err != nil {
		log.Fatal(err)
	}
	privateKey, err := ioutil.ReadFile(*signPrivate)
	if err != nil {
		log.Fatal(err)
	}
	message := client.ReadMessage(*signMessage)
	status, signature := client.CreateSignature(foldedPublicKeys, privateKey, message, []byte(*signCase), *signFormat)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	client.WriteOutput(*signOutput, signature)
}

func commandVerifySignature(verifyCmd *flag.FlagSet, verifyFoldedPubs, verifySignature, verifyMessage, verifyCase *string) {
	if err := verifyCmd.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
	foldedPublicKeys, err := ioutil.ReadFile(*verifyFoldedPubs)
	if err != nil {
		log.Fatal(err)
	}
	signature := client.ReadFromFileOrStdin(*verifySignature)
	message := client.ReadMessage(*verifyMessage)
	status := client.VerifySignature(foldedPublicKeys, signature, message, []byte(*verifyCase))
	if status == ring.Success {
		fmt.Println("Verified OK")
		os.Exit(0)
	} else {
		fmt.Println("Verification Failure")
		os.Exit(1)
	}
}

func commandRestorePublicKeys(seqPubCmd *flag.FlagSet, seqPubDir, seqPubFile, seqPubFormat *string) {
	if err := seqPubCmd.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
	if *seqPubDir == "" {
		log.Fatal("Parameter -in missing.")
	}
	foldedPublicKeys, err := ioutil.ReadFile(*seqPubFile)
	if err != nil {
		log.Fatal(err)
	}
	status, unfoldedPublicKeys := client.UnfoldPublicKeysIntoBytes(foldedPublicKeys, *seqPubFormat)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	var ext string
	if *seqPubFormat == "PEM" {
		ext = "pem"
	} else {
		ext = "der"
	}
	numOfPoints := len(unfoldedPublicKeys)
	digits := strconv.Itoa(numOfPoints)
	pattern := fmt.Sprintf("public-key-%%0%dd.", len(digits)) + ext
	for i, key := range unfoldedPublicKeys {
		path := filepath.Join(*seqPubDir, fmt.Sprintf(pattern, i+1))
		client.WriteOutput(path, key)
	}
	fmt.Printf("%d public keys saved into %s.\n", numOfPoints, *seqPubDir)
}

func commandKeyImage(keyImageCmd *flag.FlagSet, keyImageSignature, keyImageOutput *string, keyImageSeparator *bool) {
	if err := keyImageCmd.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
	status, keyImage := client.SignatureKeyImage(client.ReadFromFileOrStdin(*keyImageSignature), *keyImageSeparator)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	client.WriteOutput(*keyImageOutput, keyImage)
}

func commandFoldPublicKeys(pubSeqCmd *flag.FlagSet, pubSeqPubDir, pubSeqHash, pubSeqFormat, pubSeqOrder, pubSeqOutput *string) {
	if err := pubSeqCmd.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
	contents := client.LoadFolder(*pubSeqPubDir)
	status, foldedPublicKeys := client.FoldPublicKeys(contents, *pubSeqHash, *pubSeqFormat, *pubSeqOrder)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	client.WriteOutput(*pubSeqOutput, foldedPublicKeys)
}

func commandPublicKeysDigest(pubDgstCmd *flag.FlagSet, pubDgstFile, pubDgstOutput *string, pubDgstSeparator *bool) {
	if err := pubDgstCmd.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
	status, digest := client.PublicKeysDigest(client.ReadFromFileOrStdin(*pubDgstFile), *pubDgstSeparator)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	client.WriteOutput(*pubDgstOutput, digest)
}

func commandPublicKeyCoordinates(pubCoordinatesCmd *flag.FlagSet, pubCoordinatesFile, pubDgstOutput *string) {
	if err := pubCoordinatesCmd.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
	status, coordinates := client.PublicKeyXYCoordinates(client.ReadFromFileOrStdin(*pubCoordinatesFile))
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	client.WriteOutput(*pubDgstOutput, coordinates)
}

func commandHelp() {
	if len(os.Args) < 3 {
		fmt.Println("Enter a command name to display the command help.")
	} else {
		printHelpCommand(os.Args[2])
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
	signMessage := signCmd.String("message", "", "A text message or the name of the file to be signed.")
	signCase := signCmd.String("case", "", "Case identifier.")
	signFoldedPubs := signCmd.String("inpub", "", "Public keys folded into the file.")
	signPrivate := signCmd.String("inkey", "", "Filename to the private key.")
	signOutput := signCmd.String("out", "", "Output to the file.")
	signFormat := signCmd.String("outform", "PEM", "Format of output. Can be PEM, DER. Default is PEM.")

	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	verifySignature := verifyCmd.String("in", "", "Signature filename.")
	verifyMessage := verifyCmd.String("message", "", "A text message or the name of the file to be verified.")
	verifyCase := verifyCmd.String("case", "", "Case identifier.")
	verifyFoldedPubs := verifyCmd.String("inpub", "", "Public keys folded into the file.")

	keyImageCmd := flag.NewFlagSet("key-image", flag.ExitOnError)
	keyImageSignature := keyImageCmd.String("in", "", "Signature filename.")
	keyImageSeparator := keyImageCmd.Bool("c", false, "Print the digest with separating colons.")
	keyImageOutput := keyImageCmd.String("out", "", "Output to the file.")

	pubSeqCmd := flag.NewFlagSet("fold-pub", flag.ExitOnError)
	pubSeqHash := pubSeqCmd.String("hash", "sha3-256", "Hash type.")
	pubSeqPubDir := pubSeqCmd.String("inpath", "", "Folder with public keys.")
	pubSeqOutput := pubSeqCmd.String("out", "", "Output to the file.")
	pubSeqFormat := pubSeqCmd.String("outform", "PEM", "Format of output. Can be PEM, DER. Default is PEM.")
	pubSeqOrder := pubSeqCmd.String("order", "hashes", "Public keys order. It can be hashes or alphabetical. Default is hashes.")

	seqPubCmd := flag.NewFlagSet("restore-pub", flag.ExitOnError)
	seqPubFile := seqPubCmd.String("in", "", "Public keys sequence filename.")
	seqPubDir := seqPubCmd.String("outpath", "", "Path to save public keys.")
	seqPubFormat := seqPubCmd.String("outform", "PEM", "Format of output. Can be PEM, DER. Default is PEM.")

	pubDgstCmd := flag.NewFlagSet("pub-dgst", flag.ExitOnError)
	pubDgstFile := pubDgstCmd.String("in", "", "Public keys sequence filename.")
	pubDgstSeparator := pubDgstCmd.Bool("c", false, "Print the digest with separating colons.")
	pubDgstOutput := pubDgstCmd.String("out", "", "Output to the file.")

	pubCoordinatesCmd := flag.NewFlagSet("pub-xy", flag.ExitOnError)
	pubCoordinatesFile := pubCoordinatesCmd.String("in", "", "Public key filename.")

	flag.Parse()

	if len(os.Args) < 2 {
		printHelp()
	} else {
		switch os.Args[1] {
		case "help":
			commandHelp()

		case "list-curves":
			helpListCurves()

		case "list-hashes":
			helpListHashes()

		case "sign":
			commandMakeSignature(signCmd, signFoldedPubs, signPrivate, signMessage, signCase, signFormat, signOutput)

		case "verify":
			commandVerifySignature(verifyCmd, verifyFoldedPubs, verifySignature, verifyMessage, verifyCase)

		case "key-image":
			commandKeyImage(keyImageCmd, keyImageSignature, keyImageOutput, keyImageSeparator)

		case "fold-pub":
			commandFoldPublicKeys(pubSeqCmd, pubSeqPubDir, pubSeqHash, pubSeqFormat, pubSeqOrder, pubSeqOutput)

		case "pub-dgst":
			commandPublicKeysDigest(pubDgstCmd, pubDgstFile, pubDgstOutput, pubDgstSeparator)

		case "pub-xy":
			commandPublicKeyCoordinates(pubCoordinatesCmd, pubCoordinatesFile, pubDgstOutput)

		case "restore-pub":
			commandRestorePublicKeys(seqPubCmd, seqPubDir, seqPubFile, seqPubFormat)

		default:
			printHelp()
		}
	}
}
