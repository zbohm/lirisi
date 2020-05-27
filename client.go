// This is a simple console application as an example how to use library.
package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"

	"github.com/zbohm/lirisi/client"
)

func main() {
	output := flag.String("output", "", "Output to filename.")
	private := flag.String("private", "", "Private key filename.")
	size := flag.String("size", "", "Create a ring of $size public keys. Use for testing.")
	ring := flag.String("ring", "", "List of public keys.")
	message := flag.String("message", "", "Text for signing.")
	signature := flag.String("signature", "", "Signature in format PEM.")

	flag.Parse()

	var command string
	numOfParams := len(flag.Args())
	if numOfParams > 0 {
		command = flag.Arg(numOfParams - 1)
	}

	if command == "create-private-key" {
		client.CreatePrivateKey(*output)
		return
	}

	if command == "extract-public-key" {
		if *private == "" {
			log.Fatal("Parameter --private missing.")
		}
		client.ExtractPublicKey(*output, *private)
		return
	}

	if command == "create-testing-ring" {
		if *size == "" {
			log.Fatal("Parameter --size missing.")
		}
		numOfKeys, err := strconv.ParseInt(*size, 10, 64)
		if err != nil {
			log.Fatal(err)
		}
		if numOfKeys < 1 {
			log.Fatal("Ring size must be greater than 0.")
		}
		client.CreateTestingRing(*output, int(numOfKeys))
		return
	}

	if command == "sign" {
		if *message == "" {
			log.Fatal("Parameter --message missing.")
		}
		if *ring == "" {
			log.Fatal("Parameter --ring missing.")
		}
		if *private == "" {
			log.Fatal("Parameter --private missing.")
		}
		client.CreateSignature(*output, *message, *ring, *private)
		return
	}

	if command == "verify" {
		if *message == "" {
			log.Fatal("Parameter --message missing.")
		}
		if *ring == "" {
			log.Fatal("Parameter --ring missing.")
		}
		if *signature == "" {
			log.Fatal("Parameter --signature missing.")
		}
		client.VerifySignature(*output, *message, *ring, *signature)
		return
	}

	if command == "get-key-image" {
		if *signature == "" {
			log.Fatal("Parameter --signature missing.")
		}
		client.GetKeyImage(*output, *signature)
		return
	}

	usage := `Usage:
  lirisi [params] COMMAND

Commands:
  create-private-key
  extract-public-key
  create-testing-ring
  sign
  verify
  get-key-image

Examples:
  lirisi create-private-key > private-key.hex
  lirisi --output=private-key.hex create-private-key

  lirisi --private=private-key.hex extract-public-key > public.b64
  lirisi --private=private-key.hex --output=public.b64 extract-public-key

  lirisi --size=9 create-testing-ring > ring.lst
  lirisi --size=9 --output=ring.lst create-testing-ring

  // Append my public key to other keys:
  cat public.b64 >> ring.lst

  lirisi --message='Hello world!' --ring=ring.lst --private=private-key.hex sign > signature.pem
  lirisi --message='Hello world!' --ring=ring.lst --private=private-key.hex --output=signature.pem sign

  lirisi --message='Hello world!' --ring=ring.lst --signature=signature.pem verify
  lirisi --message='Hello world!' --ring=ring.lst --signature=signature.pem --output=result.txt verify

  lirisi --signature=signature.pem get-key-image > private-key-id.b64
  lirisi --signature=signature.pem --output=private-key-id.b64 get-key-image
`
	fmt.Println(usage)
}
