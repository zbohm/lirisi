// This is a simple console application as an example how to use library.
package main

import (
	"flag"
	"fmt"

	"github.com/zbohm/lirisi/client"
)

func main() {
	output := flag.String("output", "", "Output to filename.")
	flag.Parse()

	if flag.Arg(0) == "create-private-key" {
		client.CreatePrivateKey(*output)
		return
	}

	usage := `Usage:
lirisi [params] COMMAND

Commands:
  create-private-key

Examples:
  lirisi create-private-key > private-key.hex
  lirisi --output=private-key.hex create-private-key
`
	fmt.Println(usage)
}
