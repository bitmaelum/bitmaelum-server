package main

import (
	"fmt"
	pow "github.com/bitmaelum/bitmaelum-server/pkg/proofofwork"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <bits> <data>", os.Args[0])
		os.Exit(1)
	}

	bits, _ := strconv.Atoi(os.Args[1])
	data := os.Args[2]

	fmt.Printf("Working on %d bits proof...\n", bits)
	work := pow.New(bits, []byte(data), 0)

	work.Work()
	fmt.Printf("Proof: %d\n", work.Proof)
}
