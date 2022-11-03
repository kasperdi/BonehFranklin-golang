package main

import (
	"bufio"
	"net"
	"os"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

const (
	PARAMETERS_COMMAND  = "get-parameters"
	PRIVATE_KEY_COMMAND = "get-private-key"
	ENCRYPT_COMMAND     = "encrypt"
	DECRYPT_COMMAND     = "decrypt"
)

func main() {
	if len(os.Args) != 4 {
		panic("WRONG NUMBER OF ARGS!!! AAAAAAAAAAAAAAAAAAAAAAAAAA")
	}
	switch os.Args[1] {
	case PARAMETERS_COMMAND:
		handleParametersCommand()
	case PRIVATE_KEY_COMMAND:
		handlePrivateKeyCommand()
	case ENCRYPT_COMMAND:
		handleEncryptCommand()
	case DECRYPT_COMMAND:
		handleDecryptCommand()
	}

	net.Dial("tcp", ":8000")
}

func handleParametersCommand() {
	pkgAddress := os.Args[2]
	conn, err := net.Dial("tcp", pkgAddress+":8000")
	if err != nil {
		panic("AAAAAAAAAAAAAAAAa")
	}

	request := make([]byte, 1)
	request[0] = 2
	conn.Write(request)

	reader := bufio.NewReader(conn)
	buf := make([]byte, 96)
	reader.Read(buf)

	P := new(bls.G2)
	P.SetBytes(buf)

	reader.Read(buf)
	Ppub := new(bls.G2)
	Ppub.SetBytes(buf)

	// TODO: Write to file???
	panic("DIDN'T FIX THIS YET, AAAAAAAAAAAa")
}
func handlePrivateKeyCommand() {
	pkgAddress := os.Args[2]
	id := os.Args[3]
	id_len := len(id)
	conn, err := net.Dial("tcp", pkgAddress+":8000")
	if err != nil {
		panic("AAAAAAAAAAAAa")
	}
	request := make([]byte, 1)

	conn.Write()
}

func handleEncryptCommand() {}

func handleDecryptCommand() {}
