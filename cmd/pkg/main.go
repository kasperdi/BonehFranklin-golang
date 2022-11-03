package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/kasperdi/BonehFranklin-golang/fullident"
)

const PRIVATE_KEY_REQUEST = 1
const PARAMETER_REQUEST = 2

type IBEParameters struct {
	masterKey *bls.Scalar
	P         *bls.G2
	Ppub      *bls.G2
}

func setup() IBEParameters {
	masterKey, P, Ppub := fullident.Setup()
	return IBEParameters{
		masterKey: masterKey,
		P:         P,
		Ppub:      Ppub,
	}
}

func handlePrivateKeyRequest(conn net.Conn, reader *bufio.Reader, params *IBEParameters) {
	idLenBytes := make([]byte, 4)
	_, err := reader.Read(idLenBytes)
	if err != nil {
		panic(err)
	}
	idLen := binary.BigEndian.Uint32(idLenBytes)

	idBytes := make([]byte, idLen)
	_, err = reader.Read(idBytes)
	if err != nil {
		panic(err)
	}
	id := string(idBytes)

	fmt.Printf("%v asked for private key for \"%v\"\n", conn.RemoteAddr().String(), id)

	key := fullident.Extract(params.masterKey, id)
	keyBytes := key.BytesCompressed()

	response := make([]byte, 49)
	// Authentication successful (y)
	response[0] = 1
	for i := 0; i < len(keyBytes); i++ {
		response[i+1] = keyBytes[i]
	}

	n, err := conn.Write(response)
	if err != nil {
		panic(err)
	}
	if n != 49 {
		panic("could not write all bytes")
	}
}

func handleParameterRequest(conn net.Conn, params *IBEParameters) {
	response := make([]byte, 0)
	response = append(response, params.P.BytesCompressed()...)
	response = append(response, params.Ppub.BytesCompressed()...)
	conn.Write(response)
}

func handleConnection(conn net.Conn, params *IBEParameters) {
	defer conn.Close()

	for {
		reader := bufio.NewReader(conn)
		reqType, err := reader.ReadByte()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			fmt.Printf("Got an error while reading from %v: %v", conn.RemoteAddr().String(), err)
			break
		}

		switch reqType {
		case PRIVATE_KEY_REQUEST:
			handlePrivateKeyRequest(conn, reader, params)
		case PARAMETER_REQUEST:
			handleParameterRequest(conn, params)
		}
	}
}

func main() {
	fmt.Println("Generating IBE parameters...")
	params := setup()

	fmt.Println("Start server...")

	// listen on port 8000
	ln, err := net.Listen("tcp", ":8000")
	if err != nil {
		log.Fatalf("Failed while setting up TCP listener: %v", err)
	}

	fmt.Println("Server started on", ln.Addr().String())

	// run loop forever (or until ctrl-c)
	for {
		// accept connection
		conn, err := ln.Accept()
		if err != nil {
			continue
		}

		go handleConnection(conn, &params)
	}
}
