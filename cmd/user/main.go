package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/kasperdi/BonehFranklin-golang/fullident"
)

const (
	PARAMETERS_COMMAND  = "get-parameters"
	PRIVATE_KEY_COMMAND = "get-private-key"
	ENCRYPT_COMMAND     = "encrypt"
	DECRYPT_COMMAND     = "decrypt"

	PRIVATE_KEY_REQUEST = 1
	PARAMETER_REQUEST   = 2
)

func main() {
	switch os.Args[1] {
	case PARAMETERS_COMMAND:
		pkgAddress := os.Args[2]
		handleParametersCommand(pkgAddress)
	case PRIVATE_KEY_COMMAND:
		pkgAddress := os.Args[2]
		id := os.Args[3]
		handlePrivateKeyCommand(pkgAddress, id)
	case ENCRYPT_COMMAND:
		id := os.Args[2]
		msg := os.Args[3]
		handleEncryptCommand(id, msg)
	case DECRYPT_COMMAND:
		ciphertext := os.Args[2]
		handleDecryptCommand(ciphertext)
	}
}

func writeParametersFile(P *bls.G2, Ppub *bls.G2) {
	fileBytes := make([]byte, 0)
	fileBytes = append(fileBytes, P.BytesCompressed()...)
	fileBytes = append(fileBytes, Ppub.BytesCompressed()...)
	err := os.WriteFile("params.bin", fileBytes, 0664)
	if err != nil {
		panic(err)
	}
}

func readParametersFile() fullident.PublicParameters {
	fileBytes, err := os.ReadFile("params.bin")
	if err != nil {
		panic(err)
	}

	if len(fileBytes) != 96*2 {
		panic("incorrect number of bytes from file")
	}

	P := new(bls.G2)
	P.SetBytes(fileBytes[:96])
	PPub := new(bls.G2)
	PPub.SetBytes(fileBytes[96:])

	return fullident.PublicParameters{P: P, PPub: PPub}
}

func handleParametersCommand(pkgAddress string) {
	conn, err := net.Dial("tcp", pkgAddress+":8000")
	if err != nil {
		panic(err)
	}

	// Send parameter request
	request := make([]byte, 1)
	request[0] = PARAMETER_REQUEST
	conn.Write(request)

	// Receive parameters
	reader := bufio.NewReader(conn)
	buf := make([]byte, 96)

	reader.Read(buf)
	P := new(bls.G2)
	P.SetBytes(buf)

	reader.Read(buf)
	Ppub := new(bls.G2)
	Ppub.SetBytes(buf)

	// Write parameters to file
	writeParametersFile(P, Ppub)
}

func writePrivateKeyFile(dID *bls.G1) {
	fileBytes := dID.BytesCompressed()
	err := os.WriteFile("privatekey.bin", fileBytes, 0664)
	if err != nil {
		panic(err)
	}
}

func readPrivateKeyFile() fullident.PrivateKey {
	fileBytes, err := os.ReadFile("privatekey.bin")
	if err != nil {
		panic(err)
	}

	if len(fileBytes) != 48 {
		panic("incorrect number of bytes from file")
	}

	dID := new(bls.G1)
	dID.SetBytes(fileBytes)

	return fullident.PrivateKey{D_ID: dID}
}

func handlePrivateKeyCommand(pkgAddress, id string) {
	conn, err := net.Dial("tcp", pkgAddress+":8000")
	if err != nil {
		panic(err)
	}

	// Send private key request
	request := make([]byte, 1)
	request[0] = PRIVATE_KEY_REQUEST
	idBytes := []byte(id)
	request = binary.BigEndian.AppendUint32(request, uint32(len(idBytes)))
	request = append(request, idBytes...)
	conn.Write(request)

	// Receive private key
	reader := bufio.NewReader(conn)
	granted, err := reader.ReadByte()
	if err != nil {
		panic(err)
	}
	if granted == 0 {
		panic("was not granted private key")
	}

	keyBytes := make([]byte, 48)
	n, err := reader.Read(keyBytes)
	if err != nil {
		panic(err)
	}
	if n != 48 {
		panic("did not receive all of the expected bytes")
	}

	key := new(bls.G1)
	err = key.SetBytes(keyBytes)
	if err != nil {
		panic(err)
	}

	writePrivateKeyFile(key)
}

func handleEncryptCommand(id, msg string) {
	pp := readParametersFile()

	// TODO: Apply PKCS#7 padding to the message (and split into multiple blocks if necessary)
	msgBytes := []byte(msg)
	paddedMsgBytes := make([]byte, 32)
	for i, b := range msgBytes {
		paddedMsgBytes[i+(32-len(msgBytes))] = b
	}

	c := fullident.Encrypt(&pp, id, paddedMsgBytes)
	cBytes := c.Serialize()
	println(hex.EncodeToString(cBytes))
}

func handleDecryptCommand(ciphertext string) {
	pp := readParametersFile()
	pk := readPrivateKeyFile()

	ciphertextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		panic(err)
	}

	c := new(fullident.Ciphertext)
	c.Deserialize(ciphertextBytes)

	msg, err := fullident.Decrypt(&pp, &pk, c)
	if err != nil {
		panic(err)
	}
	println(string(msg))
}
