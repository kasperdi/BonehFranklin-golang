package basicident

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
)

func TestOrderPrime(t *testing.T) {
	q := new(big.Int).SetBytes(bls12381.Order())
	if !q.ProbablyPrime(20) {
		t.Error("q is not prime!!!!")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	for i := 0; i < 20; i++ {
		M := make([]byte, 32)
		rand.Read(M)

		mkey, pp, err := Setup()
		if err != nil {
			t.Error(err)
		}

		pk := Extract(&mkey, "I am an ID")

		c, err := Encrypt(&pp, "I am an ID", M)
		if err != nil {
			t.Error(err)
		}

		dec_M := Decrypt(&pk, &c)

		if !reflect.DeepEqual(dec_M, M) {
			t.Errorf("Error: Decrypt(Encrypt(M) != M")
		}
	}
}

func TestEncryptDecryptIncorrectID(t *testing.T) {
	for i := 0; i < 20; i++ {
		M := make([]byte, 32)
		rand.Read(M)

		mkey, pp, err := Setup()
		if err != nil {
			t.Error(err)
		}

		pk := Extract(&mkey, "I am an ID")

		c, err := Encrypt(&pp, "I am an incorrect ID", M)
		if err != nil {
			t.Error(err)
		}

		dec_M := Decrypt(&pk, &c)

		if reflect.DeepEqual(dec_M, M) {
			t.Errorf("Error: Decrypt(Encrypt(M) == M")
		}
	}
}
