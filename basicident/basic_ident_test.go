package basicident

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
)

func TestPrimeGen(t *testing.T) {
	// k := 5
	// params, master_key := Setup(k)
}

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

		mkey, P, Ppub := Setup()

		dID := Extract(mkey, "I am an ID")

		c := Encrypt(P, Ppub, "I am an ID", M)
		dec_M := Decrypt(&c, dID)

		if !reflect.DeepEqual(dec_M, M) {
			t.Errorf("Error: Decrypt(Encrypt(M) != M")
		}
	}
}

func TestEncryptDecryptIncorrectID(t *testing.T) {
	for i := 0; i < 20; i++ {
		M := make([]byte, 32)
		rand.Read(M)

		mkey, P, Ppub := Setup()

		dID := Extract(mkey, "I am an ID")

		c := Encrypt(P, Ppub, "I am an incorrect ID", M)
		dec_M := Decrypt(&c, dID)

		if reflect.DeepEqual(dec_M, M) {
			t.Errorf("Error: Decrypt(Encrypt(M) == M")
		}
	}
}
