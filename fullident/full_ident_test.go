package fullident

import (
	"crypto/rand"
	"reflect"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	for i := 0; i < 20; i++ {
		M := make([]byte, 32)
		rand.Read(M)

		mkey, P, Ppub := Setup()

		dID := Extract(mkey, "I am an ID")

		c := Encrypt(P, Ppub, "I am an ID", M)
		dec_M := Decrypt(&c, dID, P)

		if !reflect.DeepEqual(dec_M, M) {
			t.Errorf("Error: Decrypt(Encrypt(M) != M")
		}
	}
}

func TestEncryptDecryptIncorrectID(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	for i := 0; i < 20; i++ {
		M := make([]byte, 32)
		rand.Read(M)

		mkey, P, Ppub := Setup()

		dID := Extract(mkey, "I am an ID")

		c := Encrypt(P, Ppub, "I am an incorrect ID", M)
		dec_M := Decrypt(&c, dID, P)

		if reflect.DeepEqual(dec_M, M) {
			t.Errorf("Error: Decrypt(Encrypt(M) == M")
		}
	}
}
