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

		mkey, pp, err := Setup()
		if err != nil {
			t.Error(err)
		}

		pk := Extract(&mkey, "I am an ID")

		c := Encrypt(&pp, "I am an ID", M)
		dec_M, err := Decrypt(&pp, &pk, &c)
		if err != nil {
			t.Error(err)
		}

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

		c := Encrypt(&pp, "I am an incorrect ID", M)
		dec_M, err := Decrypt(&pp, &pk, &c)
		if err == nil {
			t.Error(err)
		}

		if reflect.DeepEqual(dec_M, M) {
			t.Errorf("Error: Decrypt(Encrypt(M) == M")
		}
	}
}

func BenchmarkSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Setup()
	}
}

func BenchmarkExtract(b *testing.B) {
	mkey, _, _ := Setup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Extract(&mkey, "I am an ID")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	M := make([]byte, 32)
	rand.Read(M)
	_, pp, _ := Setup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(&pp, "I am an ID", M)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	M := make([]byte, 32)
	rand.Read(M)
	mkey, pp, _ := Setup()

	pk := Extract(&mkey, "I am an ID")
	c := Encrypt(&pp, "I am an ID", M)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(&pp, &pk, &c)
	}
}
