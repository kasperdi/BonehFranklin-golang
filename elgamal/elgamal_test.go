package elgamal

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func BenchmarkKeygen(b *testing.B) {
	g := GenerateGroup(3072)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk := GenerateSecretKey(g)
		GeneratePublicKey(g, sk)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	g := GenerateGroup(3072)
	sk := GenerateSecretKey(g)
	pk := GeneratePublicKey(g, sk)

	M := make([]byte, 32)
	rand.Read(M)
	M_int := *new(big.Int)
	M_int.SetBytes(M)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(g, pk, M_int)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	g := GenerateGroup(3072)
	sk := GenerateSecretKey(g)
	pk := GeneratePublicKey(g, sk)

	M := make([]byte, 32)
	rand.Read(M)
	M_int := *new(big.Int)
	M_int.SetBytes(M)

	c := Encrypt(g, pk, M_int)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(g, sk, c)
	}
}
