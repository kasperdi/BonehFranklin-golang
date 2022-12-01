package elgamal

import (
	"crypto/rand"
	"math/big"
	"testing"

	"golang.org/x/crypto/openpgp/elgamal"
)

// 3072-bit safe prime, hex encoded. See RFC-3526.
const hexPrime = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"

func exampleGroup() Group {
	p := new(big.Int)
	p.SetString(hexPrime, 16)

	q := new(big.Int)
	q.Sub(p, big.NewInt(1))
	q.Div(q, big.NewInt(2))

	return Group{
		p: *p,
		q: *q,
	}
}

func keyGen(P, G *big.Int) *elgamal.PrivateKey {
	X, _ := rand.Int(rand.Reader, P)
	Y := new(big.Int).Exp(G, X, P)
	priv := &elgamal.PrivateKey{
		PublicKey: elgamal.PublicKey{
			G: G,
			P: P,
			Y: Y,
		},
		X: X,
	}
	return priv
}

func BenchmarkKeygen(b *testing.B) {
	P, _ := new(big.Int).SetString(hexPrime, 16)
	G := big.NewInt(2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keyGen(P, G)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	P, _ := new(big.Int).SetString(hexPrime, 16)
	G := big.NewInt(2)
	priv := keyGen(P, G)

	M := make([]byte, 32)
	rand.Read(M)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elgamal.Encrypt(rand.Reader, &priv.PublicKey, M)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	P, _ := new(big.Int).SetString(hexPrime, 16)
	G := big.NewInt(2)
	priv := keyGen(P, G)

	M := make([]byte, 32)
	rand.Read(M)

	c1, c2, _ := elgamal.Encrypt(rand.Reader, &priv.PublicKey, M)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elgamal.Decrypt(priv, c1, c2)
	}
}
