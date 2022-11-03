package basicident

import (
	"crypto/rand"
	"crypto/sha256"
	"log"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type Ciphertext struct {
	U *bls.G2
	V []byte
}

func Setup() (*bls.Scalar, *bls.G2, *bls.G2) {
	s := new(bls.Scalar)
	err := s.Random(rand.Reader)
	if err != nil {
		log.Fatal("Error while generating master key:", err)
	}

	P := bls.G2Generator()

	P_pub := new(bls.G2)
	P_pub.ScalarMult(s, P)

	return s, P, P_pub
}

func Extract(s *bls.Scalar, ID string) *bls.G1 {
	IDbytes := []byte(ID)
	Q_ID := H1(IDbytes)

	d_ID := new(bls.G1)
	d_ID.ScalarMult(s, Q_ID)

	return d_ID
}

// M must be 32 bytes.
func Encrypt(P, P_pub *bls.G2, ID string, M []byte) Ciphertext {
	r := new(bls.Scalar)
	err := r.Random(rand.Reader)
	if err != nil {
		log.Fatal("Error while generating master key:", err)
	}

	// First part of ciphertext
	rP := new(bls.G2)
	rP.ScalarMult(r, P)

	// Second part of ciphertext
	IDbytes := []byte(ID)
	Q_ID := H1(IDbytes)

	g_ID := bls.Pair(Q_ID, P_pub)
	g_ID_r := new(bls.Gt)
	g_ID_r.Exp(g_ID, r)

	h := H2(g_ID_r)

	return Ciphertext{
		U: rP,
		V: XorBytes(M, h),
	}
}

func Decrypt(c *Ciphertext, dID *bls.G1) []byte {
	return XorBytes(c.V, H2(bls.Pair(dID, c.U)))
}

func H1(in []byte) *bls.G1 {
	out := new(bls.G1)
	out.Hash(in, make([]byte, 0))
	return out
}

func H2(in *bls.Gt) []byte {
	bytes, err := in.MarshalBinary()
	if err != nil {
		panic(err)
	}
	md := sha256.New()
	md.Write(bytes)

	return md.Sum(nil)
}

// Returns a XOR b, where a and b has to have same length
func XorBytes(a []byte, b []byte) []byte {
	res := make([]byte, len(a))
	for i, elem := range a {
		res[i] = elem ^ b[i]
	}
	return res
}
