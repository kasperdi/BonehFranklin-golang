package fullident

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/kasperdi/BonehFranklin-golang/basicident"
)

type Ciphertext struct {
	U *bls.G2
	V []byte
	W []byte
}

func Setup() (*bls.Scalar, *bls.G2, *bls.G2) {
	return basicident.Setup()
}

func Extract(s *bls.Scalar, ID string) *bls.G1 {
	return basicident.Extract(s, ID)
}

// M must be 32 bytes.
func Encrypt(P, P_pub *bls.G2, ID string, M []byte) Ciphertext {
	// Second part of ciphertext
	IDbytes := []byte(ID)
	Q_ID := basicident.H1(IDbytes)

	sigma := make([]byte, 32)
	rand.Read(sigma)

	r := H3(sigma, M)

	rP := new(bls.G2)
	rP.ScalarMult(&r, P)

	gID := bls.Pair(Q_ID, P_pub)

	gID_exp_r := new(bls.Gt)
	gID_exp_r.Exp(gID, &r)

	return Ciphertext{
		U: rP,
		V: basicident.XorBytes(sigma, basicident.H2(gID_exp_r)),
		W: basicident.XorBytes(M, H4(sigma)),
	}
}

func Decrypt(c *Ciphertext, dID *bls.G1, P *bls.G2) []byte {
	sigma := basicident.XorBytes(c.V, basicident.H2(bls.Pair(dID, c.U)))
	M := basicident.XorBytes(c.W, H4(sigma))
	r := H3(sigma, M)

	rP := new(bls.G2)
	rP.ScalarMult(&r, P)

	if !rP.IsEqual(c.U) {
		panic("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!!!")
	}

	return M
}

// Beware of the 0's
func H3(M1 []byte, M2 []byte) bls.Scalar {
	res := new(bls.Scalar)

	md := sha512.New()
	md.Write(M1)
	md.Write(M2)
	res.SetBytes(md.Sum(nil))

	return *res
}

func H4(in []byte) []byte {
	md := sha256.New()
	md.Write(in)
	return md.Sum(nil)
}
