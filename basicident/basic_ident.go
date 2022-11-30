package basicident

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type MasterKey struct {
	S *bls.Scalar
}

type PublicParameters struct {
	P    *bls.G2
	PPub *bls.G2
}

type PrivateKey struct {
	D_ID *bls.G1
}

type Ciphertext struct {
	U *bls.G2
	V []byte
}

func Setup() (MasterKey, PublicParameters, error) {
	s := new(bls.Scalar)
	err := s.Random(rand.Reader)
	if err != nil {
		return MasterKey{}, PublicParameters{}, fmt.Errorf("error while generating master key: %v", err)
	}

	P := bls.G2Generator()

	PPub := new(bls.G2)
	PPub.ScalarMult(s, P)

	return MasterKey{S: s}, PublicParameters{P, PPub}, nil
}

func Extract(mkey *MasterKey, ID string) PrivateKey {
	IDbytes := []byte(ID)
	Q_ID := H1(IDbytes)

	d_ID := new(bls.G1)
	d_ID.ScalarMult(mkey.S, Q_ID)

	return PrivateKey{D_ID: d_ID}
}

// M must be 32 bytes.
func Encrypt(pp *PublicParameters, ID string, M []byte) (Ciphertext, error) {
	r := new(bls.Scalar)
	err := r.Random(rand.Reader)
	if err != nil {
		return Ciphertext{}, fmt.Errorf("error while generating random scalar: %v", err)
	}

	// First part of ciphertext
	rP := new(bls.G2)
	rP.ScalarMult(r, pp.P)

	// Second part of ciphertext
	IDbytes := []byte(ID)
	Q_ID := H1(IDbytes)

	g_ID := bls.Pair(Q_ID, pp.PPub)
	g_ID_r := new(bls.Gt)
	g_ID_r.Exp(g_ID, r)

	h := H2(g_ID_r)

	return Ciphertext{
		U: rP,
		V: XorBytes(M, h),
	}, nil
}

func Decrypt(pk *PrivateKey, c *Ciphertext) []byte {
	return XorBytes(c.V, H2(bls.Pair(pk.D_ID, c.U)))
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
