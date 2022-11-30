package fullident

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"log"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/kasperdi/BonehFranklin-golang/basicident"
)

type MasterKey = basicident.MasterKey

type PublicParameters = basicident.PublicParameters

type PrivateKey = basicident.PrivateKey

type Ciphertext struct {
	U *bls.G2
	V []byte
	W []byte
}

func (c *Ciphertext) Serialize() []byte {
	bytes := c.U.BytesCompressed()
	// We know that this is 32 bytes...
	bytes = append(bytes, c.V...)
	// And the same here...
	bytes = append(bytes, c.W...)

	if len(bytes) != 96+32+32 {
		log.Fatalf("wrong byte length %v, expected %v", len(bytes), 96+32+32)
	}
	return bytes
}

func (c *Ciphertext) Deserialize(in []byte) error {
	if len(in) != 96+32+32 {
		return errors.New("wrong length of bytes")
	}
	c.U = new(bls.G2)
	c.U.SetBytes(in[:96])
	c.V = in[96 : 96+32]
	c.W = in[96+32:]

	return nil
}

func Setup() (MasterKey, PublicParameters, error) {
	return basicident.Setup()
}

func Extract(mkey *MasterKey, ID string) PrivateKey {
	return basicident.Extract(mkey, ID)
}

// M must be 32 bytes.
func Encrypt(pp *PublicParameters, ID string, M []byte) Ciphertext {
	// Second part of ciphertext
	IDbytes := []byte(ID)
	Q_ID := basicident.H1(IDbytes)

	sigma := make([]byte, 32)
	rand.Read(sigma)

	r := H3(sigma, M)

	rP := new(bls.G2)
	rP.ScalarMult(&r, pp.P)

	gID := bls.Pair(Q_ID, pp.PPub)

	gID_exp_r := new(bls.Gt)
	gID_exp_r.Exp(gID, &r)

	return Ciphertext{
		U: rP,
		V: basicident.XorBytes(sigma, basicident.H2(gID_exp_r)),
		W: basicident.XorBytes(M, H4(sigma)),
	}
}

func Decrypt(pp *PublicParameters, pk *PrivateKey, c *Ciphertext) ([]byte, error) {
	sigma := basicident.XorBytes(c.V, basicident.H2(bls.Pair(pk.D_ID, c.U)))
	M := basicident.XorBytes(c.W, H4(sigma))
	r := H3(sigma, M)

	rP := new(bls.G2)
	rP.ScalarMult(&r, pp.P)

	if !rP.IsEqual(c.U) {
		return nil, errors.New("error while decrypting: rP does not equal U")
	}

	return M, nil
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
