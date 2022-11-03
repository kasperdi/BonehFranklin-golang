package elgamal

import (
	"crypto/rand"
	"math/big"
)

// Group represents a q-order subgroup of the multiplicative group of integers modulo p.
type Group struct {
	p big.Int
	q big.Int
}

// PublicKey represents an ElGamal public key, consisting of two group elements.
type PublicKey struct {
	g big.Int
	h big.Int
}

// SecretKey represents the secret ElGamal exponent needed for decryption.
type SecretKey struct {
	alpha big.Int
}

// GenerateGroup uses rejection sampling to find primes p and q such that p = 2q + 1.
func GenerateGroup(bits int) Group {
	var p, q big.Int
	for {
		x, _ := rand.Prime(rand.Reader, bits)
		p = *x
		q = *big.NewInt(0).Sub(&p, big.NewInt(1))
		q.Div(&q, big.NewInt(2))

		if q.ProbablyPrime(20) {
			break
		}
	}
	return Group{
		p,
		q,
	}
}

// findGroupGenerator finds a random group element.
func (group *Group) findGroupGenerator() big.Int {
	var x *big.Int

	for {
		// Get a random number in [1, p)
		x, _ = rand.Int(rand.Reader, big.NewInt(0).Sub(&group.p, big.NewInt(1)))
		x.Add(x, big.NewInt(1))

		if x.Cmp(big.NewInt(1)) != 0 {
			break
		}
	}
	g := big.NewInt(0).Exp(x, big.NewInt(2), &group.p)
	return *g
}

// GenerateSecretKey generates a secret key, which is just an integer < q.
func GenerateSecretKey(group Group) SecretKey {
	alpha, _ := rand.Int(rand.Reader, &group.q)
	return SecretKey{
		*alpha,
	}
}

// GeneratePublicKey generates a public key from a random group element and the secret key.
func GeneratePublicKey(group Group, sk SecretKey) PublicKey {
	var g, h big.Int
	g = group.findGroupGenerator()
	h.Exp(&g, &sk.alpha, &group.p)
	return PublicKey{
		g,
		h,
	}
}

// GenerateObliviousPublicKey generates a public key for which we cannot (efficiently) find the secret key.
func GenerateObliviousPublicKey(group Group) PublicKey {
	g := group.findGroupGenerator()
	h := group.findGroupGenerator()
	return PublicKey{
		g,
		h,
	}
}

// Encrypt takes a group, public key, and message, and outputs the corresponding ciphertext.
func Encrypt(group Group, pk PublicKey, m big.Int) [2]big.Int {
	m_enc := Encode(group, m)

	r, _ := rand.Int(rand.Reader, &group.p)

	c0 := big.NewInt(1).Exp(&pk.g, r, &group.p)
	c1 := big.NewInt(1).Exp(&pk.h, r, &group.p)
	c1.Mul(c1, &m_enc)
	c1.Mod(c1, &group.p)

	return [2]big.Int{
		*c0,
		*c1,
	}
}

// Decrypt takes a group, secret key, and ciphertext and outputs the corresponding plaintext.
func Decrypt(group Group, sk SecretKey, c [2]big.Int) big.Int {
	var c0, c1, aNeg, r big.Int
	c0 = c[0]
	c1 = c[1]
	aNeg.Neg(&sk.alpha)

	r.Exp(&c0, &aNeg, &group.p)
	r.Mul(&r, &c1)
	r.Mod(&r, &group.p)

	m := Decode(group, r)

	return m
}

func Encode(group Group, m big.Int) big.Int {
	one := big.NewInt(1)
	m_shift := big.NewInt(0).Add(&m, one)
	m_shift_order := big.NewInt(0).Exp(m_shift, &group.q, &group.p)
	if m_shift_order.Cmp(one) == 0 {
		return *m_shift
	}
	m_shift.Neg(m_shift)
	m_shift.Mod(m_shift, &group.p)
	return *m_shift
}

func Decode(group Group, m big.Int) big.Int {
	one := big.NewInt(1)
	if m.Cmp(&group.q) != 1 {
		return *big.NewInt(0).Sub(&m, one)
	}
	res := big.NewInt(0).Set(&m)
	res.Neg(res)
	res.Mod(res, &group.p)
	res.Sub(res, one)
	res.Mod(res, &group.p)
	return *res
}
