package main

import "crypto/rand"

func Setup(k uint) (*Parameters, *MasterKey) {
	// Generates random prime q of size k bits
	q := rand.Prime(rand.Reader, k)

	// Find smallest prime p such that p = 2 mod 3, q divides p + 1, and q^2 does not divide p + 1
	var big.Int p
	ell := big.NewInt(1)
	for {
		// Check (1) - Implicit
		p = ell * q + 1

		// Check (2)
		p_plus_one := p.Add(big.NewInt(big.NewInt(1)))
		if new(big.Int).Mod(q, p_plus_one).Cmp(big.NewInt(0)) != 0 {
			continue
		}
		
		// Checek (3)
		if new(big.Int).Mod(new(big.Int).Exp(q, big.NewInt(2), nil), p_plus_one).Cmp(big.NewInt(0)) == 0 {
			break
		}
		ell.Add(ell, big.NewInt(1))
	}
}

func Extract() {

}

func Encrypt() {

}

func Decrypt() {

}
