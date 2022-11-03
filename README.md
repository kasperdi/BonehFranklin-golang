# Boneh Franklin

This package uses [bilinear pairings on the BLS12-381 curve](https://pkg.go.dev/github.com/cloudflare/circl/ecc/bls12381).

## Running the PKG

```bash
go build ./cmd/pkg/

# No parameters, just run! Ctrl+C to stop.
./pkg
```

## Running the user CLI

```bash
go build ./cmd/user/

# Get the public parameters for the scheme (necessary for encrypting and decrypting)
./user get-parameters "<PKG-HOSTNAME>"

# Request a private key for a given ID (necessary for decrypting)
./user get-private-key "<PKG-HOSTNAME>" "<REQUESTED-ID>"

# Encrypt a message! This uses the locally stored params.bin file.
./user encrypt "<RECIPIENT-ID>" "<MESSAGE>"
# Output: hex encoded ciphertext

# Decrypt a received message! This uses the locally stored params.bin and privatekey.bin files. 
./user decrypt "<HEX-CIPHERTEXT>"
# Output: your message!
```
