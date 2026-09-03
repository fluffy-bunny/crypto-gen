# crypto-gen

## github actions secrets

[dockerhub access_token](https://hub.docker.com/settings/security)  
[dockerhub account settings](https://hub.docker.com/settings/general)

```env
DOCKER_HUB_USERNAME={{ your dockerhub username}}
DOCKER_HUB_ACCESS_TOKEN={{ your dockerhub access_token}}
```

## Docker

```bash
docker run ghstahl/crypto-gen
docker run ghstahl/crypto-gen version
```

## Prebuilt binaries (no Go toolchain required)

Every push to `main` publishes a [GitHub Release](https://github.com/fluffy-bunny/crypto-gen/releases) tagged with the same version used for the Docker image, with statically-linked, CGO-free `cli` binaries attached for:

- `cli-linux-amd64.tar.gz`
- `cli-linux-arm64.tar.gz`

along with a `checksums.txt`. These are meant for automation (e.g. a Pulumi `local.Command`/dynamic provider) that needs to shell out to the CLI to generate keys and stuff the output into a Kubernetes `Secret`, without needing Go, or a docker daemon, installed wherever that automation runs:

```bash
curl -fsSL -o cli.tar.gz \
  https://github.com/fluffy-bunny/crypto-gen/releases/download/<tag>/cli-linux-amd64.tar.gz
tar -xzf cli.tar.gz
./cli ed25519 rotation --count=2 > keys.json
```

Pin `<tag>` to a specific release rather than tracking `latest`, so a new crypto-gen release can't silently change what an existing Pulumi stack produces.

## Examples

### ed25519 (recommended)

```bash
.\cli.exe ed25519 rotation
```

### rs256

```bash
docker run ghstahl/crypto-gen rs256 --time_not_before="2006-01-02Z" --time_not_after="2007-01-02Z" --password="Tricycle2-Hazing-Illusion"
```

### ecdsa

```bash
docker run ghstahl/crypto-gen ecdsa --time_not_before="2006-01-02Z" --time_not_after="2007-01-02Z" --password="Tricycle2-Hazing-Illusion"

```

### Output

```json
{
  "private_key": "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,781a940e899958a0b4df3b7421f8437e\n\nWaPqcs2NVH1pSAGvmTzCJkhg4lsZvg/4CK2GWzmPw7f64Wy0IGdw4GR++YgchdOl\nH4nI/Ike903x1IeLgn8p+yI6gv/ly2Uyw3v1AV+d0UmY7duHZwDLLaF3/mdYDwgZ\npswVUl1Dy6fllQ9fYGxWJ5vDE81FO7zymc2VtMeIUg4=\n-----END EC PRIVATE KEY-----\n",
  "public_key": "-----BEGIN EC  PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6hHsmVUijbr+qgu3Hgk+qDHx8ugq\nZWmq6Xud+JtN+k/jF+3Re4U+uOqACtenfAOBOFL9KB7whAnTj4dso9wURA==\n-----END EC  PUBLIC KEY-----\n",
  "not_before": "2006-01-02T00:00:00Z",
  "not_after": "0001-01-01T00:00:00Z",
  "password": "Tricycle2-Hazing-Illusion",
  "kid": "060f04d7d26f432c9036414218fc79a7",
  "public_jwk": {
    "alg": "ES256",
    "crv": "P-256",
    "kid": "060f04d7d26f432c9036414218fc79a7",
    "kty": "EC",
    "use": "sig",
    "x": "6hHsmVUijbr-qgu3Hgk-qDHx8ugqZWmq6Xud-JtN-k8",
    "y": "4xft0XuFPrjqgArXp3wDgThS_Sge8IQJ04-HbKPcFEQ"
  },
  "private_jwk": {
    "alg": "ES256",
    "crv": "P-256",
    "d": "w_XCSxsJRmt0dGQj3fjgyKwhPfKYNGFvwXtHpOMSiXk",
    "kid": "060f04d7d26f432c9036414218fc79a7",
    "kty": "EC",
    "use": "sig",
    "x": "6hHsmVUijbr-qgu3Hgk-qDHx8ugqZWmq6Xud-JtN-k8",
    "y": "4xft0XuFPrjqgArXp3wDgThS_Sge8IQJ04-HbKPcFEQ"
  }
}
```

```bash
docker run ghstahl/crypto-gen ecdsa rotation --time_not_before="2006-01-02Z" --password="Tricycle2-Hazing-Illusion" --count=2
```

### Output

```json
[
  {
    "private_key": "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,e872837cf1228f555a9c9ff84b646767\n\nDB2Ip8JazTjnXJbqf2TkOWj3cifCZtxyzfKhhnv399emDWso0s0GTs3FeUBNMcGB\nCAbOtA/QokCQ+3I0vstG6swLAXz2F1TDob7k8RweK9AwsgQV9oyl9YSXOjpZVh0M\n9s4Jp3sZDHjUNDiZyl5P+V9o3A+HRqQwmYYP+HFsSsk=\n-----END EC PRIVATE KEY-----\n",
    "public_key": "-----BEGIN EC  PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwiPQKrrDZ6kRE2HPedT5HFWxkeCo\nBw6EaaYwPlaNBL7AO7iTWbkOcaZfvWqg/HV2+o94H7iEt6ZdFn62uK0TtQ==\n-----END EC  PUBLIC KEY-----\n",
    "not_before": "2006-01-02T00:00:00Z",
    "not_after": "2007-01-02T00:00:00Z",
    "password": "Tricycle2-Hazing-Illusion",
    "kid": "c4686f20059b4f7a9024eb853489debe",
    "public_jwk": {
      "alg": "ES256",
      "crv": "P-256",
      "kid": "c4686f20059b4f7a9024eb853489debe",
      "kty": "EC",
      "use": "sig",
      "x": "wiPQKrrDZ6kRE2HPedT5HFWxkeCoBw6EaaYwPlaNBL4",
      "y": "wDu4k1m5DnGmX71qoPx1dvqPeB-4hLemXRZ-tritE7U"
    },
    "private_jwk": {
      "alg": "ES256",
      "crv": "P-256",
      "d": "vvx3J-YNehpUv3Nd8VC9oKOqoGeXrbwyBAlEYzLHrf0",
      "kid": "c4686f20059b4f7a9024eb853489debe",
      "kty": "EC",
      "use": "sig",
      "x": "wiPQKrrDZ6kRE2HPedT5HFWxkeCoBw6EaaYwPlaNBL4",
      "y": "wDu4k1m5DnGmX71qoPx1dvqPeB-4hLemXRZ-tritE7U"
    }
  },
  {
    "private_key": "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,a7caa77eaa106d317bc0a1d53286e83d\n\nxw+tgrpAH5Tq/GEFiS07k4GuSm+jG9gFUutOcUXPkD6gBVY+WoN2FpRloiIADWyF\nEsAQg8ssSebqrYt3NFjq/5VgYi1mWmkxRVpCd2gYFaMn4sOIb5T17afyKean5eWo\nQWcn1AmmWqgX/51h282t5IgW0qrHrso8cUqu2YfYxmM=\n-----END EC PRIVATE KEY-----\n",
    "public_key": "-----BEGIN EC  PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzfWAl57uzaKKD3b3xfFzlH9PBu3G\nWcABnOwimvGfc1CaS/JWK94v1AaTd98Nf6AYB6VeErj1hQIPFEOJGgyklA==\n-----END EC  PUBLIC KEY-----\n",
    "not_before": "2006-12-02T00:00:00Z",
    "not_after": "2007-12-02T00:00:00Z",
    "password": "Tricycle2-Hazing-Illusion",
    "kid": "a225baf703714cd1b857ae0a5f6574e8",
    "public_jwk": {
      "alg": "ES256",
      "crv": "P-256",
      "kid": "a225baf703714cd1b857ae0a5f6574e8",
      "kty": "EC",
      "use": "sig",
      "x": "zfWAl57uzaKKD3b3xfFzlH9PBu3GWcABnOwimvGfc1A",
      "y": "mkvyViveL9QGk3ffDX-gGAelXhK49YUCDxRDiRoMpJQ"
    },
    "private_jwk": {
      "alg": "ES256",
      "crv": "P-256",
      "d": "60wvcOHchN5MurcjoL-uEezRBI_CNoLAbmmT9_OKu5U",
      "kid": "a225baf703714cd1b857ae0a5f6574e8",
      "kty": "EC",
      "use": "sig",
      "x": "zfWAl57uzaKKD3b3xfFzlH9PBu3GWcABnOwimvGfc1A",
      "y": "mkvyViveL9QGk3ffDX-gGAelXhK49YUCDxRDiRoMpJQ"
    }
  }
]
```

## JWT

There is a small [example](internal/jwt/keys_test.go) of minting a JWT and validating it using these generated keys.  
I have started using a jwt as a secure way to send out an invite code that I can then verify when it comes back. Usually I did this by encrypting a JSON string using a symetric key, then URL encoding it. A JWT does the same thing except I can look at it using something like [jwt.io](https://jwt.io)

## Functionality

**Key generation** (`cli.exe <alg> [rotation]`, or the `internal/<alg>` packages directly):

| Algorithm | CLI command | Curve/size | Notes |
|---|---|---|---|
| RS256 | `rs256` / `rs256 rotation` | RSA 2048 | password-protected PEM optional |
| ECDSA | `ecdsa` / `ecdsa rotation` | P-256 (ES256) | password-protected PEM optional; the CLI always generates P-256 — there's no flag to pick P-384/P-521 |
| Ed25519 | `ed25519` / `ed25519 rotation` | Ed25519 (EdDSA) | recommended default; see [internal/ed25519/ed25519.go](internal/ed25519/ed25519.go) |

Every generated key ships both a PEM key pair and public/private [JWK](https://datatracker.ietf.org/doc/html/rfc7517) representations, and `rotation` variants emit a set of `--count` keys spanning a not-before/not-after window for key rotation.

**JWT minting and validation** ([internal/jwt](internal/jwt)):

- `LoadSigningKey` / `CreateKeySet` ([internal/jwt/keys.go](internal/jwt/keys.go)) turn a signing-key JSON document into a `jwx` public [`jwk.Set`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwk) for validation.
- `MintStandardJWT` / `MintGenericJWT` ([internal/jwt/mint.go](internal/jwt/mint.go)) sign a token with whatever key you hand them, dispatching on the key's `alg`: **RS256, RS384, RS512, ES256, ES384, ES512, EdDSA** are all supported signing methods.
- `JWTValidator` ([internal/jwt/jwt_validator.go](internal/jwt/jwt_validator.go)) parses and validates a token against a `jwk.Set`, with configurable signature verification, required issuer, and clock-skew tolerance.

Note: while the minter/validator support all three algorithm families end to end (including ES384/ES512), the CLI's `ecdsa` generator currently only produces P-256/ES256 keys — ES384/ES512 keys have to be constructed by hand (or via another tool) to feed into the minter.

## Test Coverage

| Algorithm | Key generation | Low-level sign/verify | Mint → validate round trip (via `MintGenericJWT`/`JWTValidator`) |
|---|---|---|---|
| RS256 | ✅ [internal/rsautil/rs256_util_test.go](internal/rsautil/rs256_util_test.go) | ✅ same file | ✅ [internal/jwt/keys_test.go](internal/jwt/keys_test.go) — `TestMintJWTWithRS256Keys`, `TestMintGenericJWTWithRS256`, `TestRS256KeyStructure`, `TestRS256JWTHeaderValidation` |
| ECDSA (ES256/ES384/ES512) | ✅ [internal/ecdsa/edcsa_util_test.go](internal/ecdsa/edcsa_util_test.go) (P-256 only) | ✅ same file (via `pascaldekloe/jwt` / `square/go-jose`, not this repo's minter) | ✅ [internal/jwt/keys_test.go](internal/jwt/keys_test.go) — `TestJWTValidator` (ES256) and `TestMintJWTWithECDSAKeys` (ES256/ES384/ES512 table test, fresh keys each run) |
| Ed25519 (EdDSA) | ✅ [internal/ed25519/ed25519_test.go](internal/ed25519/ed25519_test.go) | ✅ same file (raw `crypto/ed25519` sign/verify) | ✅ [internal/jwt/keys_test.go](internal/jwt/keys_test.go) — `TestMintJWTWithEd25519Keys` |

Also covered: `TestJWTValidatorRejectsWrongKey` proves the validator actually rejects a token signed by a key that isn't in its key set, rather than just parsing the token structure.

Until recently, Ed25519 keys could be generated but not actually used to mint a JWT — `MintGenericJWT`'s signing-method switch had no `EdDSA` case, so it would return `"unsupported signing method: EdDSA"`. That's now fixed in [internal/jwt/mint.go](internal/jwt/mint.go), and `TestMintJWTWithEd25519Keys` is the regression test for it.
