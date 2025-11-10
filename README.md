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
