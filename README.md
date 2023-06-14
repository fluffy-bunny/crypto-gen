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

```bash
docker run ghstahl/crypto-gen ecdsa --time_not_before="2006-01-02Z" --time_not_after="2007-01-02Z" --password="Tricycle2-Hazing-Illusion"
```

### Output

```json
{
    "private_key": "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0f844cb4fdf6085959cf948b8d43b716\n\ns4PjREFIYtg6HRvf6pzPNfdDV4++m4IfKfg9HoehE2VBRb34zZJ7v6ROnEkMBdPS\nJXn2+3NzwxzGscZiwvEnWd7hJPmhdhi6wWFUEgJYzqWl5Du0ZW7Omozs2edUfx5K\nm8LTTfLpq617pvRHxw07RYvKYCiuIupCnIFfw3R37NM=\n-----END EC PRIVATE KEY-----\n",
    "public_key": "-----BEGIN EC  PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa22vib7IzG7CI0apholWnnI6GXcb\nn4tPZH4j+BvCcLbVzWaEUuH0AgxtyoLg7ZTae6KQO0XD43NkWzs5RqrCUQ==\n-----END EC  PUBLIC KEY-----\n",
    "not_before": "2006-01-02T00:00:00Z",
    "not_after": "0001-01-01T00:00:00Z",
    "password": "Tricycle2-Hazing-Illusion"
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

There is a small [example](internal/jwt/keys_test.go) of minting a JWT and validatig it using these generated keys.  
I have started using a jwt as a secure way to send out an invite code that I can then verify when it comes back.  Usually I did this by encrypting a JSON string using a symetric key, then URL encoding it.  A JWT does the same thing except I can look at it using something like [jwt.io](https://jwt.io)  
