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
        "private_key": "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,9829d46fb9d6cc967ff0b0fa79c4c3e1\n\nO4o0UlR5s/sqW2lPWvd1UKxQ969LweP/JbYy2sxBtdZsHD4altqfGr5PLJwp/keF\nrbFqli/D/y8Y+E4rSaff92QGYGtA40WJfBYL544sFLYCefTIkdrSyHLxglq9b86l\nYsQhs2rM5QS9DQQ2jGC7wLO5SOz82+Oy3nBQwLnfeq0=\n-----END EC PRIVATE KEY-----\n",
        "public_key": "-----BEGIN EC  PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqph2QQWPUY9h0GJpebKHAZMg2pC7\nJwkS1ZNoXpFMU20Tl+EOiqv86Hd0L/+iujqjB/cDIZ1t0k9HrY0pYQCtoQ==\n-----END EC  PUBLIC KEY-----\n",
        "not_before": "2006-01-02T00:00:00Z",
        "not_after": "2007-01-02T00:00:00Z",
        "password": "Tricycle2-Hazing-Illusion"
    },
    {
        "private_key": "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,9829d46fb9d6cc967ff0b0fa79c4c3e1\n\nO4o0UlR5s/sqW2lPWvd1UKxQ969LweP/JbYy2sxBtdZsHD4altqfGr5PLJwp/keF\nrbFqli/D/y8Y+E4rSaff92QGYGtA40WJfBYL544sFLYCefTIkdrSyHLxglq9b86l\nYsQhs2rM5QS9DQQ2jGC7wLO5SOz82+Oy3nBQwLnfeq0=\n-----END EC PRIVATE KEY-----\n",
        "public_key": "-----BEGIN EC  PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqph2QQWPUY9h0GJpebKHAZMg2pC7\nJwkS1ZNoXpFMU20Tl+EOiqv86Hd0L/+iujqjB/cDIZ1t0k9HrY0pYQCtoQ==\n-----END EC  PUBLIC KEY-----\n",
        "not_before": "2006-12-02T00:00:00Z",
        "not_after": "2007-12-02T00:00:00Z",
        "password": "Tricycle2-Hazing-Illusion"
    }
]
```

## JWT

There is a small [example](internal/jwt/keys_test.go) of minting a JWT and validatig it using these generated keys.  
I have started using a jwt as a secure way to send out an invite code that I can then verify when it comes back.  Usually I did this by encrypting a JSON string using a symetric key, then URL encoding it.  A JWT does the same thing except I can look at it using something like [jwt.io](https://jwt.io)  
