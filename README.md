# Secure URLs

## Introduction
This application validates URL signatures and secure cookies.

When you need to protect CDN content, distribute signed URLs to clients.

# Authentication methods

## Signed URLs for single object
Each object request must be signed with a valid URL. The URL signature uses the following query parameters:
* `EX-Expires` - Unix timestamp for when the URL expires
* `EX-KeyName` - Name of the key used to sign the request
* `EX-Sign` - Signature

The ordering of query parameters must be preserved. Example:

```
https://resource.cdn.edgecdnx.com/my/favourite/file?user-query1=yes&EX-Expires=1861631432&EX-KeyName=key2&EX-Sign=8e36e0d2b6daeb9b2f1a0d12137c6de07894abac7766684ef8faa7732d6d58dc
```

You can include user-defined query parameters, but they must appear before CDN-specific query parameters.

URL to sign:
`https://resource.cdn.edgecdnx.com/my/favourite/file?user-query1=yes&EX-Expires=1861631432&EX-KeyName=key2`

```go
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(payload)
	signature := mac.Sum(nil)
```

## Signature generation examples

The validator expects these exact rules:

* HMAC algorithm: `HMAC-SHA256`
* Signature output for URL query param `EX-Sign`: lowercase hex string
* Query param ordering must be preserved exactly
* For prefix signatures, `EX-UrlPrefix` must be a URL-safe base64 encoded prefix

### Go

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
)

func signHex(payload, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// Single file/object signature
func signedFileURL(baseURL, userQuery, keyName, key string, expires int64) string {
	payload := fmt.Sprintf("%s?%sEX-Expires=%d&EX-KeyName=%s", baseURL, userQuery, expires, keyName)
	sign := signHex(payload, key)
	return payload + "&EX-Sign=" + sign
}

// Prefix signature (for HLS/DASH)
func signedPrefixURL(requestURL, prefix, keyName, key string, expires int64) string {
	encodedPrefix := base64.URLEncoding.EncodeToString([]byte(prefix))
	payload := fmt.Sprintf("%s?EX-UrlPrefix=%s&EX-Expires=%d&EX-KeyName=%s", requestURL, url.QueryEscape(encodedPrefix), expires, keyName)
	sign := signHex(payload, key)
	return payload + "&EX-Sign=" + sign
}
```

### PHP

```php
<?php
function b64url_with_padding(string $input): string {
    return strtr(base64_encode($input), '+/', '-_');
}

function sign_hex(string $payload, string $key): string {
    return hash_hmac('sha256', $payload, $key);
}

// Single file/object signature
function signed_file_url(string $baseUrl, string $userQuery, string $keyName, string $key, int $expires): string {
    $payload = sprintf('%s?%sEX-Expires=%d&EX-KeyName=%s', $baseUrl, $userQuery, $expires, $keyName);
    $sign = sign_hex($payload, $key);
    return $payload . '&EX-Sign=' . $sign;
}

// Prefix signature (for HLS/DASH)
function signed_prefix_url(string $requestUrl, string $prefix, string $keyName, string $key, int $expires): string {
    $encodedPrefix = b64url_with_padding($prefix);
    $payload = sprintf('%s?EX-UrlPrefix=%s&EX-Expires=%d&EX-KeyName=%s',
        $requestUrl,
        rawurlencode($encodedPrefix),
        $expires,
        $keyName
    );
    $sign = sign_hex($payload, $key);
    return $payload . '&EX-Sign=' . $sign;
}
```

### Node.js

```js
const crypto = require('crypto');

function b64urlWithPadding(input) {
	return Buffer.from(input, 'utf8')
		.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_');
}

function signHex(payload, key) {
	return crypto.createHmac('sha256', key).update(payload, 'utf8').digest('hex');
}

// Single file/object signature
function signedFileUrl(baseUrl, userQuery, keyName, key, expires) {
	const payload = `${baseUrl}?${userQuery}EX-Expires=${expires}&EX-KeyName=${keyName}`;
	const sign = signHex(payload, key);
	return `${payload}&EX-Sign=${sign}`;
}

// Prefix signature (for HLS/DASH)
function signedPrefixUrl(requestUrl, prefix, keyName, key, expires) {
	const encodedPrefix = encodeURIComponent(b64urlWithPadding(prefix));
	const payload = `${requestUrl}?EX-UrlPrefix=${encodedPrefix}&EX-Expires=${expires}&EX-KeyName=${keyName}`;
	const sign = signHex(payload, key);
	return `${payload}&EX-Sign=${sign}`;
}
```

### Java

```java
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class UrlSigner {
	private UrlSigner() {}

	static String signHex(String payload, String key) throws Exception {
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
		byte[] out = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
		StringBuilder hex = new StringBuilder(out.length * 2);
		for (byte b : out) {
			hex.append(String.format("%02x", b));
		}
		return hex.toString();
	}

	// Single file/object signature
	static String signedFileUrl(String baseUrl, String userQuery, String keyName, String key, long expires) throws Exception {
		String payload = String.format("%s?%sEX-Expires=%d&EX-KeyName=%s", baseUrl, userQuery, expires, keyName);
		String sign = signHex(payload, key);
		return payload + "&EX-Sign=" + sign;
	}

	// Prefix signature (for HLS/DASH)
	static String signedPrefixUrl(String requestUrl, String prefix, String keyName, String key, long expires) throws Exception {
		String encodedPrefix = Base64.getUrlEncoder().encodeToString(prefix.getBytes(StandardCharsets.UTF_8));
		String payload = String.format(
				"%s?EX-UrlPrefix=%s&EX-Expires=%d&EX-KeyName=%s",
				requestUrl,
				URLEncoder.encode(encodedPrefix, StandardCharsets.UTF_8),
				expires,
				keyName
		);
		String sign = signHex(payload, key);
		return payload + "&EX-Sign=" + sign;
	}
}
```

If the signature matches `EX-Sign`, the service returns HTTP `200`.
Because this flow validates a single URL only, no session cookie is returned.

## Signed URLs for Prefixes
Prefixes can be signed for live streaming (HLS or DASH). In this flow, the initial request must include the `EX-UrlPrefix` query parameter.

* `EX-UrlPrefix` - Base64 URL-encoded prefix
* `EX-Expires` - Unix timestamp for when the URL expires
* `EX-KeyName` - Name of the key used to sign the request
* `EX-Sign` - Signature

Example:
```
http://lsansdkaglh23as.cdn.edgecdnx.com/nice/movie/here/index.m3u8?EX-UrlPrefix=aHR0cDovL2xzYW5zZGthZ2xoMjNhcy5jZG4uZWRnZWNkbnguY29tL25pY2UvbW92aWUvaGVyZS8=&EX-Expires=1861631432&EX-KeyName=key2&EX-Sign=8e36e0d2b6daeb9b2f1a0d12137c6de07894abac7766684ef8faa7732d6d58dc
```

The encoded `EX-UrlPrefix` value contains this string:
`http://lsansdkaglh23as.cdn.edgecdnx.com/nice/movie/here/`

The service first verifies that the current request matches this prefix. If it matches, the URL to sign is built as:
```
http://lsansdkaglh23as.cdn.edgecdnx.com/nice/movie/here/index.m3u8?EX-UrlPrefix=aHR0cDovL2xzYW5zZGthZ2xoMjNhcy5jZG4uZWRnZWNkbnguY29tL25pY2UvbW92aWUvaGVyZS8=&EX-Expires=1861631432&EX-KeyName=key2
```

User-defined query parameters are not supported for prefix signatures.

If the URL is valid, a session cookie is returned with the following payload:

```go
type CookieBody struct {
	KeyName   string `json:"keyName"`
	Expires   int64  `json:"expires"`
	Service   string `json:"service"`
	URLPrefix string `json:"url,omitempty"`
}
```

This object is marshaled and signed again with the client key defined by `KeyName`.
The payload is Base64 URL-encoded, and the signature is appended after a dot (`.`), also Base64 URL-encoded.

Example:
```
ex-sec-session eyJrZXlOYW1lIjoia2V5MiIsImV4cGlyZXMiOjE3NTE5ODI1MTQsInNlcnZpY2UiOiJsc2Fuc2RrYWdsaDIzYXMuY2RuLmVkZ2VjZG54LmNvbSIsInVybCI6ImFIUjBjRG92TDJ4ellXNXpaR3RoWjJ4b01qTmhjeTVqWkc0dVpXUm5aV05rYm5ndVkyOXRMMjVwWTJVdmJXOTJhV1V2YUdWeVpTOD0ifQ==.Z69misZcfNtGAvI6YfyIFSvFOww_JTyf-wmOkJuF7uo=
```

This cookie scope is set from the URL prefix, so the client sends the session cookie with subsequent media chunk requests.


## Secure Cookies
The secure cookie from the previous step is sent with requests.
The session cookie is parsed first, and `URLPrefix` is Base64-decoded:

```go
func DecodeCookie(cookie string) (ck.CookieBody, []byte, error) {
	parts := strings.Split(cookie, ".")
	if len(parts) != 2 {
		logger.Debug("Invalid cookie format", zap.String(EX_COOKIE_NAME, cookie))
		return ck.CookieBody{}, []byte{}, errors.New("Invalid cookie format")
	}

	payload, err := base64.URLEncoding.DecodeString(parts[0])

	if err != nil {
		logger.Debug("Invalid cookie payload", zap.Error(err))
		return ck.CookieBody{}, []byte{}, errors.New("Invalid cookie payload")
	}

	signature, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		logger.Debug("Invalid cookie signature", zap.Error(err))
		return ck.CookieBody{}, []byte{}, errors.New("Invalid cookie Signature")
	}

	cookiePayload := ck.CookieBody{}
	err = json.Unmarshal(payload, &cookiePayload)

	if err != nil {
		logger.Debug("Invalid cookie payload", zap.Error(err))
		return ck.CookieBody{}, []byte{}, errors.New("Json unmarshal error")
	}

	urlPrefix, err := base64.URLEncoding.DecodeString(cookiePayload.URLPrefix)
	if err != nil {
		logger.Debug("Invalid URLPrefix in cookie payload", zap.Error(err))
		return ck.CookieBody{}, []byte{}, errors.New("Invalid URLPrefix in cookie payload")
	}

	cookiePayload.URLPrefix = string(urlPrefix)

	return cookiePayload, signature, nil
}
```

The session cookie object is signed again with the key stored in the client configuration.
If the signature is valid and not expired, the request is authorized.

If the cookie is about to expire (within 20 minutes of TTL), a new cookie is issued and returned to the client.


```go
if time.Until(time.Unix(cookiePayload.Expires, 0)) < 20*time.Minute {
    // Refresh cookie if expires soon
    secureURL.Logger.Debug("Cookie expires in less than 20 minutes. Refreshing session cookie", zap.Int64("expires_in_sec", cookiePayload.Expires-time.Now().Unix()))
    cookiePayload.Expires = time.Now().Unix() + 1*60*60 // Extend expiry by 1 hour
    payload, err = json.Marshal(cookiePayload)
...
```

# Recommendations

It is strongly recommended to distribute secure URLs over HTTPS.

You can maintain multiple keys, but rotate them periodically and revoke old keys once they are no longer in use.