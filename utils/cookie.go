package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	ck "secure-urls/cookie"
	"strings"

	"go.uber.org/zap"
)

func DecodeCookie(cookie string) (ck.CookieBody, []byte, error) {
	parts := strings.Split(cookie, ".")
	if len(parts) != 2 {
		logger.Debug("Invalid cookie format", zap.String(COOKIE_NAME, cookie))
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

	return cookiePayload, signature, nil
}

func SignPayload(payload []byte, key string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(payload)
	signature := mac.Sum(nil)
	return signature
}
