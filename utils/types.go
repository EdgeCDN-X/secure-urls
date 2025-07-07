package utils

import (
	ttlcache "secure-urls/cache"

	infrastructurev1alpha1 "github.com/EdgeCDN-X/edgecdnx-controller/api/v1alpha1"
	"go.uber.org/zap"
)

const EX_EXPIRES = "EX-Expires"
const EX_KEYNAME = "EX-KeyName"
const EX_SIGN = "EX-Sign"
const EX_COOKIE_NAME = "ex-sec-session"
const COOKIE_NAME = "ex-sec-session"

type SecureURL struct {
	Namespace string `json:"namespace"`
	Cache     *ttlcache.Cache[infrastructurev1alpha1.SecureKeySpec]
	LogLevel  string
	Logger    *zap.Logger
}
