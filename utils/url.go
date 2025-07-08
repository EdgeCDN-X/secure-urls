package utils

import (
	"go.uber.org/zap"
)

var logger *zap.Logger

func IsValidPrefix(incomingUrl string, prefix string) bool {
	return len(incomingUrl) >= len(prefix) && incomingUrl[:len(prefix)] == prefix
}
