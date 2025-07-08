package utils

import (
	"go.uber.org/zap"
)

var logger *zap.Logger

func StripLastElementFromPath(path string) string {
	if path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}
	lastSlash := -1
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			lastSlash = i
			break
		}
	}
	if lastSlash > 0 {
		return path[:lastSlash]
	} else {
		return "/"
	}
}

func IsValidPrefix(incomingUrl string, prefix string) bool {
	return len(incomingUrl) >= len(prefix) && incomingUrl[:len(prefix)] == prefix
}
