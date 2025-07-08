package cookie

type CookieBody struct {
	KeyName   string `json:"keyName"`
	Expires   int64  `json:"expires"`
	Service   string `json:"service"`
	URLPrefix string `json:"url,omitempty"`
}
