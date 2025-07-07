package cookie

type CookieBody struct {
	KeyName string `json:"keyName"`
	Expires int64  `json:"expires"`
	Service string `json:"service"`
	URL     string `json:"url"`
}
