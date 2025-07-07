package main

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	ttlcache "secure-urls/cache"
	"secure-urls/cookie"
	"secure-urls/utils"
	"strconv"
	"time"

	infrastructurev1alpha1 "github.com/EdgeCDN-X/edgecdnx-controller/api/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"

	"go.uber.org/zap"
	// Import EdgeCDN-X CRDs

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const COOKIE_NAME = "ex-sec-session"

var secureURL = utils.SecureURL{
	Namespace: "",
	Cache:     ttlcache.NewCache[infrastructurev1alpha1.SecureKeySpec](10*time.Minute, 30*time.Minute),
	LogLevel:  "",
}

func validateSignature(r *http.Request) (bool, cookie.CookieBody, string) {
	incomingURL, err := url.Parse(r.Header.Get("X-Original-Url"))

	if err != nil {
		secureURL.Logger.Error("Invalid URL in X-Original-Url", zap.Error(err))
		return false, cookie.CookieBody{}, ""
	}

	q := incomingURL.Query()

	expiryStr := q.Get(utils.EX_EXPIRES)
	keyName := q.Get(utils.EX_KEYNAME)
	sig := q.Get(utils.EX_SIGN)

	if sig == "" || expiryStr == "" || keyName == "" {
		c, err := r.Cookie(COOKIE_NAME)
		if err == nil && c != nil {
			secureURL.Logger.Debug("Secure Cookie found in request", zap.String(COOKIE_NAME, c.Value))

			cookiePayload, signature, err := utils.DecodeCookie(c.Value)

			if err != nil {
				secureURL.Logger.Debug("Failed to decode cookie", zap.Error(err))
				return false, cookie.CookieBody{}, ""
			}

			secureURL.Logger.Debug("Decoded cookie", zap.Any("cookiePayload", cookiePayload), zap.String("signature", hex.EncodeToString(signature)))

			if time.Now().Unix() > cookiePayload.Expires {
				secureURL.Logger.Debug("Cookie expired", zap.Int64("now", time.Now().Unix()), zap.Int64("expiry", cookiePayload.Expires))
				return false, cookie.CookieBody{}, ""
			}

			keyid := fmt.Sprintf("%s.%s", cookiePayload.Service, cookiePayload.KeyName)
			key, ok := secureURL.Cache.Get(keyid)

			if !ok {
				secureURL.Logger.Debug("Key not found in cache", zap.String("key", keyid))
				return false, cookie.CookieBody{}, ""
			}

			incomingURL.Path = utils.StripLastElementFromPath(incomingURL.Path)

			if cookiePayload.URL != incomingURL.Path {
				// TODO support for exact URLs and Parent Path Prefixes
				secureURL.Logger.Debug("Cookie URL does not match incoming URL", zap.String("cookieURL", cookiePayload.URL), zap.String("incomingURL", incomingURL.Path))
				return false, cookie.CookieBody{}, ""
			}

			payload, err := json.Marshal(cookiePayload)
			if err != nil {
				secureURL.Logger.Error("Failed to marshal cookie payload", zap.Error(err))
				return false, cookie.CookieBody{}, ""
			}

			verifySig := utils.SignPayload(payload, key.Value)
			secureURL.Logger.Debug("Cookie signature", zap.String("signature", hex.EncodeToString(verifySig)))
			verified := hmac.Equal(signature, verifySig)

			if verified {
				if time.Until(time.Unix(cookiePayload.Expires, 0)) < 20*time.Minute {
					// Refresh cookie if expires soon
					secureURL.Logger.Debug("Cookie expires in less than 20 minutes. Refreshing session cookie", zap.Int64("expires_in_sec", cookiePayload.Expires-time.Now().Unix()))
					cookiePayload.Expires = time.Now().Unix() + 1*60*60 // Extend expiry by 1 hour
					payload, err = json.Marshal(cookiePayload)
					if err != nil {
						secureURL.Logger.Error("Failed to marshal cookie payload for refresh", zap.Error(err))
						return false, cookie.CookieBody{}, ""
					}
					cookieSig := utils.SignPayload(payload, key.Value)
					secureURL.Logger.Debug("Created new cookie signature", zap.String("signature", hex.EncodeToString(cookieSig)))
					cookie := base64.URLEncoding.EncodeToString(payload) + "." + base64.URLEncoding.EncodeToString(cookieSig)
					secureURL.Logger.Debug("Returning refreshed cookie", zap.String("cookie", cookie))

					return true, cookiePayload, cookie
				}

				return true, cookiePayload, ""
			}

			return false, cookie.CookieBody{}, ""
		}

		secureURL.Logger.Debug("Missing correct query or cookie in request.")
		return false, cookie.CookieBody{}, ""
	} else {
		secureURL.Logger.Debug("Received query params in URL", zap.String("EX-Sign", sig), zap.String("EX-Expires", expiryStr), zap.String("EX-KeyName", keyName))

		expiry, err := strconv.ParseInt(expiryStr, 10, 64)
		if err != nil {
			secureURL.Logger.Debug("Invalid expiry", zap.Error(err))
			return false, cookie.CookieBody{}, ""
		}
		if time.Now().Unix() > expiry {
			secureURL.Logger.Debug("Signature expired", zap.Int64("now", time.Now().Unix()), zap.Int64("expiry", expiry))
			return false, cookie.CookieBody{}, "" // expired
		}

		incomingURL.Path = utils.StripLastElementFromPath(incomingURL.Path)

		// Remove signature from the query params to avoid signing it again
		q.Del("EX-Sign")
		incomingURL.RawQuery = q.Encode()

		secureURL.Logger.Debug("URL to be signed", zap.String("url", incomingURL.String()))
		keyid := fmt.Sprintf("%s.%s", incomingURL.Host, keyName)

		key, ok := secureURL.Cache.Get(keyid)

		if !ok {
			secureURL.Logger.Debug("Key not found in cache", zap.String("key", keyid))
			return false, cookie.CookieBody{}, ""
		}

		// Compute expected signature
		calculatedSig := utils.SignPayload([]byte(incomingURL.String()), key.Value)
		secureURL.Logger.Debug("Calculated URL Signature", zap.String("expected", hex.EncodeToString(calculatedSig)))

		urlSign, err := hex.DecodeString(sig)
		if err != nil {
			secureURL.Logger.Debug("Invalid signature format", zap.Error(err))
			return false, cookie.CookieBody{}, ""
		}

		verified := hmac.Equal(urlSign, calculatedSig)
		secureURL.Logger.Debug("URL Signature valid", zap.Bool("valid", verified))

		if verified {
			cookiePayload := cookie.CookieBody{
				KeyName: keyName,
				Service: incomingURL.Host,
				Expires: time.Now().Unix() + 1*60*60,
				URL:     incomingURL.Path,
			}

			payload, err := json.Marshal(cookiePayload)
			if err != nil {
				secureURL.Logger.Error("Failed to marshal cookie payload", zap.Error(err))
				return false, cookie.CookieBody{}, ""
			}

			cookieSig := utils.SignPayload(payload, key.Value)
			secureURL.Logger.Debug("Created cookie signature", zap.String("signature", hex.EncodeToString(cookieSig)))

			cookie := base64.URLEncoding.EncodeToString(payload) + "." + base64.URLEncoding.EncodeToString(cookieSig)
			return verified, cookiePayload, cookie
		}

		return verified, cookie.CookieBody{}, ""
	}
}

func requestHandler(w http.ResponseWriter, r *http.Request) {

	secureURL.Logger.Debug("--- Incoming Request ---",
		zap.String("url", r.URL.String()),
		zap.String("path", r.URL.Path),
		zap.Any("query_params", r.URL.Query()),
	)
	secureURL.Logger.Debug("Headers", zap.Any("headers", r.Header))
	secureURL.Logger.Debug("------------------------")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		secureURL.Logger.Info("Method not allowed", zap.String("method", r.Method))
		return
	}

	valid, cookiePayload, cookie := validateSignature(r)

	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		secureURL.Logger.Info("Unauthorized: invalid or expired signature")
		return
	}

	secureURL.Logger.Info("valid signature", zap.Any("cookiePayload", cookiePayload), zap.String("cookie", cookie))

	if cookie != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     COOKIE_NAME,
			Value:    cookie,
			Path:     cookiePayload.URL,
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		})
	}

	w.Write([]byte("Request details logged to stdout.\n"))
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	// TODO response once cache is synced
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

func setupK8sClient() (*dynamic.DynamicClient, error) {
	scheme := kruntime.NewScheme()
	clientsetscheme.AddToScheme(scheme)
	infrastructurev1alpha1.AddToScheme(scheme)

	var config *rest.Config
	var err error

	// Try in-cluster config
	config, err = rest.InClusterConfig()
	if err != nil {
		secureURL.Logger.Info("Falling back to kubeconfig", zap.Error(err))
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, _ := os.UserHomeDir()
			kubeconfig = home + "/.kube/config"
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			secureURL.Logger.Error("Failed to load kubeconfig", zap.Error(err))
			return nil, err
		}
	}

	clientset, err := dynamic.NewForConfig(config)
	if err != nil {
		secureURL.Logger.Error("Failed to create k8s client", zap.Error(err))
		return nil, err
	}
	secureURL.Logger.Info("Kubernetes client initialized")
	return clientset, nil
}

func main() {
	flag.StringVar(&secureURL.Namespace, "namespace", "", "Namespace for the application")
	flag.StringVar(&secureURL.LogLevel, "log-level", "info", "Log level: debug, info, warn, error")
	flag.Parse()

	var err error

	level := utils.ParseLogLevel(secureURL.LogLevel)
	logger := utils.NewLogger(level)
	secureURL.Logger = logger
	defer logger.Sync()

	clientset, err := setupK8sClient()
	if err != nil {
		logger.Fatal("Could not set up Kubernetes client", zap.Error(err))
	}
	_ = clientset // Use or remove as needed

	fac := dynamicinformer.NewFilteredDynamicSharedInformerFactory(clientset, 5*time.Minute, secureURL.Namespace, nil)

	informer := fac.ForResource(schema.GroupVersionResource{
		Group:    infrastructurev1alpha1.GroupVersion.Group,
		Version:  infrastructurev1alpha1.GroupVersion.Version,
		Resource: "services",
	}).Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			service_raw := obj.(*unstructured.Unstructured)
			temp, _ := json.Marshal(service_raw.Object)
			service := &infrastructurev1alpha1.Service{}
			json.Unmarshal(temp, service)
			for _, key := range service.Spec.SecureKeys {
				logger.Info("Adding key to cache", zap.String("key", fmt.Sprintf("%s.%s", service.Spec.Domain, key.Name)))
				secureURL.Cache.Set(fmt.Sprintf("%s.%s", service.Spec.Domain, key.Name), key)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldService_raw := oldObj.(*unstructured.Unstructured)
			newService_raw := newObj.(*unstructured.Unstructured)
			temp, _ := json.Marshal(oldService_raw.Object)
			oldService := &infrastructurev1alpha1.Service{}
			json.Unmarshal(temp, oldService)
			temp, _ = json.Marshal(newService_raw.Object)
			newService := &infrastructurev1alpha1.Service{}
			json.Unmarshal(temp, newService)
			for _, key := range oldService.Spec.SecureKeys {
				logger.Info("Deleting key from cache", zap.String("key", fmt.Sprintf("%s.%s", oldService.Spec.Domain, key.Name)))
				secureURL.Cache.Delete(fmt.Sprintf("%s.%s", oldService.Spec.Domain, key.Name))
			}
			for _, key := range newService.Spec.SecureKeys {
				logger.Info("Adding key to cache", zap.String("key", fmt.Sprintf("%s.%s", newService.Spec.Domain, key.Name)))
				secureURL.Cache.Set(fmt.Sprintf("%s.%s", newService.Spec.Domain, key.Name), key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			service_raw := obj.(*unstructured.Unstructured)
			temp, _ := json.Marshal(service_raw.Object)
			service := &infrastructurev1alpha1.Service{}
			json.Unmarshal(temp, service)
			for _, key := range service.Spec.SecureKeys {
				logger.Info("Deleting key from cache", zap.String("key", fmt.Sprintf("%s.%s", service.Spec.Domain, key.Name)))
				secureURL.Cache.Delete(fmt.Sprintf("%s.%s", service.Spec.Domain, key.Name))
			}
		},
	})

	factoryCloseChan := make(chan struct{})
	fac.Start(factoryCloseChan)

	http.HandleFunc("/", requestHandler)
	http.HandleFunc("/healthz", healthzHandler)
	logger.Info("Server listening", zap.String("address", "http://localhost:8080"))
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}
