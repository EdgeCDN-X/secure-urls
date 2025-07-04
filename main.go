package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	ttlcache "secure-urls/cache"
	"strconv"
	"time"

	infrastructurev1alpha1 "github.com/EdgeCDN-X/edgecdnx-controller/api/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"

	"go.uber.org/zap"
	// Import EdgeCDN-X CRDs

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
)

var logger *zap.Logger

type SecureUrlConfig struct {
	Namespace string `json:"namespace"`
	Cache     *ttlcache.Cache[infrastructurev1alpha1.SecureKeySpec]
}

type CookieBody struct {
	KeyName string `json:"keyName"`
	Expires int64  `json:"expires"`
	Service string `json:"service"`
}

var c = SecureUrlConfig{
	Namespace: "",
	Cache:     ttlcache.NewCache[infrastructurev1alpha1.SecureKeySpec](10*time.Minute, 30*time.Minute),
}

func validateSignature(r *http.Request) (bool, string) {

	incomingURL, err := url.Parse(r.Header.Get("X-Original-Url"))

	if err != nil {
		logger.Debug("Invalid URL in X-Original-Url", zap.Error(err))
		return false, ""
	}

	q := incomingURL.Query()

	expiryStr := q.Get("EX-Expires")
	keyName := q.Get("EX-KeyName")
	sig := q.Get("EX-Sign")

	logger.Debug("Received expiry, keyname and signature", zap.String("EX-Sign", sig), zap.String("EX-Expires", expiryStr), zap.String("EX-KeyName", keyName))
	if sig == "" || expiryStr == "" {
		logger.Debug("Missing signature or expiry in query params")
		return false, ""
	}

	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		logger.Debug("Invalid expiry", zap.Error(err))
		return false, ""
	}
	if time.Now().Unix() > expiry {
		logger.Debug("Signature expired", zap.Int64("now", time.Now().Unix()), zap.Int64("expiry", expiry))
		return false, "" // expired
	}

	// Remove signature from the query params
	q.Del("EX-Sign")
	incomingURL.RawQuery = q.Encode()

	logger.Debug("URL to be signed", zap.String("url", incomingURL.String()))

	keyid := fmt.Sprintf("%s.%s", incomingURL.Host, keyName)

	key, ok := c.Cache.Get(keyid)

	if !ok {
		logger.Debug("Key not found in cache", zap.String("key", keyid))
		return false, ""
	}

	// Compute expected signature
	mac := hmac.New(sha256.New, []byte(key.Value))
	mac.Write([]byte(incomingURL.String()))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	logger.Debug("Expected signature", zap.String("expected", expectedSig))

	verified := hmac.Equal([]byte(sig), []byte(expectedSig))
	logger.Debug("Signature valid", zap.Bool("valid", verified))

	if verified {
		cookiePayload := CookieBody{
			KeyName: keyid,
			Service: incomingURL.Host,
			Expires: time.Now().Unix() + 1*60*60, // 1 hour
		}

		payload, err := json.Marshal(cookiePayload)
		if err != nil {
			logger.Error("Failed to marshal cookie payload", zap.Error(err))
			return false, ""
		}

		cookiemac := hmac.New(sha256.New, []byte(key.Value))
		cookiemac.Write(payload)

		cookiesignature := mac.Sum(nil)
		cookie := base64.URLEncoding.EncodeToString(payload) + "." + base64.URLEncoding.EncodeToString(cookiesignature)

		return verified, cookie
	}

	return verified, ""
}

func handler(w http.ResponseWriter, r *http.Request) {

	logger.Info("--- Incoming Request ---",
		zap.String("url", r.URL.String()),
		zap.String("path", r.URL.Path),
		zap.Any("query_params", r.URL.Query()),
	)
	logger.Info("Headers", zap.Any("headers", r.Header))
	logger.Info("------------------------")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		logger.Info("Method not allowed", zap.String("method", r.Method))
		return
	}

	valid, cookie := validateSignature(r)

	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		logger.Info("Unauthorized: invalid or expired signature")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "EX-Cookie",
		Value:    cookie,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

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
		logger.Info("Falling back to kubeconfig", zap.Error(err))
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, _ := os.UserHomeDir()
			kubeconfig = home + "/.kube/config"
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			logger.Error("Failed to load kubeconfig", zap.Error(err))
			return nil, err
		}
	}

	clientset, err := dynamic.NewForConfig(config)
	if err != nil {
		logger.Error("Failed to create k8s client", zap.Error(err))
		return nil, err
	}
	logger.Info("Kubernetes client initialized")
	return clientset, nil
}

func main() {
	flag.StringVar(&c.Namespace, "namespace", "", "Namespace for the application")
	flag.Parse()

	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		log.Fatalf("Failed to initialize zap logger: %v", err)
	}
	defer logger.Sync()

	clientset, err := setupK8sClient()
	if err != nil {
		logger.Fatal("Could not set up Kubernetes client", zap.Error(err))
	}
	_ = clientset // Use or remove as needed

	fac := dynamicinformer.NewFilteredDynamicSharedInformerFactory(clientset, 5*time.Minute, c.Namespace, nil)

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
				c.Cache.Set(fmt.Sprintf("%s.%s", service.Spec.Domain, key.Name), key)
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
				c.Cache.Delete(fmt.Sprintf("%s.%s", oldService.Spec.Domain, key.Name))
			}
			for _, key := range newService.Spec.SecureKeys {
				logger.Info("Adding key to cache", zap.String("key", fmt.Sprintf("%s.%s", newService.Spec.Domain, key.Name)))
				c.Cache.Set(fmt.Sprintf("%s.%s", newService.Spec.Domain, key.Name), key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			service_raw := obj.(*unstructured.Unstructured)
			temp, _ := json.Marshal(service_raw.Object)
			service := &infrastructurev1alpha1.Service{}
			json.Unmarshal(temp, service)
			for _, key := range service.Spec.SecureKeys {
				logger.Info("Deleting key from cache", zap.String("key", fmt.Sprintf("%s.%s", service.Spec.Domain, key.Name)))
				c.Cache.Delete(fmt.Sprintf("%s.%s", service.Spec.Domain, key.Name))
			}
		},
	})

	factoryCloseChan := make(chan struct{})
	fac.Start(factoryCloseChan)

	http.HandleFunc("/", handler)
	http.HandleFunc("/healthz", healthzHandler)
	logger.Info("Server listening", zap.String("address", "http://localhost:8080"))
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}
