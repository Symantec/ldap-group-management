package authn

import (
	"log"
	"net/http"
	"os"
	"time"
)

type OpenIDConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	ProviderURL  string `yaml:"provider_url"`
	AuthURL      string `yaml:"auth_url"`
	TokenURL     string `yaml:"token_url"`
	UserinfoURL  string `yaml:"userinfo_url"`
	Scopes       string `yaml:"scopes"`
}

type AuthCookie struct {
	Username  string
	ExpiresAt time.Time
}

type SetHeadersFunc func(w http.ResponseWriter) error

type Authenticator struct {
	openID         OpenIDConfig
	sharedSecrets  []string
	appName        string
	netClient      *http.Client
	logger         *log.Logger
	setHeadersFunc SetHeadersFunc
}

const Oauth2redirectPath = "/oauth2/redirect"
const AuthCookieName = "authn_cookie"

const secsBetweenCleanup = 30

func NewAuthenticator(config OpenIDConfig, appName string, netClient *http.Client,
	sharedSecrets []string, logger *log.Logger,
	setHeadersFunc SetHeadersFunc) *Authenticator {
	authenticator := Authenticator{
		openID:         config,
		appName:        appName,
		sharedSecrets:  sharedSecrets,
		netClient:      netClient,
		logger:         logger,
		setHeadersFunc: setHeadersFunc}
	if logger == nil {
		authenticator.logger = log.New(os.Stdout, appName, log.LstdFlags)
	}
	if netClient == nil {
		authenticator.netClient = http.DefaultClient
	}
	if len(sharedSecrets) < 1 {
		randString, err := randomStringGeneration()
		if err != nil {
			panic(err)
		}
		authenticator.sharedSecrets = append(authenticator.sharedSecrets, randString)
	}
	return &authenticator
}

func (a *Authenticator) GetRemoteUserName(w http.ResponseWriter, r *http.Request) (string, error) {
	return a.getRemoteUserName(w, r)
}
func (a *Authenticator) Oauth2RedirectPathHandler(w http.ResponseWriter, r *http.Request) {
	a.oauth2RedirectPathHandler(w, r)
}

// This function is only for testing purposes, should not be used in prod
func (a *Authenticator) GenUserCookieValue(username string, expires time.Time) (string, error) {
	return a.genUserCookieValue(username, expires)
}
