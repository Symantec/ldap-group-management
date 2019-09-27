package auth

import (
	"bytes"
	/*
		"crypto/rand"
		"encoding/base64"
		"encoding/json"
		"io/ioutil"
	i*/
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	/*
		"github.com/Symantec/cloud-gate/lib/constants"
	*/)

type oauth2StateJWT struct {
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   []string `json:"aud,omitempty"`
	Expiration int64    `json:"exp,omitempty"`
	NotBefore  int64    `json:"nbf,omitempty"`
	IssuedAt   int64    `json:"iat,omitempty"`
	ReturnURL  string   `json:"return_url,omitempty"`
}

type accessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:expires_in`
	IDToken     string `json:"id_token"`
}

type openidConnectUserInfo struct {
	Subject           string `json:"sub"`
	Name              string `json:"name"`
	Login             string `json:"login,omitempty"`
	Username          string `json:"username,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
}

const oauth2redirectPath = "/oauth2/redirect"

func (s *RuntimeState) getRedirURL(r *http.Request) string {
	return "https://" + r.Host + oauth2redirectPath
}

func (s *RuntimeState) generateAuthCodeURL(state string, r *http.Request) string {
	var buf bytes.Buffer
	buf.WriteString(s.Config.OpenID.AuthURL)
	redirectURL := s.getRedirURL(r)
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {s.Config.OpenID.ClientID},
		"scope":         {s.Config.OpenID.Scopes},
		"redirect_uri":  {redirectURL},
	}

	if state != "" {
		// TODO(light): Docs say never to omit state; don't allow empty.
		v.Set("state", state)
	}
	if strings.Contains(s.Config.OpenID.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

const redirCookieName = "redir_cookie"
const maxAgeSecondsRedirCookie = 300

func (s *RuntimeState) generateValidStateString(r *http.Request) (string, error) {
	key := []byte(s.Config.Base.SharedSecrets[0])
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		log.Printf("New jose signer error err: %s", err)
		return "", err
	}
	issuer := "smallpoint"
	subject := "state:" + redirCookieName
	now := time.Now().Unix()
	stateToken := oauth2StateJWT{Issuer: issuer,
		Subject:    subject,
		Audience:   []string{issuer},
		ReturnURL:  r.URL.String(),
		NotBefore:  now,
		IssuedAt:   now,
		Expiration: now + maxAgeSecondsRedirCookie}
	return jwt.Signed(sig).Claims(stateToken).CompactSerialize()
}

// This is where the redirect to the oath2 provider is computed.
func (s *RuntimeState) oauth2DoRedirectoToProviderHandler(w http.ResponseWriter, r *http.Request) {
	stateString, err := s.generateValidStateString(r)
	if err != nil {
		log.Printf("Error from generateValidStateString err: %s\n", err)
		http.Error(w, "Internal Error ", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.generateAuthCodeURL(stateString, r), http.StatusFound)
}

// Next are the functions for checking the callback
func (s *RuntimeState) JWTClaims(t *jwt.JSONWebToken, dest ...interface{}) (err error) {
	for _, key := range s.Config.Base.SharedSecrets {
		binkey := []byte(key)
		err = t.Claims(binkey, dest...)
		if err == nil {
			return nil
		}
	}
	if err != nil {
		return err
	}
	return errors.New("No valid key found")
}

func getUsernameFromUserinfo(userInfo openidConnectUserInfo) string {
	username := userInfo.Username
	if len(username) < 1 {
		username = userInfo.Login
	}
	if len(username) < 1 {
		username = userInfo.PreferredUsername
	}
	if len(username) < 1 {
		username = userInfo.Email
	}
	return username
}

/*
func (s *Server) getBytesFromSuccessfullPost(url string, data url.Values) ([]byte, error) {
        response, err := s.netClient.PostForm(url, data)
        if err != nil {
                s.logger.Debugf(1, "client post error err: %s\n", err)
                return nil, err
        }
        defer response.Body.Close()

        responseBody, err := ioutil.ReadAll(response.Body)
        if err != nil {
                s.logger.Debugf(1, "Error reading http responseBody err: %s\n", err)
                return nil, err
        }

        if response.StatusCode >= 300 {
                s.logger.Debugf(1, string(responseBody))
                return nil, errors.New("invalid status code")
        }
        return responseBody, nil
}
*/
