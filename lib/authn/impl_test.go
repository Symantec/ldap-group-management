package authn

import (
	"errors"
	"fmt"
	//"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	//"os"
	"testing"
	"time"
)

func TestOauth2RedirectHandlerSucccess(t *testing.T) {
	//slogger := stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	//logger := debuglogger.New(slogger)

	authenticator := NewAuthenticator(OpenIDConfig{}, "smallpoint", nil, []string{}, nil, nil)

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	stateString, err := authenticator.generateValidStateString(req)
	if err != nil {
		t.Fatal(err)
	}
	v := url.Values{
		"state": {stateString},
		"code":  {"12345"},
	}
	redirReq, err := http.NewRequest("GET", "/?"+v.Encode(), nil)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "{\"access_token\": \"6789\", \"token_type\": \"Bearer\",\"username\":\"user\"}")
	}))
	defer ts.Close()
	authenticator.netClient = ts.Client()
	authenticator.openID.TokenURL = ts.URL
	authenticator.openID.UserinfoURL = ts.URL

	rr := httptest.NewRecorder()
	authenticator.Oauth2RedirectPathHandler(rr, redirReq)
	if rr.Code != http.StatusFound {
		t.Fatal("Response should have been a redirect")
	}
	resp := rr.Result()
	//body, _ := ioutil.ReadAll(resp.Body)
	//t.Logf("body =%s", string(body))
	if resp.Header.Get("Location") != "/" {
		t.Fatal("Response should have been a redirect to /")
	}

}

func checkRequestHandlerCode(req *http.Request, handlerFunc http.HandlerFunc, expectedStatus int) (*httptest.ResponseRecorder, error) {
	rr := httptest.NewRecorder()
	//l := httpLogger{}
	//handler := NewLoggingHandler(http.HandlerFunc(handlerFunc), l)
	handler := http.HandlerFunc(handlerFunc)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != expectedStatus {
		errStr := fmt.Sprintf("handler returned wrong status code: got %v want %v",
			status, expectedStatus)
		err := errors.New(errStr)
		return nil, err
	}
	return rr, nil
}

func TestGetRemoteUserNameHandler(t *testing.T) {

	authenticator := NewAuthenticator(OpenIDConfig{}, "smallpoint", nil, []string{}, nil, nil)

	// Test with no cookies... inmediate redirect
	urlList := []string{"/", "/static/foo"}
	for _, url := range urlList {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = checkRequestHandlerCode(req, func(w http.ResponseWriter, r *http.Request) {
			_, err := authenticator.GetRemoteUserName(w, r)
			if err == nil {
				t.Fatal("getRemoteUsername should have failed")
			}
		}, http.StatusFound)
		if err != nil {
			t.Fatal(err)
		}

	}

	// Now fail with an unknown cookie
	uknownCookieReq, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	cookieVal, err := randomStringGeneration()
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: AuthCookieName, Value: cookieVal}
	uknownCookieReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(uknownCookieReq, func(w http.ResponseWriter, r *http.Request) {
		_, err := authenticator.getRemoteUserName(w, r)
		if err == nil {
			t.Fatal("getRemoteUsername should have failed")
		}
	}, http.StatusFound)

	//now succeed with known cookie
	expires := time.Now().Add(time.Hour * cookieExpirationHours)
	Cookieinfo := AuthCookie{"username", expires}
	authenticator.authCookie[cookieVal] = Cookieinfo
	knownCookieReq, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	//authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	knownCookieReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(knownCookieReq, func(w http.ResponseWriter, r *http.Request) {
		_, err := authenticator.getRemoteUserName(w, r)
		if err != nil {
			t.Fatal("GetRemoteUsername should have failed")
		}
	}, http.StatusFound)

	//now fail with expired cookie
	expired := time.Now().Add(-1 * time.Hour * cookieExpirationHours)
	Cookieinfo = AuthCookie{"username", expired}
	authenticator.authCookie[cookieVal] = Cookieinfo
	expiredCookieReq, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	expiredCookieReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(expiredCookieReq, func(w http.ResponseWriter, r *http.Request) {
		_, err := authenticator.getRemoteUserName(w, r)
		if err == nil {
			t.Fatal("GetRemoteUsername should have failed")
		}
	}, http.StatusFound)

}
