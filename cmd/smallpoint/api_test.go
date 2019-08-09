package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Symantec/ldap-group-management/lib/userinfo/mock"
)

const (
	usergroupsTestPath   = "/user_groups/?username=user1"
	groupusersTestPath   = "/group_users/?groupname=group1"
	adminCookievalueTest = "hellogroup1group2"
	adminTestusername    = "user1"
	cookievalueTest      = "somecookie"
	testUsername         = "userX"
	testdbpath           = "sqlite:./test-sqlite3.db"
)

func testCreateValidCookie() http.Cookie {
	expiresAt := time.Now().Add(time.Hour * cookieExpirationHours)
	cookie := http.Cookie{Name: cookieName, Value: cookievalueTest, Path: indexPath, Expires: expiresAt, HttpOnly: true, Secure: true}
	return cookie
}

func testCreateValidAdminCookie() http.Cookie {
	expiresAt := time.Now().Add(time.Hour * cookieExpirationHours)
	cookie := http.Cookie{Name: cookieName, Value: adminCookievalueTest, Path: indexPath, Expires: expiresAt, HttpOnly: true, Secure: true}
	return cookie
}

func setupTestState() (RuntimeState, error) {
	var state RuntimeState
	state.Config.Base.StorageURL = testdbpath
	err := initDB(&state)
	if err != nil {
		return state, err
	}
	mockldap := mock.New()
	state.Userinfo = mockldap
	state.authcookies = make(map[string]cookieInfo)
	expiresAt := time.Now().Add(time.Hour * cookieExpirationHours)
	usersession := cookieInfo{Username: testUsername, ExpiresAt: expiresAt}
	state.authcookies[cookievalueTest] = usersession
	adminSession := cookieInfo{Username: adminTestusername, ExpiresAt: expiresAt}
	state.authcookies[adminCookievalueTest] = adminSession
	state.loadTemplates()
	return state, nil
}
func getTestApiEndpints(state *RuntimeState) map[string]http.HandlerFunc {
	testApiEndpoints := map[string]http.HandlerFunc{
		creategroupPath:          state.createGrouphandler,
		deletegroupPath:          state.deleteGrouphandler,
		createServiceAccountPath: state.createServiceAccounthandler,
	}
	return testApiEndpoints
}

func getAdminOnlyEndpoints(state *RuntimeState) map[string]http.HandlerFunc {
	adminOnlyApiEndpoints := map[string]http.HandlerFunc{
		creategroupPath:           state.createGrouphandler,
		deletegroupPath:           state.deleteGrouphandler,
		createServiceAccountPath:  state.createServiceAccounthandler,
		changeownershipbuttonPath: state.changeownership,
	}
	return adminOnlyApiEndpoints
}

func TestMethodsForApiEndPoints(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	apiTestPoints := getTestApiEndpints(&state)
	cookie := testCreateValidCookie()
	for path, testFunc := range apiTestPoints {
		req, err := http.NewRequest("GET", path, nil)
		if err != nil {
			t.Fatal(err)
		}
		//cookie := testCreateValidCookie()
		req.AddCookie(&cookie)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(testFunc)

		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusMethodNotAllowed {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}
	}

}

func TestAdminOnlyAuthnEndpoints(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	adminTestPoints := getAdminOnlyEndpoints(&state)
	cookie := testCreateValidCookie()
	for path, testFunc := range adminTestPoints {
		req, err := http.NewRequest("POST", path, nil)
		if err != nil {
			t.Fatal(err)
		}
		//cookie := testCreateValidCookie()
		req.AddCookie(&cookie)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(testFunc)

		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusForbidden {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusForbidden)
		}
	}

	adminCookie := testCreateValidAdminCookie()
	for path, testFunc := range adminTestPoints {
		req, err := http.NewRequest("POST", path, nil)
		if err != nil {
			t.Fatal(err)
		}
		//cookie := testCreateValidCookie()
		req.AddCookie(&adminCookie)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(testFunc)

		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusBadRequest)
		}
	}
}

func TestCreateGrouphandlerSuccess(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	formValues := url.Values{"groupname": {"foo"}, "description": {"group1"}, "members": {"user1"}}
	//formString := strings.NewReader(formValues.Encode())
	req, err := http.NewRequest("POST", creategroupPath, strings.NewReader(formValues.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidAdminCookie()
	req.AddCookie(&cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.createGrouphandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}

func TestCreateDrouphandlerSuccess(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	formValues := url.Values{"groupnames": {"group1"}}
	//formString := strings.NewReader(formValues.Encode())
	req, err := http.NewRequest("POST", deletegroupPath, strings.NewReader(formValues.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidAdminCookie()
	req.AddCookie(&cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.deleteGrouphandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}
