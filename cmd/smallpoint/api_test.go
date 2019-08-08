package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Symantec/ldap-group-management/lib/userinfo/mock"
)

const (
	usergroupsTestPath = "/user_groups/?username=user1"
	groupusersTestPath = "/group_users/?groupname=group1"
	cookievalueTest    = "hellogroup1group2"
	testusername       = "user1"
	testdbpath         = "sqlite:./test-sqlite3.db"
)

func testCreateValidCookie() http.Cookie {
	expiresAt := time.Now().Add(time.Hour * cookieExpirationHours)
	cookie := http.Cookie{Name: cookieName, Value: cookievalueTest, Path: indexPath, Expires: expiresAt, HttpOnly: true, Secure: true}
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
	usersession := cookieInfo{Username: testusername, ExpiresAt: expiresAt}
	state.authcookies[cookievalueTest] = usersession
	state.loadTemplates()
	return state, nil
}

func TestRuntimeState_getallgroupsHandler(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET", allgroupsPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.getallgroupsHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}
func TestRuntimeState_getusersingroupHandlerFail(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET", groupusersPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.getusersingroupHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}

}

func TestRuntimeState_getusersingroupHandlerSuccess(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET", groupusersTestPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.getusersingroupHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}

func TestRuntimeState_getgroupsofuserHandlerFail(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET", usergroupsPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.getgroupsofuserHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}

}

func TestRuntimeState_getgroupsofuserHandlerSuccess(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET", usergroupsTestPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.getgroupsofuserHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}

func TestRuntimeState_getallusersHandler(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET", allusersPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.getallusersHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}
