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

func TestCreateGrouphandler(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	cookie := testCreateValidCookie()
	req, err := http.NewRequest("POST", creategroupPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.createGrouphandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

/*
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
*/

/*
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
*/
