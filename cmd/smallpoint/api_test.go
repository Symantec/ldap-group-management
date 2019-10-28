package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Symantec/ldap-group-management/lib/authn"
	"github.com/Symantec/ldap-group-management/lib/userinfo/mock"
)

const (
	usergroupsTestPath   = "/user_groups/?username=user1"
	groupusersTestPath   = "/group_users/?groupname=group1"
	adminCookievalueTest = "hellogroup1group2"
	adminTestusername    = "user1"
	cookievalueTest      = "somecookie"
	testUsername         = "user2"
	testdbpath           = "sqlite:./test-sqlite3.db"
)

func testGenValidCookie(authenticator *authn.Authenticator, username string) http.Cookie {
	expiresAt := time.Now().Add(time.Hour * cookieExpirationHours)
	cookieValue, err := authenticator.GenUserCookieValue(username, expiresAt)
	if err != nil {
		panic(err)
	}
	cookie := http.Cookie{Name: authn.AuthCookieName, Value: cookieValue, Path: indexPath, Expires: expiresAt, HttpOnly: true, Secure: true}
	return cookie
}

func testCreateValidCookie(authenticator *authn.Authenticator) http.Cookie {
	return testGenValidCookie(authenticator, testUsername)
}

func testCreateValidAdminCookie(authenticator *authn.Authenticator) http.Cookie {
	return testGenValidCookie(authenticator, adminTestusername)
}

func mockPermissionDB(state RuntimeState) error {
	var insertStmt = `insert into permissions(groupname, resource_type, resource, permission) values (?,?,?,?);`
	stmt, err := state.db.Prepare(insertStmt)
	if err != nil {
		log.Print("Error preparing statement" + insertStmt)
		log.Fatal(err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec("group3", "group", "group1", 2)
	if err != nil {
		return err
	}
	_, err = stmt.Exec("group3", "service_account", "new_svc_account", 0)
	if err != nil {
		return err
	}
	_, err = stmt.Exec("group3", "group", "group1", 0)
	if err != nil {
		return err
	}
	_, err = stmt.Exec("group3", "group", "foo", 0)
	if err != nil {
		return err
	}
	return nil
}

func setupTestState() (RuntimeState, error) {
	var state RuntimeState
	state.Config.Base.StorageURL = testdbpath
	err := initDB(&state)
	if err != nil {
		return state, err
	}
	mockPermissionDB(state)
	mockldap := mock.New()
	state.Userinfo = mockldap
	state.UserSourceinfo = mockldap
	state.allUsersCacheValue = make(map[string]time.Time)
	state.pendingUserActionsCache = make(map[string]pendingUserActionsCacheEntry)
	state.authenticator = authn.NewAuthenticator(state.Config.OpenID, "smallpoint", nil,
		[]string{}, nil,
		nil)
	//state.authenticator.SetExplicitAuthCookie(cookievalueTest, testUsername)
	//state.authenticator.SetExplicitAuthCookie(adminCookievalueTest, adminTestusername)

	state.Config.Base.TemplatesPath = "."
	log.Printf("before loading templates")
	err = state.loadTemplates()
	if err != nil {
		return state, err
	}
	log.Printf("after loading templates")
	return state, nil
}
func getTestApiEndpoints(state *RuntimeState) map[string]http.HandlerFunc {
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
	apiTestPoints := getTestApiEndpoints(&state)
	cookie := testCreateValidCookie(state.authenticator)
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
	cookie := testCreateValidCookie(state.authenticator)
	for path, testFunc := range adminTestPoints {
		var formValues url.Values
		if strings.Contains(path, "service") {
			formValues = url.Values{"AccountName": {"new_svc_account"}, "mail": {"alice@example.com"}, "loginShell": {"/bin/false"}}
		} else if strings.Contains(path, "delete") {
			formValues = url.Values{"groupnames": {"group1"}}
		} else {
			formValues = url.Values{"groupname": {"group1"}}
		}

		req, err := http.NewRequest("POST", path, strings.NewReader(formValues.Encode()))
		if err != nil {
			t.Fatal(err)
		}

		//cookie := testCreateValidCookie()
		req.AddCookie(&cookie)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(testFunc)

		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusForbidden {
			t.Errorf("%v handler returned wrong status code: got %v want %v",
				path, status, http.StatusForbidden)
		}
	}

	// This one should fail due to missing form
	adminCookie := testCreateValidAdminCookie(state.authenticator)
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
	// This one should fail due to CSRF detection
	for path, testFunc := range adminTestPoints {
		req, err := http.NewRequest("POST", "https://foobar.com"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&adminCookie)
		req.Header.Set("Referer", "https://evilsite.com")

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(testFunc)

		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusUnauthorized)
		}
	}
}

func TestCreateGrouphandlerSuccess(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		t.Fatal(err)
	}
	formValues := url.Values{"groupname": {"foo"}, "description": {"group1"}, "members": {"user1"}}
	//formString := strings.NewReader(formValues.Encode())
	req, err := http.NewRequest("POST", creategroupPath, strings.NewReader(formValues.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidAdminCookie(state.authenticator)
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
	cookie := testCreateValidAdminCookie(state.authenticator)
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

func TestCreateServiceAccounthandlerSuccess(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	formValues := url.Values{"AccountName": {"new_svc_account"}, "mail": {"alice@example.com"}, "loginShell": {"/bin/false"}}
	//formString := strings.NewReader(formValues.Encode())
	log.Println(formValues)
	req, err := http.NewRequest("POST", createServiceAccountPath, strings.NewReader(formValues.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidAdminCookie(state.authenticator)
	req.AddCookie(&cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.createServiceAccounthandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestChangeownershipSuccess(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	formValues := url.Values{"groupnames": {"group1"}, "managegroup": {"group1"}}
	//formString := strings.NewReader(formValues.Encode())
	req, err := http.NewRequest("POST", changeownershipbuttonPath, strings.NewReader(formValues.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidAdminCookie(state.authenticator)
	req.AddCookie(&cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.changeownership)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestGetGroupsJSHandler(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	var groupTypes = []string{"invalid", "all", "pendingRequests", "allNoManager", "pendingActions", "managedByMe"}
	for _, groupType := range groupTypes {
		req, err := http.NewRequest("GET", getGroupsJSPath+"?type="+groupType, nil)
		if err != nil {
			t.Fatal(err)
		}
		cookie := testCreateValidCookie(state.authenticator)
		req.AddCookie(&cookie)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(state.getGroupsJSHandler)

		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}
	}
}

func TestGetUsersJSHandler(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	var testParams = []string{"foo=bar", "encoding=json", "type=group&groupName=group1"}
	for _, param := range testParams {
		req, err := http.NewRequest("GET", getUsersJSPath+"?"+param, nil)
		if err != nil {
			t.Fatal(err)
		}
		cookie := testCreateValidCookie(state.authenticator)
		req.AddCookie(&cookie)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(state.getUsersJSHandler)

		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}
	}
}
