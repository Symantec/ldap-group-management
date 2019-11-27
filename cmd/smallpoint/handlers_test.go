package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNonAdminWebPathsHandlerSuccess(t *testing.T) {

	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	validTestGroupInfoPath := groupinfoPath + "?groupname=group1"
	testWebEndpoints := map[string]http.HandlerFunc{
		indexPath:                  state.mygroupsHandler,
		allLDAPgroupsPath:          state.allGroupsHandler,
		myManagedGroupsWebPagePath: state.myManagedGroupsHandler,
		pendingactionsPath:         state.pendingActions,
		pendingrequestsPath:        state.pendingRequests,
		addmembersPath:             state.addmemberstoGroupWebpageHandler,
		deletemembersPath:          state.deletemembersfromGroupWebpageHandler,
		validTestGroupInfoPath:     state.groupInfoWebpage,
		// The next two should be admin paths, but not now,
		creategroupWebPagePath: state.creategroupWebpageHandler,
		deletegroupWebPagePath: state.deletegroupWebpageHandler,
	}

	//nonAdminWebPaths := []string{indexPath}
	cookie := testCreateValidCookie(state.authenticator)

	for path, testFunc := range testWebEndpoints {
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
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}
	}

	//now test with explicit accept for web browser
	for path, testFunc := range testWebEndpoints {
		req, err := http.NewRequest("GET", path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&cookie)
		req.Header.Set("Accept", "text/html")

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(testFunc)

		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}
	}

	//now ensure unathenticated failed
	for path, testFunc := range testWebEndpoints {
		req, err := http.NewRequest("GET", path, nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(testFunc)

		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusFound {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}
	}
}

func TestAdminOnlyWebPaths(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	testWebEndpoints := map[string]http.HandlerFunc{
		permissionmanageWebPagePath: state.permissionmanageWebpageHandler,
	}

	adminCookie := testCreateValidAdminCookie(state.authenticator)

	for path, testFunc := range testWebEndpoints {
		req, err := http.NewRequest("GET", path, nil)
		if err != nil {
			t.Fatal(err)
		}
		//cookie := testCreateValidCookie()
		req.AddCookie(&adminCookie)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(testFunc)

		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}
	}

	cookie := testCreateValidCookie(state.authenticator)

	for path, testFunc := range testWebEndpoints {
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
		if status := rr.Code; status != http.StatusForbidden {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusForbidden)
		}
	}
	//now ensure unathenticated failed
	for path, testFunc := range testWebEndpoints {
		req, err := http.NewRequest("GET", path, nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(testFunc)

		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusFound {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}
	}
}

func TestRequestAccessHandler(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	//formValues := url.Values{"groupnames": {"group1"}, "managegroup": {"group1"}}
	//req, err := http.NewRequest("POST", changeownershipbuttonPath, strings.NewReader(formValues.Encode()))
	requestData := map[string][]string{
		"groups": []string{"group3"},
	}
	jsonBytes, err := json.Marshal(requestData)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", changeownershipbuttonPath, bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidCookie(state.authenticator) //testCreateValidAdminCookie()
	req.AddCookie(&cookie)
	//This is actually not neded
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.requestAccessHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	////Now we test the delete request

	delReq, err := http.NewRequest("POST", deleterequestsPath, bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatal(err)
	}
	delReq.AddCookie(&cookie)
	delReq.Header.Set("Content-Type", "application/json")

	rr2 := httptest.NewRecorder()
	handler2 := http.HandlerFunc(state.deleteRequests)

	handler2.ServeHTTP(rr2, delReq)
	// Check the status code is what we expect.
	if status := rr2.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

// This should probably go into another func
func TestAddmemberstoExistingGroupSuccess(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Println(err)
	}
	smtpClient = func(addr string) (smtpDialer, error) {
		client := &smtpDialerMock{}
		return client, nil
	}

	formValues := url.Values{"groupname": {"group1"}, "members": {"user1"}}
	req, err := http.NewRequest("POST", addmembersbuttonPath, strings.NewReader(formValues.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidAdminCookie(state.authenticator)
	req.AddCookie(&cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.addmemberstoExistingGroup)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}

func TestApproveHandler(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Fatal(err)
	}
	smtpClient = func(addr string) (smtpDialer, error) {
		client := &smtpDialerMock{}
		return client, nil
	}
	//Need to add a request to the DB
	err = insertRequestInDB("user2", []string{"group3"}, &state)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: Consistency is not our forte here
	requestData := map[string][][]string{
		"groups": [][]string{[]string{"user2", "group3"}},
	}
	jsonBytes, err := json.Marshal(requestData)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", approverequestPath, bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidCookie(state.authenticator) //testCreateValidAdminCookie()
	req.AddCookie(&cookie)
	//This is actually not neded
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.approveHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestRejectHandler(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Fatal(err)
	}
	smtpClient = func(addr string) (smtpDialer, error) {
		client := &smtpDialerMock{}
		return client, nil
	}
	//Need to add a request to the DB
	err = insertRequestInDB("user2", []string{"group3"}, &state)
	if err != nil {
		log.Fatal(err)
	}
	// TODO: Consistency is not our forte here
	requestData := map[string][][]string{
		"groups": [][]string{[]string{"user2", "group3"}},
	}
	jsonBytes, err := json.Marshal(requestData)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", rejectrequestPath, bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidCookie(state.authenticator) //testCreateValidAdminCookie()
	req.AddCookie(&cookie)
	//This is actually not neded
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.rejectHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestExitfromGroup(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Fatal(err)
	}
	smtpClient = func(addr string) (smtpDialer, error) {
		client := &smtpDialerMock{}
		return client, nil
	}
	// TODO: Consistency is not our forte here
	requestData := map[string][]string{
		"groups": []string{"group1"},
	}
	jsonBytes, err := json.Marshal(requestData)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", exitgroupPath, bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidCookie(state.authenticator) //testCreateValidAdminCookie()
	req.AddCookie(&cookie)
	//This is actually not neded
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.exitfromGroup)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}

func TestDeletemembersfromExistingGroupMinimal(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Fatal(err)
	}
	smtpClient = func(addr string) (smtpDialer, error) {
		client := &smtpDialerMock{}
		return client, nil
	}
	formValues := url.Values{"groupname": {"group2"}, "members": {"user2"}}
	req, err := http.NewRequest("POST", deletemembersbuttonPath, strings.NewReader(formValues.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	cookie := testCreateValidAdminCookie(state.authenticator)
	req.AddCookie(&cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.deletemembersfromExistingGroup)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestCreateUserorNot(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		t.Fatal(err)
	}
	err = state.createUserorNot("user1")
	if err != nil {
		t.Fatal(err)
	}
	err = state.createUserorNot("user1")
	if err != nil {
		t.Fatal(err)
	}
	err = state.createUserorNot("non-existing-user")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTenderTemplateOrReturnJson(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "whateverpath", nil)
	req.Header.Set("Accept", "text/html")
	if err != nil {
		t.Fatal(err)
	}
	pageData := simpleMessagePageData{
		SuccessMessage: "Any Message",
	}
	//renderTemplateOrReturnJson(w http.ResponseWriter, r *http.Request, templateName string, pageData interface{})
	err = state.renderTemplateOrReturnJson(rr, req, "simpleMessagePage", pageData)
	if err != nil {
		t.Fatal(err)
	}
	// now with invalid template name, should fail
	req2, err := http.NewRequest("POST", "whateverpath", nil)
	req2.Header.Set("Accept", "text/html")
	if err != nil {
		t.Fatal(err)
	}
	someIncompatibleData := []string{"someString"}
	err = state.renderTemplateOrReturnJson(rr, req2, "simpleMessagePage", someIncompatibleData)
	if err == nil {
		t.Fatal(err)
	}
	// now with a bad name
	req3, err := http.NewRequest("POST", "whateverpath", nil)
	req3.Header.Set("Accept", "text/html")
	if err != nil {
		t.Fatal(err)
	}
	err = state.renderTemplateOrReturnJson(rr, req2, "invalidName", pageData)
	if err == nil {
		t.Fatal(err)
	}
	// now we test with an encodible JSON object
	req4, err := http.NewRequest("POST", "whateverpath", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = state.renderTemplateOrReturnJson(rr, req4, "invalidName", pageData)
	if err != nil {
		t.Fatal(err)
	}
	// and now witn an unencodibl JSON object
	req5, err := http.NewRequest("POST", "whateverpath", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := make(chan int)
	err = state.renderTemplateOrReturnJson(rr, req5, "simpleMessagePage", c)
	if err == nil {
		t.Fatal(err)
	}
}

func TestDefaultPathHandler(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		log.Fatal(err)
	}

	handler := http.HandlerFunc(state.defaultPathHandler)

	// test raw Post
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/", nil)
	req.Header.Set("Accept", "text/html")
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}

	redirectedPaths := []string{"/", "/favicon.ico"}
	for _, path := range redirectedPaths {
		rr := httptest.NewRecorder()
		req, err := http.NewRequest("GET", path, nil)
		req.Header.Set("Accept", "text/html")
		if err != nil {
			t.Fatal(err)
		}
		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusFound {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusFound)
		}
	}
	invalidPaths := []string{"/foo", "/bar"}
	for _, path := range invalidPaths {
		rr := httptest.NewRecorder()
		req, err := http.NewRequest("GET", path, nil)
		req.Header.Set("Accept", "text/html")
		if err != nil {
			t.Fatal(err)
		}
		handler.ServeHTTP(rr, req)
		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusNotFound {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusNotFound)
		}
	}

}
