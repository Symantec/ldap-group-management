package main

import (
	"log"
	"net/http"
	"net/http/httptest"
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
	}

	//nonAdminWebPaths := []string{indexPath}
	cookie := testCreateValidCookie()

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
