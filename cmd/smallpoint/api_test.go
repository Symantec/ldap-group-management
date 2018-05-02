package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const(
	usergroupsTest="/user_groups/?username=user1"
	groupusersTest="/group_users/?groupname=group1"
	cookievalueTest="hellogroup1group2"
	testusername="user1"
)

func createCookie() http.Cookie {
	expiresAt := time.Now().Add(time.Hour * cookieExpirationTime)
	cookie := http.Cookie{Name: cookieName, Value: cookievalueTest, Path: indexpath, Expires: expiresAt, HttpOnly: true,Secure:true}
	return cookie
}

func Init() (RuntimeState, error) {
	var state RuntimeState
	mock := New()
	state.Userinfo = mock
	state.authcookies = make(map[string]cookieInfo)
	expiresAt := time.Now().Add(time.Hour * cookieExpirationTime)
	usersession := cookieInfo{testusername, expiresAt}
	state.authcookies[cookievalueTest] = usersession
	return state, nil
}

func TestRuntimeState_GetallgroupsHandler(t *testing.T) {
	state, err := Init()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET", allgroups, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := createCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetallgroupsHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}
func TestRuntimeState_GetusersingroupHandlerFail(t *testing.T) {
	state, err := Init()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET", groupusers, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := createCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetusersingroupHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}

}

func TestRuntimeState_GetusersingroupHandlerSuccess(t *testing.T) {
	state, err := Init()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET",groupusersTest , nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := createCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetusersingroupHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}

func TestRuntimeState_GetgroupsofuserHandlerFail(t *testing.T) {
	state, err := Init()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET", usergroups, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := createCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetgroupsofuserHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}

}

func TestRuntimeState_GetgroupsofuserHandlerSuccess(t *testing.T) {
	state, err := Init()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET", usergroupsTest, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := createCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetgroupsofuserHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}

func TestRuntimeState_GetallusersHandler(t *testing.T) {
	state, err := Init()
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest("GET", allusers, nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := createCookie()
	req.AddCookie(&cookie)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetallusersHandler)

	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}
