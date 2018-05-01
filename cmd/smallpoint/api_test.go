package main

import (
	"testing"
	"log"
	"net/http"
	"net/http/httptest"
	"time"
	"os"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"errors"
)
func createCookie() http.Cookie{
	expiresAt:=time.Now().Add(time.Hour*12)
	cookie:=http.Cookie{Name:"smallpointauth",Value:"hellogroup1group2",Path:"/",Expires:expiresAt,HttpOnly:true}
	return cookie
}

func loadConfigforTests(configFilename string) (RuntimeState, error) {

	var state RuntimeState

	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return state, err
	}

	//ioutil.ReadFile returns a byte slice (i.e)(source)
	source, err := ioutil.ReadFile(configFilename)
	if err != nil {
		err = errors.New("cannot read config file")
		return state, err
	}

	//Unmarshall(source []byte,out interface{})decodes the source byte slice/value and puts them in out.
	err = yaml.Unmarshal(source, &state.Config)

	if err != nil {
		err = errors.New("Cannot parse config file")
		log.Printf("Source=%s", source)
		return state, err
	}
	err = initDB(&state)
	if err != nil {
		return state, err
	}
	mock:=New()
	state.Userinfo=mock
	state.authcookies=make(map[string]cookieInfo)
	expiresAt:=time.Now().Add(time.Hour*12)
	usersession:=cookieInfo{"user1",expiresAt,"hellogroup1group2"}
	state.authcookies["hellogroup1group2"]=usersession
	return state, err
}


func TestRuntimeState_GetallgroupsHandler(t *testing.T) {
	state, err := loadConfigforTests(*configFilename)
	if err != nil {
		log.Println(err)
	}

	req,err:=http.NewRequest("GET","/allgroups",nil)
	if err!=nil{
		t.Fatal(err)
	}
	cookie:=createCookie()
	req.AddCookie(&cookie)

	rr:=httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetallgroupsHandler)

	handler.ServeHTTP(rr,req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}
func TestRuntimeState_GetusersingroupHandlerFail(t *testing.T) {
	state, err := loadConfigforTests(*configFilename)
	if err != nil {
		log.Println(err)
	}

	req,err:=http.NewRequest("GET","/group_users/",nil)
	if err!=nil{
		t.Fatal(err)
	}
	cookie:=createCookie()
	req.AddCookie(&cookie)

	rr:=httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetusersingroupHandler)

	handler.ServeHTTP(rr,req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}

}

func TestRuntimeState_GetusersingroupHandlerSuccess(t *testing.T) {
	state, err := loadConfigforTests(*configFilename)
	if err != nil {
		log.Println(err)
	}

	req,err:=http.NewRequest("GET","/group_users/?groupname=group1",nil)
	if err!=nil{
		t.Fatal(err)
	}
	cookie:=createCookie()
	req.AddCookie(&cookie)

	rr:=httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetusersingroupHandler)

	handler.ServeHTTP(rr,req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}

func TestRuntimeState_GetgroupsofuserHandlerFail(t *testing.T) {
	state, err := loadConfigforTests(*configFilename)
	if err != nil {
		log.Println(err)
	}

	req,err:=http.NewRequest("GET","/user_groups/",nil)
	if err!=nil{
		t.Fatal(err)
	}
	cookie:=createCookie()
	req.AddCookie(&cookie)


	rr:=httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetgroupsofuserHandler)

	handler.ServeHTTP(rr,req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}

}


func TestRuntimeState_GetgroupsofuserHandlerSuccess(t *testing.T) {
	state, err := loadConfigforTests(*configFilename)
	if err != nil {
		log.Println(err)
	}

	req,err:=http.NewRequest("GET","/user_groups/?username=user1",nil)
	if err!=nil{
		t.Fatal(err)
	}
	cookie:=createCookie()
	req.AddCookie(&cookie)

	rr:=httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetgroupsofuserHandler)

	handler.ServeHTTP(rr,req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}


func TestRuntimeState_GetallusersHandler(t *testing.T) {
	state, err := loadConfigforTests(*configFilename)
	if err != nil {
		log.Println(err)
	}

	req,err:=http.NewRequest("GET","/allusers",nil)
	if err!=nil{
		t.Fatal(err)
	}
	cookie:=createCookie()
	req.AddCookie(&cookie)

	rr:=httptest.NewRecorder()
	handler := http.HandlerFunc(state.GetallusersHandler)

	handler.ServeHTTP(rr,req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}

