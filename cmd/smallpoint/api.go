package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
)

//All handlers and API endpoints starts from here.

//Display all groups in Target LDAP --required
func (state *RuntimeState) getallgroupsHandler(w http.ResponseWriter, r *http.Request) {
	_, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	var AllGroupsTargetLdap GetGroups

	Allgroups, err := state.Userinfo.GetallGroups()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	sort.Strings(Allgroups)
	AllGroupsTargetLdap.AllGroups = Allgroups
	err = json.NewEncoder(w).Encode(AllGroupsTargetLdap)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
}

//Display all users in Target LDAP --required
func (state *RuntimeState) getallusersHandler(w http.ResponseWriter, r *http.Request) {
	_, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	var AllUsersTargetLdap GetUsers

	AllUsers, _, err := state.Userinfo.GetallUsers()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return

	}

	for k := range AllUsers {
		AllUsersTargetLdap.Users = append(AllUsersTargetLdap.Users, k)
	}

	err = json.NewEncoder(w).Encode(AllUsersTargetLdap)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
}

//Displays all Groups of a User. --required
func (state *RuntimeState) getgroupsofuserHandler(w http.ResponseWriter, r *http.Request) {
	_, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	q := r.URL.Query()
	params, ok := q["username"]
	if !ok {
		log.Print("couldn't parse the URL")
		http.Error(w, "couldn't parse the URL", http.StatusInternalServerError)
		return
	}
	var userGroups GetUserGroups

	userGroups.UserName = params[0] //username is "cn" Attribute of a User
	userExistsorNot, err := state.Userinfo.UsernameExistsornot(userGroups.UserName)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if !userExistsorNot {
		log.Println("username doesn't exist!")
		http.Error(w, fmt.Sprint("username doesn't exist!"), http.StatusBadRequest)
		return
	}
	UsersAllgroups, err := state.Userinfo.GetgroupsofUser(userGroups.UserName)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	sort.Strings(UsersAllgroups)
	userGroups.UserGroups = UsersAllgroups

	err = json.NewEncoder(w).Encode(userGroups)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
}

//Displays All Users in a Group --required
func (state *RuntimeState) getusersingroupHandler(w http.ResponseWriter, r *http.Request) {
	_, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	q := r.URL.Query()
	params, ok := q["groupname"]
	if !ok {
		log.Println("couldn't parse the URL")
		http.Error(w, "couldn't parse the URL", http.StatusInternalServerError)
		return
	}
	var groupUsers GetGroupUsers

	groupUsers.GroupName = params[0] //username is "cn" Attribute of a User
	groupnameExistsorNot, _, err := state.Userinfo.GroupnameExistsornot(groupUsers.GroupName)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if !groupnameExistsorNot {
		log.Println("Group doesn't exist!")
		http.Error(w, fmt.Sprint("Group doesn't exist!"), http.StatusBadRequest)
		return
	}
	AllUsersinGroup, _, err := state.Userinfo.GetusersofaGroup(groupUsers.GroupName)
	sort.Strings(AllUsersinGroup)
	groupUsers.Groupusers = AllUsersinGroup
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	err = json.NewEncoder(w).Encode(groupUsers)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

}
