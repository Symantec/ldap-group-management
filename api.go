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
func (state *RuntimeState) GetallgroupsHandler(w http.ResponseWriter, r *http.Request) {
	var AllGroupsTargetLdap GetGroups
	var err error
	TargetLDAPConn,err:=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
		return
	}
	defer TargetLDAPConn.Close()

	Allgroups, err := state.getallGroups(state.Config.TargetLDAP.GroupSearchBaseDNs,TargetLDAPConn)
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
func (state *RuntimeState) GetallusersHandler(w http.ResponseWriter, r *http.Request) {
	var AllUsersTargetLdap GetUsers
	var err error
	TargetLDAPConn,err:=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
		return
	}
	defer TargetLDAPConn.Close()
	AllUsers, err := state.GetallUsers(state.Config.TargetLDAP.UserSearchBaseDNs, state.Config.TargetLDAP.UserSearchFilter, []string{"uid"},TargetLDAPConn)
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
func (state *RuntimeState) GetgroupsofuserHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params, ok := q["username"]
	if !ok {
		log.Print("couldn't parse the URL")
		http.Error(w, "couldn't parse the URL", http.StatusInternalServerError)
		return
	}
	var userGroups GetUserGroups
	var err error
	TargetLDAPConn,err:=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
		return
	}
	defer TargetLDAPConn.Close()

	userGroups.UserName = params[0] //username is "cn" Attribute of a User
	UsersAllgroups, err := state.GetgroupsofUser(state.Config.TargetLDAP.GroupSearchBaseDNs, userGroups.UserName,TargetLDAPConn)
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
func (state *RuntimeState) GetusersingroupHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params, ok := q["groupname"]
	if !ok {
		log.Println("couldn't parse the URL")
		http.Error(w, "couldn't parse the URL", http.StatusInternalServerError)
		return
	}
	var groupUsers GetGroupUsers
	var err error
	TargetLDAPConn,err:=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
		return
	}
	defer TargetLDAPConn.Close()

	groupUsers.GroupName = params[0] //username is "cn" Attribute of a User
	AllUsersinGroup, err := state.GetusersofaGroup(groupUsers.GroupName,TargetLDAPConn)
	sort.Strings(AllUsersinGroup[0])
	groupUsers.Groupusers = AllUsersinGroup[0]
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
