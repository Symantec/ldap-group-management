package main

import (
	"net/http"
	"log"
	"sort"
	"encoding/json"
	"fmt"
)

//All handlers and API endpoints starts from here.

//Display all groups in Target LDAP --required
func (state *RuntimeState) GetallgroupsHandler(w http.ResponseWriter, r *http.Request) {
	var AllGroups_TargetLdap GetGroups

	Allgroups, err := state.getallGroups(state.Config.TargetLDAP.GroupSearchBaseDNs)

	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	sort.Strings(Allgroups)
	AllGroups_TargetLdap.AllGroups = Allgroups
	err=json.NewEncoder(w).Encode(AllGroups_TargetLdap)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
}




//Display all users in Target LDAP --required
func (state *RuntimeState) GetallusersHandler(w http.ResponseWriter, r *http.Request) {
	var AllUsers_TargetLdap GetUsers

	AllUsers, err := state.GetallUsers(state.Config.TargetLDAP.UserSearchBaseDNs, state.Config.TargetLDAP.UserSearchFilter, []string{"uid"})

	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return

	}

	for k := range AllUsers {
		AllUsers_TargetLdap.Users = append(AllUsers_TargetLdap.Users, k)
	}

	err=json.NewEncoder(w).Encode(AllUsers_TargetLdap)
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
		http.Error(w,"couldn't parse the URL",http.StatusInternalServerError)
		return
	}
	var user_groups GetUserGroups

	user_groups.UserName = params[0] //username is "cn" Attribute of a User
	UsersAllgroups, err := state.GetgroupsofUser(state.Config.TargetLDAP.GroupSearchBaseDNs, user_groups.UserName)

	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	sort.Strings(UsersAllgroups)
	user_groups.UserGroups = UsersAllgroups


	err=json.NewEncoder(w).Encode(user_groups)
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
		log.Print("couldn't parse the URL")
		http.Error(w,"couldn't parse the URL",http.StatusInternalServerError)
		return
	}
	var group_users GetGroupUsers

	group_users.GroupName = params[0] //username is "cn" Attribute of a User
	AllUsersinGroup, err := state.GetusersofaGroup(group_users.GroupName)
	sort.Strings(AllUsersinGroup[0])
	group_users.Groupusers = AllUsersinGroup[0]

	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return

	}
	err=json.NewEncoder(w).Encode(group_users)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

}

