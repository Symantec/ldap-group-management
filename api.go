package main

import (
	"net/http"
	"log"
	"sort"
	"encoding/json"
)

//All handlers and API endpoints starts from here.

//Display all groups in Target LDAP --required
func (state *RuntimeState) GetallGroups_Handler(w http.ResponseWriter, r *http.Request) {
	var AllGroups_TargetLdap GetGroups

	Allgroups, err := state.get_allGroups(state.Config.TargetLDAP.GroupSearchBaseDNs)

	if err != nil {
		log.Panic(err)
	}
	sort.Strings(Allgroups)
	AllGroups_TargetLdap.AllGroups = Allgroups
	json.NewEncoder(w).Encode(AllGroups_TargetLdap)

}




//Display all users in Target LDAP --required
func (state *RuntimeState) GetallUsers_Handler(w http.ResponseWriter, r *http.Request) {
	var AllUsers_TargetLdap GetUsers

	AllUsers, err := state.GetallUsers(state.Config.TargetLDAP.UserSearchBaseDNs, state.Config.TargetLDAP.UserSearchFilter, []string{"uid"})

	if err != nil {
		log.Println(err)
	}

	for k := range AllUsers {
		AllUsers_TargetLdap.Users = append(AllUsers_TargetLdap.Users, k)
	}

	json.NewEncoder(w).Encode(AllUsers_TargetLdap)
}




//Displays all Groups of a User. --required
func (state *RuntimeState) GetGroupsofUser_Handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params, ok := q["username"]
	if ok {

		var user_groups GetUserGroups

		user_groups.UserName = params[0] //username is "cn" Attribute of a User
		UsersAllgroups, err := state.getGroupsOfUser(state.Config.TargetLDAP.GroupSearchBaseDNs, user_groups.UserName)
		sort.Strings(UsersAllgroups)
		user_groups.UserGroups = UsersAllgroups

		if err != nil {
			log.Println(err)
		}

		json.NewEncoder(w).Encode(user_groups)
	}
	http.NotFoundHandler()
}



//Displays All Users in a Group --required
func (state *RuntimeState) GetUsersinGroup_Handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params, ok := q["groupname"]
	if ok {
		var group_users GetGroupUsers

		group_users.GroupName = params[0] //username is "cn" Attribute of a User
		AllUsersinGroup, err := state.getUsersofaGroup(group_users.GroupName)
		sort.Strings(AllUsersinGroup[0])
		group_users.Groupusers = AllUsersinGroup[0]

		if err != nil {
			log.Println(err)
		}

		json.NewEncoder(w).Encode(group_users)
	}
	http.NotFoundHandler()
}

