package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/Symantec/ldap-group-management/lib/userinfo"
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
	returnAcceptType := state.getPreferredAcceptType(r)
	// TODO: @SLR9511: why is done this way?... please revisit
	switch returnAcceptType {
	case "text/html":
		err = json.NewEncoder(w).Encode(AllGroupsTargetLdap)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
	default:
		b, err := json.MarshalIndent(Allgroups, "", " ")
		if err != nil {
			log.Printf("Failed marshal %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		_, err = w.Write(b)
		if err != nil {
			log.Printf("Incomplete write? %v", err)
		}
	}
	return
}

//Display all users in Target LDAP --required
func (state *RuntimeState) getallusersHandler(w http.ResponseWriter, r *http.Request) {
	_, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	var AllUsersTargetLdap GetUsers

	AllUsers, err := state.Userinfo.GetallUsers()
	sort.Strings(AllUsers)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return

	}

	for _, k := range AllUsers {
		AllUsersTargetLdap.Users = append(AllUsersTargetLdap.Users, k)
	}
	// TODO: @SLR9511: why is done this way?... please revisit
	returnAcceptType := state.getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		err = json.NewEncoder(w).Encode(AllUsersTargetLdap)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
	default:
		b, err := json.MarshalIndent(AllUsersTargetLdap, "", "  ")
		if err != nil {
			log.Printf("Failed marshal %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return

		}
		_, err = w.Write(b)
		if err != nil {
			log.Printf("Incomplete write? %v", err)
		}
	}
	return
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
	// TODO: @SLR9511: why is done this way?... please revisit
	returnAcceptType := state.getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		err = json.NewEncoder(w).Encode(userGroups)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
	default:
		b, err := json.MarshalIndent(userGroups, "", "  ")
		if err != nil {
			log.Printf("Failed marshal %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return

		}
		_, err = w.Write(b)
		if err != nil {
			log.Printf("Incomplete write? %v", err)
		}
	}
	return
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
	//// TODO: @SLR9511: why is done this way?... please revisit
	returnAcceptType := state.getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		err = json.NewEncoder(w).Encode(groupUsers)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
	default:
		b, err := json.MarshalIndent(groupUsers, "", "  ")
		if err != nil {
			log.Printf("Failed marshal %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return

		}
		_, err = w.Write(b)
		if err != nil {
			log.Printf("Incomplete write? %v", err)
		}
	}
	return
}

func (state *RuntimeState) getPreferredAcceptType(r *http.Request) string {
	preferredAcceptType := "application/json"
	acceptHeader, ok := r.Header["Accept"]
	if ok {
		for _, acceptValue := range acceptHeader {
			if strings.Contains(acceptValue, "text/html") {
				preferredAcceptType = "text/html"
			}
		}
	}
	return preferredAcceptType
}

// Create a group handler --required
func (state *RuntimeState) createGrouphandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	//check if user is admin or not
	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized ", http.StatusForbidden)
		return
	}
	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	var groupinfo userinfo.GroupInfo
	groupinfo.Groupname = r.PostFormValue("groupname")
	groupinfo.Description = r.PostFormValue("description")
	members := r.PostFormValue("members")

	//check if the group name already exists or not.
	groupExistsorNot, _, err := state.Userinfo.GroupnameExistsornot(groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if groupExistsorNot {
		http.Error(w, fmt.Sprint("Groupname already exists! Choose a different one!"), http.StatusInternalServerError)
		return
	}
	//if the group managed attribute (description) isn't self-managed and thus another groupname. check if that group exists or not
	if groupinfo.Description != descriptionAttribute {
		descriptiongroupExistsorNot, _, err := state.Userinfo.GroupnameExistsornot(groupinfo.Description)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !descriptiongroupExistsorNot {
			http.Error(w, fmt.Sprint("Managed by group doesn't exists!"), http.StatusInternalServerError)
			return
		}
	}

	//check if all the users to be added exists or not.
	for _, member := range strings.Split(members, ",") {
		userExistsorNot, err := state.Userinfo.UsernameExistsornot(member)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !userExistsorNot {
			http.Error(w, fmt.Sprintf("User %s doesn't exist!", member), http.StatusInternalServerError)
			return
		}
		groupinfo.MemberUid = append(groupinfo.MemberUid, member)
		groupinfo.Member = append(groupinfo.Member, state.Userinfo.CreateuserDn(member))
	}

	err = state.Userinfo.CreateGroup(groupinfo)

	if err != nil {
		log.Println(err)
		http.Error(w, "error occurred! May be group name exists or may be members are not available!", http.StatusInternalServerError)
		return
	}
	state.sysLog.Write([]byte(fmt.Sprintf("Group "+"%s"+" was created by "+"%s", groupinfo.Groupname, username)))
	for _, member := range strings.Split(members, ",") {
		state.sysLog.Write([]byte(fmt.Sprintf("%s"+" was added to Group "+"%s"+" by "+"%s", member, groupinfo.Groupname, username)))
	}
	pageData := simpleMessagePageData{
		UserName:       username,
		IsAdmin:        true,
		Title:          "Group Creation Success",
		SuccessMessage: "Group has been successfully Created",
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=10")
	err = state.htmlTemplate.ExecuteTemplate(w, "simpleMessagePage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

//Delete groups handler --required
func (state *RuntimeState) deleteGrouphandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusForbidden)
		return
	}

	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(w, "cannot parse form!", http.StatusInternalServerError)
		return
	}
	var groupnames []string
	groups := r.PostFormValue("groupnames")
	//check if groupnames are valid or not.
	for _, eachGroup := range strings.Split(groups, ",") {
		groupnameExistsorNot, _, err := state.Userinfo.GroupnameExistsornot(eachGroup)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return

		}
		if !groupnameExistsorNot {
			http.Error(w, fmt.Sprintf("Group %s doesn't exist!", eachGroup), http.StatusBadRequest)
			return
		}
		groupnames = append(groupnames, eachGroup)
	}

	err = state.Userinfo.DeleteGroup(groupnames)
	if err != nil {
		log.Println(err)
		http.Error(w, "error occurred! May be there is no such group!", http.StatusInternalServerError)
		return
	}
	for _, eachGroup := range groupnames {
		state.sysLog.Write([]byte(fmt.Sprintf("Group "+"%s"+" was deleted by "+"%s", eachGroup, username)))
	}
	err = deleteEntryofGroupsInDB(groupnames, state)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	pageData := simpleMessagePageData{
		UserName:       username,
		IsAdmin:        true,
		Title:          "Group Deletion Suucess",
		SuccessMessage: "Group has been successfully Deleted",
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=10")
	err = state.htmlTemplate.ExecuteTemplate(w, "simpleMessagePage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

}

func (state *RuntimeState) createServiceAccounthandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized ", http.StatusForbidden)
		return
	}
	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	var groupinfo userinfo.GroupInfo
	groupinfo.Groupname = r.PostFormValue("AccountName")
	groupinfo.Mail = r.PostFormValue("mail")
	groupinfo.LoginShell = r.PostFormValue("loginShell")

	if !(groupinfo.LoginShell == "/bin/false") && !(groupinfo.LoginShell == "/bin/bash") {
		log.Println("Bad request! Not an valid LoginShell value")
		http.Error(w, fmt.Sprint("Bad request! Not an valid LoginShell value"), http.StatusBadRequest)
		return
	}

	GroupExistsornot, _, err := state.Userinfo.GroupnameExistsornot(groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if GroupExistsornot {
		log.Println("Bad request! A group already exists with that name!")
		http.Error(w, fmt.Sprint("Bad request! A group already exists with that name!"), http.StatusBadRequest)
		return
	}

	serviceAccountExists, _, err := state.Userinfo.ServiceAccountExistsornot(groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if serviceAccountExists {
		log.Println("Service Account already exists!")
		http.Error(w, fmt.Sprint("Service Account already exists!"), http.StatusBadRequest)
		return
	}

	err = state.Userinfo.CreateServiceAccount(groupinfo)

	if err != nil {
		log.Println(err)
		http.Error(w, "error occurred! May be group name exists or may be members are not available!", http.StatusInternalServerError)
		return
	}
	state.sysLog.Write([]byte(fmt.Sprintf("Service account "+"%s"+" was created by "+"%s", groupinfo.Groupname, username)))
	pageData := simpleMessagePageData{
		UserName:       username,
		IsAdmin:        true,
		Title:          "Service Account Creation Success",
		SuccessMessage: "Service Account successfully created",
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=10")
	err = state.htmlTemplate.ExecuteTemplate(w, "simpleMessagePage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

func (state *RuntimeState) changeownership(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusForbidden)
		return
	}

	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	groups := strings.Split(r.PostFormValue("groupnames"), ",")
	managegroup := r.PostFormValue("managegroup")
	//check if given member exists or not and see if he is already a groupmember if yes continue.
	for _, group := range groups[:len(groups)-1] {
		groupinfo := userinfo.GroupInfo{}
		groupinfo.Groupname = group
		err = state.groupExistsorNot(w, groupinfo.Groupname)
		if err != nil {
			return
		}
		err = state.Userinfo.ChangeDescription(group, managegroup)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		state.sysLog.Write([]byte(fmt.Sprintf("Group %s is managed by %s now, this change was made by %s.", group, managegroup, username)))
	}
	pageData := simpleMessagePageData{
		UserName:       username,
		IsAdmin:        true,
		Title:          "Change Ownership success",
		SuccessMessage: "Group(s) have successfuly changed ownership",
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=10")
	err = state.htmlTemplate.ExecuteTemplate(w, "simpleMessagePage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

// TODO: figure out how to do this with templates or even better migrate to AJAX to get data
const getGroupsJSRequestAccessText = `
document.addEventListener('DOMContentLoaded', function () {
                var groupnames = %s;
                var final_groupnames=array(groupnames);
                RequestAccess(final_groupnames);
                datalist(groupnames[0]);
});
`

const getGroupsJSPendingActionsText = `
document.addEventListener('DOMContentLoaded', function () {
	pendingActions = %s; 
	var pending_actions=arrayPendingActions(pendingActions);
	pendingActionsTable(pending_actions);
});
`

func (state *RuntimeState) getGroupsJSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	outputText := getGroupsJSRequestAccessText
	var groupsToSend [][]string
	switch r.FormValue("type") {
	case "all":
		groupsToSend, err = state.Userinfo.GetAllGroupsManagedBy()
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
	case "pendingRequests":
		groupsToSend, err = state.getPendingRequestGroupsofUser(username)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
	case "allNoManager":
		allgroups, err := state.Userinfo.GetallGroups()
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		sort.Strings(allgroups)
		groupsToSend = [][]string{allgroups}
	case "pendingActions":
		groupsToSend, err = state.getUserPendingActions(username)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		outputText = getGroupsJSPendingActionsText
	case "managedByMe":
		allGroups, err := state.Userinfo.GetAllGroupsManagedBy()
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		userGroups, err := state.Userinfo.GetgroupsofUser(username)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		userGroupMap := make(map[string]interface{})
		for _, groupName := range userGroups {
			userGroupMap[groupName] = nil
		}
		for _, groupTuple := range allGroups {
			managingGroup := groupTuple[1]
			_, ok := userGroupMap[managingGroup]
			if ok {
				groupsToSend = append(groupsToSend, groupTuple)
			}
		}
	default:

		groupsToSend, err = state.Userinfo.GetGroupsInfoOfUser(state.Config.TargetLDAP.GroupSearchBaseDNs, username)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
	}
	encodedGroups, err := json.Marshal(groupsToSend)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	//log.Printf("%s", encodedGroups)
	w.Header().Set("Cache-Control", "private, max-age=15")
	w.Header().Set("Content-Type", "application/javascript")
	fmt.Fprintf(w, outputText, encodedGroups)
	return
}

const getUsersJSText = `
document.addEventListener('DOMContentLoaded', function () {
	        var ajaxRequest = new XMLHttpRequest();
		ajaxRequest.onreadystatechange = function(){
			if(ajaxRequest.readyState == 4){
				if(ajaxRequest.status == 200){
					var jsonObj = JSON.parse(ajaxRequest.responseText);
					var users = jsonObj.Users;
					console.log("users :" + users);
					list_members(users);
				}
				else {
					console.log("Status error: " + ajaxRequest.status);
				}
			}
		}
		ajaxRequest.open('GET', '/getUsers.js?type=all&encoding=json');
		ajaxRequest.send();
                //var Allusers = %s;
		//list_members(Allusers);
});
`

const getUsersGroupJSText = `
document.addEventListener('DOMContentLoaded', function () {
                var groupUsers = %s;
                var usernames=arrayUsers(groupUsers);
                Group_Info(usernames);
});
`

type usersJSONData struct {
	Users []string
}

func (state *RuntimeState) getUsersJSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, err := state.GetRemoteUserName(w, r)
	if err != nil {
		log.Println(err)
		return
	}
	outputText := getUsersJSText
	var usersToSend []string
	switch r.FormValue("type") {
	case "group":
		groupName := r.FormValue("groupName")
		if groupName == "" {
			log.Printf("No groupName found")
			http.Error(w, fmt.Sprint(err), http.StatusBadRequest)
			return
		}
		groupnameExistsorNot, _, err := state.Userinfo.GroupnameExistsornot(groupName)
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
		usersToSend, _, err = state.Userinfo.GetusersofaGroup(groupName)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		outputText = getUsersGroupJSText

	default:
		if r.FormValue("encoding") == "json" {
			usersToSend, err = state.Userinfo.GetallUsers()
			if err != nil {
				log.Println(err)
				http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
				return
			}
		} else {
			go state.Userinfo.GetallUsers()
		}
	}
	sort.Strings(usersToSend)
	switch r.FormValue("encoding") {
	case "json":
		w.Header().Set("Cache-Control", "private, max-age=15")
		w.Header().Set("Content-Type", "application/json")
		usersJSON := usersJSONData{Users: usersToSend}
		err = json.NewEncoder(w).Encode(usersJSON)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}

	default:
		encodedUsers, err := json.Marshal(usersToSend)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "private, max-age=15")
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, outputText, encodedUsers)
		return
	}
	return
}
