package main

import (
	"encoding/json"
	"fmt"
	"github.com/Symantec/ldap-group-management/lib/userinfo"
	"log"
	"net/http"
	"sort"
	"strings"
)

//All handlers and API endpoints starts from here.

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

func (state *RuntimeState) renderTemplateOrReturnJson(w http.ResponseWriter, r *http.Request, templateName string, pageData interface{}) error {
	preferredAcceptType := state.getPreferredAcceptType(r)
	switch preferredAcceptType {
	case "text/html":
		setSecurityHeaders(w)
		cacheControlValue := "private, max-age=60"
		if templateName != "simpleMessagePage" {
			cacheControlValue = "private, max-age=5"
		}
		w.Header().Set("Cache-Control", cacheControlValue)
		err := state.htmlTemplate.ExecuteTemplate(w, templateName, pageData)
		if err != nil {
			log.Printf("Failed to execute %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return err
		}
	default:
		b, err := json.Marshal(pageData)
		if err != nil {
			log.Printf("Failed marshal %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return err
		}
		_, err = w.Write(b)
		if err != nil {
			log.Printf("Incomplete write %v", err)
			return err
		}
	}
	return nil
}

// Create a group handler --required
func (state *RuntimeState) createGrouphandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != postMethod {
		state.writeFailureResponse(w, r, "POST Method is required", http.StatusMethodNotAllowed)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		if err.Error() == "missing form body" {
			http.Error(w, fmt.Sprint(err), http.StatusBadRequest)
		} else {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		}
		return
	}
	var groupinfo userinfo.GroupInfo
	groupinfo.Groupname = r.PostFormValue("groupname")
	groupinfo.Description = r.PostFormValue("description")
	members := r.PostFormValue("members")

	//check whether the user has the ability to create group
	allow, err := state.canPerformAction(username, groupinfo.Groupname, resourceGroup, permCreate)
	if err != nil {
		log.Println(err)
		return
	}
	if !allow {
		state.writeFailureResponse(w, r, fmt.Sprintf("You don't have permission to create group %s", groupinfo.Groupname), http.StatusForbidden)
		return
	}

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
			http.Error(w, fmt.Sprintf("Managed by group doesn't exists! managerGroup='%s'", groupinfo.Description), http.StatusInternalServerError)
			return
		}
	}

	//check if all the users to be added exists or not.
	for _, member := range strings.Split(members, ",") {
		if len(member) < 1 {
			continue
		}
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
	}

	err = state.Userinfo.CreateGroup(groupinfo)

	if err != nil {
		log.Println(err)
		http.Error(w, "error occurred! May be group name exists or may be members are not available!", http.StatusInternalServerError)
		return
	}
	if state.sysLog != nil {
		state.sysLog.Write([]byte(fmt.Sprintf("Group "+"%s"+" was created by "+"%s", groupinfo.Groupname, username)))

		for _, member := range strings.Split(members, ",") {
			state.sysLog.Write([]byte(fmt.Sprintf("%s"+" was added to Group "+"%s"+" by "+"%s", member, groupinfo.Groupname, username)))
		}
	}
	pageData := simpleMessagePageData{
		UserName:       username,
		IsAdmin:        true,
		Title:          "Group Creation Success",
		SuccessMessage: "Group has been successfully Created",
	}
	state.renderTemplateOrReturnJson(w, r, "simpleMessagePage", pageData)

}

//Delete groups handler --required
func (state *RuntimeState) deleteGrouphandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		state.writeFailureResponse(w, r, "POST Method is required", http.StatusMethodNotAllowed)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		if err.Error() == "missing form body" {
			http.Error(w, fmt.Sprint(err), http.StatusBadRequest)
		} else {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		}
		return
	}
	var groupnames []string
	groups := r.PostFormValue("groupnames")
	//check if groupnames are valid or not.
	for _, eachGroup := range strings.Split(groups, ",") {
		allow, err := state.canPerformAction(username, eachGroup, resourceGroup, permDelete)
		if err != nil {
			log.Println(err)
			return
		}
		if !allow {
			state.writeFailureResponse(w, r, fmt.Sprintf("You don't have permission to delete group %s", eachGroup), http.StatusForbidden)
			return
		}
		groupnameExistsorNot, _, err := state.Userinfo.GroupnameExistsornot(eachGroup)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return

		}
		if !groupnameExistsorNot {
			state.writeFailureResponse(w, r, fmt.Sprintf("Group %s doesn't exist!", eachGroup), http.StatusBadRequest)
			return
		}

		for _, groupname := range state.Config.Base.AutoGroups {
			if eachGroup == groupname {
				state.writeFailureResponse(w, r, groupname+" is part of auto-added group, you cannot delete it!", http.StatusBadRequest)
				return
			}
		}
		groupnames = append(groupnames, eachGroup)
	}

	err = state.Userinfo.DeleteGroup(groupnames)
	if err != nil {
		log.Println(err)
		http.Error(w, "error occurred! May be there is no such group!", http.StatusInternalServerError)
		return
	}
	if state.sysLog != nil {
		for _, eachGroup := range groupnames {
			state.sysLog.Write([]byte(fmt.Sprintf("Group "+"%s"+" was deleted by "+"%s", eachGroup, username)))
		}
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
	state.renderTemplateOrReturnJson(w, r, "simpleMessagePage", pageData)

}

func (state *RuntimeState) createServiceAccounthandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		state.writeFailureResponse(w, r, "POST Method is required", http.StatusMethodNotAllowed)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		if err.Error() == "missing form body" {
			http.Error(w, fmt.Sprint(err), http.StatusBadRequest)
		} else {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		}
		return
	}
	var groupinfo userinfo.GroupInfo
	groupinfo.Groupname = r.PostFormValue("AccountName")
	groupinfo.Mail = r.PostFormValue("mail")
	groupinfo.LoginShell = r.PostFormValue("loginShell")

	allow, err := state.canPerformAction(username, groupinfo.Groupname, resourceSVC, permCreate)
	if err != nil {
		log.Println(err)
		return
	}
	if !allow {
		state.writeFailureResponse(w, r, fmt.Sprintf("You don't have permission to create service account %s", groupinfo.Groupname), http.StatusForbidden)
		return
	}

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
	if state.sysLog != nil {
		state.sysLog.Write([]byte(fmt.Sprintf("Service account "+"%s"+" was created by "+"%s", groupinfo.Groupname, username)))
	}
	pageData := simpleMessagePageData{
		UserName:       username,
		IsAdmin:        true,
		Title:          "Service Account Creation Success",
		SuccessMessage: "Service Account successfully created",
	}
	state.renderTemplateOrReturnJson(w, r, "simpleMessagePage", pageData)
}

func (state *RuntimeState) changeownership(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		state.writeFailureResponse(w, r, "POST Method is required", http.StatusMethodNotAllowed)
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
		if err.Error() == "missing form body" {
			http.Error(w, fmt.Sprint(err), http.StatusBadRequest)
		} else {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		}
		return
	}
	groupList := strings.Split(r.PostFormValue("groupnames"), ",")
	managegroup := r.PostFormValue("managegroup")
	if len(groupList) < 1 {
		state.writeFailureResponse(w, r, "groupnamesParameter is missing", http.StatusBadRequest)
		return
	}
	donecount := 0
	//check if given member exists or not and see if he is already a groupmember if yes continue.
	for _, group := range groupList {
		// Our UI likes to put commas as the end of the group, so we get usually "foo,bar,"... resulting in a list
		// with an empty value.
		if len(group) < 1 {
			continue
		}
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
		if state.sysLog != nil {
			state.sysLog.Write([]byte(fmt.Sprintf("Group %s is managed by %s now, this change was made by %s.", group, managegroup, username)))
		}
		donecount += 1
	}
	if donecount == 0 {
		state.writeFailureResponse(w, r, "Invalid groupnames parameter", http.StatusBadRequest)
		return
	}
	pageData := simpleMessagePageData{
		UserName:       username,
		IsAdmin:        true,
		Title:          "Change Ownership success",
		SuccessMessage: "Group(s) have successfuly changed ownership",
	}
	state.renderTemplateOrReturnJson(w, r, "simpleMessagePage", pageData)
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

        var ajaxRequest = new XMLHttpRequest();
                ajaxRequest.onreadystatechange = function(){
                        if(ajaxRequest.readyState == 4){
                                if(ajaxRequest.status == 200){
                                        var jsonObj = JSON.parse(ajaxRequest.responseText);
                                        var groups = jsonObj.Groups;
                                        console.log("groups :" + groups);
                                        //list_members(users);
					var pending_actions=arrayPendingActions(groups);
					pendingActionsTable(pending_actions);
                                }
                                else {
                                        console.log("Status error: " + ajaxRequest.status);
                                }
                        }
                }
        ajaxRequest.open('GET', '/getGroups.js?type=pendingActions&encoding=json');
        ajaxRequest.send();

	pendingActions = %s; 
});
`

type groupsJSONData struct {
	Groups [][]string
}

func (state *RuntimeState) getGroupsJSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		state.writeFailureResponse(w, r, "GET Method is required", http.StatusMethodNotAllowed)
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
		outputText = getGroupsJSPendingActionsText
		if r.FormValue("encoding") == "json" {

			groupsToSend, err = state.getUserPendingActions(username)
			if err != nil {
				log.Println(err)
				http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
				return
			}
		}
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
	switch r.FormValue("encoding") {
	case "json":
		w.Header().Set("Cache-Control", "private, max-age=15")
		w.Header().Set("Content-Type", "application/json")
		groupsJSON := groupsJSONData{Groups: groupsToSend}
		err = json.NewEncoder(w).Encode(groupsJSON)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}

	default:
		encodedGroups, err := json.Marshal(groupsToSend)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "private, max-age=15")
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, outputText, encodedGroups)
		return
	}
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
					//console.log("users :" + users);
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
		state.writeFailureResponse(w, r, "GET Method is required", http.StatusMethodNotAllowed)
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
		usersToSend, _, err = state.Userinfo.GetusersofaGroup(groupName)
		if err != nil {
			log.Println(err)
			if err == userinfo.GroupDoesNotExist {
				http.Error(w, fmt.Sprint("Group doesn't exist!"), http.StatusBadRequest)
				return
			}
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
