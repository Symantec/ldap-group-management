package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
)

func GetRemoteUserName(w http.ResponseWriter, r *http.Request) (string, error) {
	userInfo, err := authSource.GetRemoteUserInfo(r)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return "", err
	}
	if userInfo == nil {
		log.Println("null userinfo!")
		http.Error(w, "null userinfo", http.StatusInternalServerError)
		return "", err
	}
	return *userInfo.Username, nil
}

//Main page with all LDAP groups displayed
func (state *RuntimeState) IndexHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	state.targetLdap,err=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
	}
	Allgroups, err := state.getallGroups(state.Config.TargetLDAP.GroupSearchBaseDNs)

	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	defer state.targetLdap.Close()
	sort.Strings(Allgroups)
	response := Response{username, Allgroups, nil, nil}
	//response.UserName=*userInfo.Username
	if state.UserisadminOrNot(username) == true {
		generateHTML(w, response, "index", "admins_sidebar", "groups")

	} else {
		generateHTML(w, response, "index", "sidebar", "groups")
	}
}

//User Groups page
func (state *RuntimeState) MygroupsHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	state.targetLdap,err=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
	}
	userGroups, err := state.GetgroupsofUser(state.Config.TargetLDAP.GroupSearchBaseDNs, username)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	defer state.targetLdap.Close()
	sort.Strings(userGroups)
	response := Response{username, userGroups, nil, nil}
	if state.UserisadminOrNot(response.UserName) {
		generateHTML(w, response, "index", "admins_sidebar", "my_groups")
	} else {
		generateHTML(w, response, "index", "sidebar", "my_groups")
	}
}

//user's pending requests
func (state *RuntimeState) pendingRequests(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	groupnames, _, err := state.findrequestsofUserinDB(username)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	response := Response{UserName: username, Groups: groupnames, Users: nil, PendingActions: nil}
	sidebarType := "sidebar"
	if state.UserisadminOrNot(username) {
		sidebarType = "admins_sidebar"
	}
	if groupnames == nil {
		generateHTML(w, response, "index", sidebarType, "no_pending_requests")

	} else {
		generateHTML(w, response, "index", sidebarType, "pending_requests")

	}
}

func (state *RuntimeState) creategroupWebpageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	state.targetLdap,err=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
	}
	Allgroups, err := state.getallGroups(state.Config.TargetLDAP.GroupSearchBaseDNs)

	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	defer state.targetLdap.Close()
	if !state.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
	sort.Strings(Allgroups)

	response := Response{username, Allgroups, nil, nil}

	generateHTML(w, response, "index", "admins_sidebar", "create_group")

}

func (state *RuntimeState) deletegroupWebpageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
	response := Response{username, nil, nil, nil}

	generateHTML(w, response, "index", "admins_sidebar", "delete_group")

}

//requesting access by users to join in groups...
func (state *RuntimeState) requestAccessHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	var out map[string][]string
	err = json.NewDecoder(r.Body).Decode(&out)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	state.targetLdap,err=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
	}
	//log.Println(out)
	//fmt.Print(out["groups"])
	err = state.insertRequestInDB(username, out["groups"])
	if err != nil {
		log.Println(err)
		http.Error(w, "oops! an error occured.", http.StatusInternalServerError)
		return
	}
	go state.SendRequestemail(username,out["groups"],r.RemoteAddr, r.UserAgent())
	if state.UserisadminOrNot(username) == true {
		generateHTML(w, Response{UserName: username}, "index", "admins_sidebar", "Accessrequestsent")

	} else {
		generateHTML(w, Response{UserName: username}, "index", "sidebar", "Accessrequestsent")
	}
	defer state.targetLdap.Close()
}

//delete access requests made by user
func (state *RuntimeState) deleteRequests(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	var out map[string][]string
	err = json.NewDecoder(r.Body).Decode(&out)
	if err != nil {
		log.Print(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	for _, entry := range out["groups"] {
		err = state.deleteEntryInDB(username, entry)
		if err != nil {
			log.Println(err)
		}
	}
}

//Parses post info from create group button click.
func (state *RuntimeState) AddmemberstoGroup(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
	}

	err = r.ParseForm()
	if err != nil {
		log.Println("Cannot parse form")
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	var groupinfo groupInfo
	groupinfo.groupname = r.PostFormValue("groupname")
	members := r.PostFormValue("members")
	for _, member := range strings.Split(members, ",") {
		groupinfo.memberUid = append(groupinfo.memberUid, member)
		groupinfo.member = append(groupinfo.member, state.CreateuserDn(member))
	}

	state.targetLdap,err=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
	}

	err = state.createGroup(groupinfo)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	defer state.targetLdap.Close()
}

func (state *RuntimeState) exitfromGroup(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	var out map[string][]string
	err = json.NewDecoder(r.Body).Decode(&out)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return

	}
	state.targetLdap,err=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
	}
	var groupinfo groupInfo
	groupinfo.member = append(groupinfo.member, state.CreateuserDn(username))
	groupinfo.memberUid = append(groupinfo.memberUid, username)
	for _, entry := range out["groups"] {
		groupinfo.groupname = entry
		err = state.DeletemembersfromGroup(groupinfo)
		if err != nil {
			log.Println(err)
		}
	}
	defer state.targetLdap.Close()
}

//User's Pending Actions
func (state *RuntimeState) pendingActions(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	DBentries, err := state.getDBentries()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	state.targetLdap,err=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
	}
	var description string
	var response Response
	response.UserName = username
	for _, entry := range DBentries {
		description, err = state.GetDescriptionvalue(entry[1])
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if description == "self-managed" {
			if state.IsgroupmemberorNot(entry[1], username) {
				response.PendingActions = append(response.PendingActions, entry)
			} else {
				continue
			}
		} else if state.IsgroupmemberorNot(description, username) {
			response.PendingActions = append(response.PendingActions, entry)
		}
		continue
	}
	defer state.targetLdap.Close()
	sidebarType := "sidebar"
	if state.UserisadminOrNot(username) {
		sidebarType = "admins_sidebar"
	}

	if response.PendingActions == nil {
		generateHTML(w, response, "index", sidebarType, "no_pending_actions")

	} else {
		generateHTML(w, response, "index", sidebarType, "pending_actions")

	}
}

//Approving
func (state *RuntimeState) approveHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	var out map[string][][]string
	err = json.NewDecoder(r.Body).Decode(&out)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	state.targetLdap,err=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
	}
	//log.Println(out)
	//log.Println(out["groups"])
	var userPair = out["groups"]
	for _, entry := range userPair {
		if state.IsgroupmemberorNot(entry[1], entry[0]) {
			err = state.deleteEntryInDB(entry[0], entry[1])
			if err != nil {
				fmt.Println("error me")
				log.Println(err)
			}

		} else if state.entryExistsorNot(entry[0], entry[1]) {
			var groupinfo groupInfo
			groupinfo.groupname = entry[1]
			groupinfo.memberUid = append(groupinfo.memberUid, entry[0])
			groupinfo.member = append(groupinfo.member, state.CreateuserDn(entry[0]))
			err := state.AddmemberstoExisting(groupinfo)
			if err != nil {
				log.Println(err)
			}
			err = state.deleteEntryInDB(entry[0], entry[1])
			if err != nil {
				fmt.Println("error here!")
				log.Println(err)
			}
		}
	}
	go state.sendApproveemail(username, out["groups"], r.RemoteAddr, r.UserAgent())
	//generateHTML(w,username,"index","sidebar","Accessrequestsent")
	defer state.targetLdap.Close()
}

//Reject handler
func (state *RuntimeState) rejectHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	var out map[string][][]string
	err = json.NewDecoder(r.Body).Decode(&out)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	//log.Println(out)
	//fmt.Print(out["groups"])//[[username1,groupname1][username2,groupname2]]
	state.targetLdap,err=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
	}
	for _, entry := range out["groups"] {
		fmt.Println(entry[0], entry[1])
		err = state.deleteEntryInDB(entry[0], entry[1])
		if err != nil {
			//fmt.Println("I am the error")
			log.Println(err)
		}
	}
	go state.sendRejectemail(username, out["groups"], r.RemoteAddr, r.UserAgent())
	defer state.targetLdap.Close()
}


// Create a group handler --required
func (state *RuntimeState) createGrouphandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized ", http.StatusUnauthorized)
		return
	}
	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	var groupinfo groupInfo
	groupinfo.groupname = r.PostFormValue("groupname")
	groupinfo.description = r.PostFormValue("description")
	members := r.PostFormValue("members")

	for _, member := range strings.Split(members, ",") {
		groupinfo.memberUid = append(groupinfo.memberUid, member)
		groupinfo.member = append(groupinfo.member, state.CreateuserDn(member))
	}
	state.targetLdap,err=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
	}

	err = state.createGroup(groupinfo)

	if err != nil {
		log.Println(err)
		http.Error(w, "error occurred! May be group name exists or may be members are not available!", http.StatusInternalServerError)
		return
	}
	defer state.targetLdap.Close()
	generateHTML(w, Response{UserName: username}, "index", "admins_sidebar", "groupcreation_success")
}

//Delete groups handler --required
func (state *RuntimeState) deleteGrouphandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
	}

	err = r.ParseForm()
	if err != nil {
		panic("Cannot parse form")
	}
	state.targetLdap,err=state.GetTargetLDAPConnection()
	if err!=nil{
		http.Error(w,"cannot connect to LDAP server",http.StatusInternalServerError)
	}
	var groupnames []string
	groups := r.PostFormValue("groupnames")
	for _, eachGroup := range strings.Split(groups, ",") {
		groupnames = append(groupnames, eachGroup)
	}
	err = state.deleteGroup(groupnames)
	if err != nil {
		log.Println(err)
		http.Error(w, "error occurred! May be there is no such group!", http.StatusInternalServerError)
		return
	}
	defer state.targetLdap.Close()
	err = state.deleteEntryofGroupsInDB(groupnames)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	generateHTML(w, Response{UserName: username}, "index", "admins_sidebar", "groupdeletion_success")

}
