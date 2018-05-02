package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
	"github.com/Symantec/ldap-group-management/lib/userinfo"
)

func randomStringGeneration() (string, error) {
	const size = 32
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (state *RuntimeState) LoginHandler(w http.ResponseWriter, r *http.Request) {
	userInfo, err := authSource.GetRemoteUserInfo(r)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if userInfo == nil {
		log.Println("null userinfo!")

		http.Error(w, "null userinfo", http.StatusInternalServerError)
		return
	}
	randomString, err := randomStringGeneration()
	if err != nil {
		log.Println(err)
		http.Error(w, "cannot generate random string", http.StatusInternalServerError)
		return
	}

	expires := time.Now().Add(time.Hour * cookieExpirationTime)

	usercookie := http.Cookie{Name: cookieName, Value: randomString, Path: indexpath, Expires: expires, HttpOnly: true,Secure:true}

	http.SetCookie(w, &usercookie)

	Cookieinfo := cookieInfo{*userInfo.Username, usercookie.Expires}

	state.cookiemutex.Lock()
	state.authcookies[usercookie.Value] = Cookieinfo
	state.cookiemutex.Unlock()

	http.Redirect(w, r, indexpath, http.StatusFound)
}

func (state *RuntimeState) GetRemoteUserName(w http.ResponseWriter, r *http.Request) (string, error) {

	remoteCookie, err := r.Cookie(cookieName)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, loginpath, http.StatusFound)
		return "", err
	}
	state.cookiemutex.Lock()
	cookieInfo, ok := state.authcookies[remoteCookie.Value]
	state.cookiemutex.Unlock()

	if !ok {
		http.Redirect(w, r, loginpath, http.StatusFound)
		return "", nil
	}
	if cookieInfo.ExpiresAt.Before(time.Now()) {
		http.Redirect(w, r, loginpath, http.StatusFound)
		return "", nil
	}
	return cookieInfo.Username, nil
}

//Main page with all LDAP groups displayed
func (state *RuntimeState) IndexHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	Allgroups, err := state.Userinfo.GetallGroups()

	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	sort.Strings(Allgroups)
	response := Response{username, Allgroups, nil, nil}
	//response.UserName=*userInfo.Username
	if state.Userinfo.UserisadminOrNot(username) == true {
		generateHTML(w, response, "index", "admins_sidebar", "groups")

	} else {
		generateHTML(w, response, "index", "sidebar", "groups")
	}
}

//User Groups page
func (state *RuntimeState) MygroupsHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	userGroups, err := state.Userinfo.GetgroupsofUser(username)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	sort.Strings(userGroups)
	response := Response{username, userGroups, nil, nil}
	sidebarType := "sidebar"

	if state.Userinfo.UserisadminOrNot(response.UserName) {
		sidebarType = "admins_sidebar"
	}

	generateHTML(w, response, "index", sidebarType, "my_groups")
}

//user's pending requests
func (state *RuntimeState) pendingRequests(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	groupnames, _, err := findrequestsofUserinDB(username, state)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	response := Response{UserName: username, Groups: groupnames, Users: nil, PendingActions: nil}
	sidebarType := "sidebar"
	if state.Userinfo.UserisadminOrNot(username) {
		sidebarType = "admins_sidebar"
	}
	if groupnames == nil {
		generateHTML(w, response, "index", sidebarType, "no_pending_requests")

	} else {
		generateHTML(w, response, "index", sidebarType, "pending_requests")

	}
}

func (state *RuntimeState) creategroupWebpageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	Allgroups, err := state.Userinfo.GetallGroups()

	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
	sort.Strings(Allgroups)

	response := Response{username, Allgroups, nil, nil}

	generateHTML(w, response, "index", "admins_sidebar", "create_group")

}

func (state *RuntimeState) deletegroupWebpageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
	response := Response{username, nil, nil, nil}

	generateHTML(w, response, "index", "admins_sidebar", "delete_group")

}

//requesting access by users to join in groups...
func (state *RuntimeState) requestAccessHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
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
	//log.Println(out)
	//fmt.Print(out["groups"])
	err = insertRequestInDB(username, out["groups"], state)
	if err != nil {
		log.Println(err)
		http.Error(w, "oops! an error occured.", http.StatusInternalServerError)
		return
	}
	go state.SendRequestemail(username, out["groups"], r.RemoteAddr, r.UserAgent())
	sidebarType := "sidebar"

	if state.Userinfo.UserisadminOrNot(username) == true {
		sidebarType = "admins_sidebar"
	}
	generateHTML(w, Response{UserName: username}, "index", sidebarType, "Accessrequestsent")

}

//delete access requests made by user
func (state *RuntimeState) deleteRequests(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
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
		err = deleteEntryInDB(username, entry, state)
		if err != nil {
			log.Println(err)
		}
	}
}

//Parses post info from create group button click.
func (state *RuntimeState) AddmemberstoGroup(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
	}

	err = r.ParseForm()
	if err != nil {
		log.Println("Cannot parse form")
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	var groupinfo userinfo.GroupInfo
	groupinfo.Groupname = r.PostFormValue("groupname")
	members := r.PostFormValue("members")
	for _, member := range strings.Split(members, ",") {
		groupinfo.MemberUid = append(groupinfo.MemberUid, member)
		groupinfo.Member = append(groupinfo.Member, state.Userinfo.CreateuserDn(member))
	}

	err = state.Userinfo.CreateGroup(groupinfo)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
}

func (state *RuntimeState) exitfromGroup(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
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
	var groupinfo userinfo.GroupInfo
	groupinfo.Member = append(groupinfo.Member, state.Userinfo.CreateuserDn(username))
	groupinfo.MemberUid = append(groupinfo.MemberUid, username)
	for _, entry := range out["groups"] {
		groupinfo.Groupname = entry
		err = state.Userinfo.DeletemembersfromGroup(groupinfo)
		if err != nil {
			log.Println(err)
		}
	}
}

//User's Pending Actions
func (state *RuntimeState) pendingActions(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	DBentries, err := getDBentries(state)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	var description string
	var response Response
	response.UserName = username
	for _, entry := range DBentries {
		groupName := entry[1]
		//fmt.Println(groupName)
		description, err = state.Userinfo.GetDescriptionvalue(groupName)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if description != descriptionAttribute {
			groupName = description
		}
		// Check now if username is member of groupname(in description) and if it is, then add it.
		if state.Userinfo.IsgroupmemberorNot(groupName, username) {
			response.PendingActions = append(response.PendingActions, entry)
		}
	}
	sidebarType := "sidebar"
	if state.Userinfo.UserisadminOrNot(username) {
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
	username, err := state.GetRemoteUserName(w, r)
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
	//log.Println(out["groups"])
	var userPair = out["groups"]
	for _, entry := range userPair {
		if state.Userinfo.IsgroupmemberorNot(entry[1], entry[0]) {
			err = deleteEntryInDB(entry[0], entry[1], state)
			if err != nil {
				fmt.Println("error me")
				log.Println(err)
			}

		} else if entryExistsorNot(entry[0], entry[1], state) {
			var groupinfo userinfo.GroupInfo
			groupinfo.Groupname = entry[1]
			groupinfo.MemberUid = append(groupinfo.MemberUid, entry[0])
			groupinfo.Member = append(groupinfo.Member, state.Userinfo.CreateuserDn(entry[0]))
			err := state.Userinfo.AddmemberstoExisting(groupinfo)
			if err != nil {
				log.Println(err)
			}
			err = deleteEntryInDB(entry[0], entry[1], state)
			if err != nil {
				fmt.Println("error here!")
				log.Println(err)
			}
		}
	}
	go state.sendApproveemail(username, out["groups"], r.RemoteAddr, r.UserAgent())
	//generateHTML(w,username,"index","sidebar","Accessrequestsent")
}

//Reject handler
func (state *RuntimeState) rejectHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
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

	for _, entry := range out["groups"] {
		fmt.Println(entry[0], entry[1])
		err = deleteEntryInDB(entry[0], entry[1], state)
		if err != nil {
			//fmt.Println("I am the error")
			log.Println(err)
		}
	}
	go state.sendRejectemail(username, out["groups"], r.RemoteAddr, r.UserAgent())
}

// Create a group handler --required
func (state *RuntimeState) createGrouphandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized ", http.StatusUnauthorized)
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

	for _, member := range strings.Split(members, ",") {
		groupinfo.MemberUid = append(groupinfo.MemberUid, member)
		groupinfo.Member = append(groupinfo.Member, state.Userinfo.CreateuserDn(member))
	}
	err = state.Userinfo.CreateGroup(groupinfo)

	if err != nil {
		log.Println(err)
		http.Error(w, "error occurred! May be group name exists or may be members are not available!", http.StatusInternalServerError)
		return
	}
	generateHTML(w, Response{UserName: username}, "index", "admins_sidebar", "groupcreation_success")
}

//Delete groups handler --required
func (state *RuntimeState) deleteGrouphandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
	}

	err = r.ParseForm()
	if err != nil {
		panic("Cannot parse form")
	}
	var groupnames []string
	groups := r.PostFormValue("groupnames")
	for _, eachGroup := range strings.Split(groups, ",") {
		groupnames = append(groupnames, eachGroup)
	}
	err = state.Userinfo.DeleteGroup(groupnames)
	if err != nil {
		log.Println(err)
		http.Error(w, "error occurred! May be there is no such group!", http.StatusInternalServerError)
		return
	}
	err = deleteEntryofGroupsInDB(groupnames, state)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	generateHTML(w, Response{UserName: username}, "index", "admins_sidebar", "groupdeletion_success")

}
