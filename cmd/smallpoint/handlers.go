package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Symantec/ldap-group-management/lib/userinfo"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const postMethod = "POST"
const getMethod = "GET"
const UserServiceAccount = "User Service Account"
const GroupServiceAccount = "Group Service Account"

func checkCSRF(w http.ResponseWriter, r *http.Request) (bool, error) {
	if r.Method != getMethod {
		referer := r.Referer()
		if len(referer) > 0 && len(r.Host) > 0 {
			log.Println(3, "ref =%s, host=%s", referer, r.Host)
			refererURL, err := url.Parse(referer)
			if err != nil {
				log.Println(err)
				return false, err
			}
			log.Println(3, "refHost =%s, host=%s", refererURL.Host, r.Host)
			if refererURL.Host != r.Host {
				log.Printf("CSRF detected.... rejecting with a 400")
				http.Error(w, "you are not authorized", http.StatusUnauthorized)
				err := errors.New("CSRF detected... rejecting")
				return false, err

			}
		}
	}
	return true, nil
}

func randomStringGeneration() (string, error) {
	const size = 32
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (state *RuntimeState) loginHandler(w http.ResponseWriter, r *http.Request) {
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

	expires := time.Now().Add(time.Hour * cookieExpirationHours)

	usercookie := http.Cookie{Name: cookieName, Value: randomString, Path: indexPath, Expires: expires, HttpOnly: true, Secure: true}

	http.SetCookie(w, &usercookie)

	Cookieinfo := cookieInfo{*userInfo.Username, usercookie.Expires}

	state.cookiemutex.Lock()
	state.authcookies[usercookie.Value] = Cookieinfo
	state.cookiemutex.Unlock()

	http.Redirect(w, r, indexPath, http.StatusFound)
}

func (state *RuntimeState) GetRemoteUserName(w http.ResponseWriter, r *http.Request) (string, error) {
	_, err := checkCSRF(w, r)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusUnauthorized)
		return "", err
	}
	remoteCookie, err := r.Cookie(cookieName)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, loginPath, http.StatusFound)
		return "", err
	}
	state.cookiemutex.Lock()
	cookieInfo, ok := state.authcookies[remoteCookie.Value]
	state.cookiemutex.Unlock()

	if !ok {
		http.Redirect(w, r, loginPath, http.StatusFound)
		return "", nil
	}
	if cookieInfo.ExpiresAt.Before(time.Now()) {
		http.Redirect(w, r, loginPath, http.StatusFound)
		return "", nil
	}
	return cookieInfo.Username, nil
}

//Main page with all LDAP groups displayed
func (state *RuntimeState) indexHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	Allgroups, err := state.Userinfo.GetallGroupsandDescription(state.Config.TargetLDAP.GroupSearchBaseDNs)

	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	response := Response{username, Allgroups, nil, nil}
	//response.UserName=*userInfo.Username
	if state.Userinfo.UserisadminOrNot(username) == true {
		generateHTML(w, response, "index", "admins_sidebar", "groups")

	} else {
		generateHTML(w, response, "index", "sidebar", "groups")
	}
}

//User Groups page
func (state *RuntimeState) mygroupsHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	userGroups, err := state.Userinfo.GetGroupsInfoOfUser(state.Config.TargetLDAP.GroupSearchBaseDNs, username)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
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

	for _, groupname := range groupnames {
		Ismember, _, err := state.Userinfo.IsgroupmemberorNot(groupname, username)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if Ismember {
			err := deleteEntryInDB(groupname, username, state)
			if err != nil {
				log.Println(err)
				http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
				return
			}
			continue
		}
	}

	groups, err := state.Userinfo.ManagedbyAttribute(groupnames)
	if err != nil {
		log.Println(err)
	}
	response := Response{UserName: username, Groups: groups, Users: nil, PendingActions: nil}

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

	response := Response{username, [][]string{Allgroups}, nil, nil}

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
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
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
	for _, entry := range out["groups"] {
		GroupExistsornot, _, err := state.Userinfo.GroupnameExistsornot(entry)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !GroupExistsornot {
			log.Println("Bad request!")
			http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
			return
		}
	}
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
	w.WriteHeader(http.StatusOK)
	generateHTML(w, Response{UserName: username}, "index", sidebarType, "Accessrequestsent")

}

//delete access requests made by user
func (state *RuntimeState) deleteRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
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
		GroupExistsornot, _, err := state.Userinfo.GroupnameExistsornot(entry)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !GroupExistsornot {
			log.Println("Bad request!")
			http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
			return
		}
	}

	for _, entry := range out["groups"] {
		err = deleteEntryInDB(username, entry, state)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (state *RuntimeState) exitfromGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
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
	for _, entry := range out["groups"] {
		GroupExistsornot, _, err := state.Userinfo.GroupnameExistsornot(entry)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !GroupExistsornot {
			log.Println("Bad request!")
			http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
			return
		}
	}
	for _, entry := range out["groups"] {
		IsgroupMember, _, err := state.Userinfo.IsgroupmemberorNot(entry, username)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !IsgroupMember {
			http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
			return
		}
	}
	var groupinfo userinfo.GroupInfo
	groupinfo.Member = append(groupinfo.Member, state.Userinfo.CreateuserDn(username))
	groupinfo.MemberUid = append(groupinfo.MemberUid, username)
	for _, entry := range out["groups"] {
		groupinfo.Groupname = entry
		err = state.Userinfo.DeletemembersfromGroup(groupinfo)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusBadRequest)
			return
		}
	}
	w.WriteHeader(http.StatusOK)

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
	var response Response
	response.UserName = username
	for _, entry := range DBentries {
		groupName := entry[1]
		user := entry[0]
		//fmt.Println(groupName)
		//check if entry[0] i.e. user is already a group member or not ; if yes, delete request and continue.
		Ismember, description, err := state.Userinfo.IsgroupmemberorNot(groupName, user)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if Ismember {
			err := deleteEntryInDB(groupName, user, state)
			if err != nil {
				log.Println(err)
				http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
				return
			}
			continue
		}
		//get the description value (or) group managed by value; if descriptionAttribute

		if description != descriptionAttribute {
			groupName = description
		}
		// Check now if username is member of groupname(in description) and if it is, then add it.
		Isgroupmember, _, err := state.Userinfo.IsgroupmemberorNot(groupName, username)
		if err != nil {
			log.Println(err)
		}
		if Isgroupmember {
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
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
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
	//log.Println(out["groups"])//[[username1,groupname1][username2,groupname2]]
	var userPair = out["groups"]
	//entry:[username1 groupname1]

	//check [username1 groupname1] exists or not
	for _, entry := range userPair {
		userExistsornot, err := state.Userinfo.UsernameExistsornot(entry[0])
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !userExistsornot {
			log.Println("Bad request!")
			http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
			return
		}
		GroupExistsornot, _, err := state.Userinfo.GroupnameExistsornot(entry[1])
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !GroupExistsornot {
			log.Println("Bad request!")
			http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
			return
		}
		IsgroupAdmin, err := state.Userinfo.IsgroupAdminorNot(username, entry[1])
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !IsgroupAdmin {
			http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
			return
		}
	}

	//entry:[user group]
	for _, entry := range userPair {
		Isgroupmember, _, err := state.Userinfo.IsgroupmemberorNot(entry[1], entry[0])
		if err != nil {
			log.Println(err)
		}
		if Isgroupmember {
			err = deleteEntryInDB(entry[0], entry[1], state)
			if err != nil {
				//fmt.Println("error me")
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
	w.WriteHeader(http.StatusOK)

	//generateHTML(w,username,"index","sidebar","Accessrequestsent")
}

//Reject handler
func (state *RuntimeState) rejectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
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
	//this handler just deletes requests from the DB, so check if the user is authorized to reject or not.
	for _, entry := range out["groups"] {
		IsgroupAdmin, err := state.Userinfo.IsgroupAdminorNot(username, entry[1])
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !IsgroupAdmin {
			http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
			return
		}
	}
	//check if the entry still exists or not.
	for _, entry := range out["groups"] {
		entryExists := entryExistsorNot(entry[0], entry[1], state)
		if entryExists {
			log.Println("entry doesn't exist!")
			http.Error(w, fmt.Sprintf("%s doesn't exist in DB! Refresh your page!", entry), http.StatusInternalServerError)
			return
		}
	}
	for _, entry := range out["groups"] {
		//fmt.Println(entry[0], entry[1])
		err = deleteEntryInDB(entry[0], entry[1], state)
		if err != nil {
			//fmt.Println("I am the error")
			log.Println(err)
			http.Error(w, fmt.Sprintf("error occurred while process request of %s", entry), http.StatusInternalServerError)
			return

		}
	}
	go state.sendRejectemail(username, out["groups"], r.RemoteAddr, r.UserAgent())
	w.WriteHeader(http.StatusOK)
}

// Create a group handler --required
func (state *RuntimeState) createGrouphandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	//check if user is admin or not
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
	generateHTML(w, Response{UserName: username}, "index", "admins_sidebar", "groupcreation_success")
}

//Delete groups handler --required
func (state *RuntimeState) deleteGrouphandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
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
			http.Error(w, fmt.Sprintf("Group %s doesn't exist!", eachGroup), http.StatusInternalServerError)
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
	err = deleteEntryofGroupsInDB(groupnames, state)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	generateHTML(w, Response{UserName: username}, "index", "admins_sidebar", "groupdeletion_success")

}

func (state *RuntimeState) addmemberstoGroupWebpageHandler(w http.ResponseWriter, r *http.Request) {
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

	response := Response{username, [][]string{Allgroups}, nil, nil}

	sidebarType := "sidebar"
	if state.Userinfo.UserisadminOrNot(username) {
		sidebarType = "admins_sidebar"
	}

	generateHTML(w, response, "index", sidebarType, "addpeopletogroups")

}

func (state *RuntimeState) addmemberstoExistingGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
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
	members := r.PostFormValue("members")
	//check if groupname given by user exists or not
	GroupExistsornot, _, err := state.Userinfo.GroupnameExistsornot(groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if !GroupExistsornot {
		log.Println("Bad request!")
		http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
		return
	}
	IsgroupAdmin, err := state.Userinfo.IsgroupAdminorNot(username, groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if !IsgroupAdmin && !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, fmt.Sprint("You are not authorized to add people to this group!"), http.StatusBadRequest)
		return
	}

	//check if given member exists or not and see if he is already a groupmember if yes continue.
	for _, member := range strings.Split(members, ",") {
		userExistsornot, err := state.Userinfo.UsernameExistsornot(member)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !userExistsornot {
			log.Println("Bad request!")
			http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
			return
		}
		IsgroupMember, _, err := state.Userinfo.IsgroupmemberorNot(groupinfo.Groupname, member)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if IsgroupMember {
			continue
		}
		groupinfo.MemberUid = append(groupinfo.MemberUid, member)
		groupinfo.Member = append(groupinfo.Member, state.Userinfo.CreateuserDn(member))
	}

	err = state.Userinfo.AddmemberstoExisting(groupinfo)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	generateHTML(w, Response{UserName: username}, "index", "admins_sidebar", "addpeopletogroup_success")

}

func (state *RuntimeState) deletemembersfromGroupWebpageHandler(w http.ResponseWriter, r *http.Request) {
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

	response := Response{username, [][]string{Allgroups}, nil, nil}

	sidebarType := "sidebar"
	if state.Userinfo.UserisadminOrNot(username) {
		sidebarType = "admins_sidebar"
	}

	generateHTML(w, response, "index", sidebarType, "deletemembersfromgroup")

}

func (state *RuntimeState) deletemembersfromExistingGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
	}

	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	var groupinfo userinfo.GroupInfo
	groupinfo.Groupname = r.PostFormValue("groupname")
	members := r.PostFormValue("members")
	//check if groupname given by user exists or not
	GroupExistsornot, _, err := state.Userinfo.GroupnameExistsornot(groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if !GroupExistsornot {
		log.Println("Bad request!")
		http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
		return
	}
	IsgroupAdmin, err := state.Userinfo.IsgroupAdminorNot(username, groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if !IsgroupAdmin && !state.Userinfo.UserisadminOrNot(username) {
		log.Println("you are not authorized!", username)
		http.Error(w, fmt.Sprint("you are not authorized to remove members from this group!"), http.StatusBadRequest)
		return
	}

	//check if given member exists or not and see if he is already a groupmember if yes continue.
	for _, member := range strings.Split(members, ",") {
		userExistsornot, err := state.Userinfo.UsernameExistsornot(member)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if !userExistsornot {
			log.Println("Bad request!")
			http.Error(w, fmt.Sprint("Bad request! Check if the usernames exists or not!"), http.StatusBadRequest)
			return
		}
		IsgroupMember, _, err := state.Userinfo.IsgroupmemberorNot(groupinfo.Groupname, member)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if IsgroupMember {
			continue
		}
		groupinfo.MemberUid = append(groupinfo.MemberUid, member)
		groupinfo.Member = append(groupinfo.Member, state.Userinfo.CreateuserDn(member))
	}

	err = state.Userinfo.DeletemembersfromGroup(groupinfo)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	generateHTML(w, Response{UserName: username}, "index", "admins_sidebar", "deletemembersfromgroup_success")

}

func (state *RuntimeState) createserviceAccountPageHandler(w http.ResponseWriter, r *http.Request) {
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

	response := Response{username, [][]string{Allgroups}, nil, nil}

	generateHTML(w, response, "index", "admins_sidebar", "create_service_account")

}

func (state *RuntimeState) createServiceAccounthandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
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
	accountType := r.PostFormValue("Service Account Type")
	groupinfo.Groupname = r.PostFormValue("AccountName")
	groupinfo.Mail = r.PostFormValue("Email Address")

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

	err = state.Userinfo.CreateServiceAccount(groupinfo, accountType)

	if err != nil {
		log.Println(err)
		http.Error(w, "error occurred! May be group name exists or may be members are not available!", http.StatusInternalServerError)
		return
	}
	generateHTML(w, Response{UserName: username}, "index", "admins_sidebar", "serviceacc_creation_success")
}
