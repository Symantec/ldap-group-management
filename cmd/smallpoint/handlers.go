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

func setSecurityHeaders(w http.ResponseWriter) {
	//all common security headers go here
	w.Header().Set("Strict-Transport-Security", "max-age=1209600")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' cdn.datatables.net maxcdn.bootstrapcdn.com code.jquery.com "+
			";style-src 'self' cdn.datatables.net maxcdn.bootstrapcdn.com fonts.googleapis.com 'unsafe-inline'; font-src cdnjs.cloudflare.com fonts.gstatic.com fonts.googleapis.com ")
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

	//If having a verified cert, no need for cookies
	if r.TLS != nil {
		if len(r.TLS.VerifiedChains) > 0 {
			clientName := r.TLS.VerifiedChains[0][0].Subject.CommonName
			return clientName, nil
		}
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
func (state *RuntimeState) allGroupsHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	isAdmin := state.Userinfo.UserisadminOrNot(username)
	pageData := allGroupsPageData{
		UserName: username,
		IsAdmin:  isAdmin,
		Title:    "All Groups",
	}

	returnAcceptType := state.getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		setSecurityHeaders(w)
		w.Header().Set("Cache-Control", "private, max-age=30")

		err = state.htmlTemplate.ExecuteTemplate(w, "allGroupsPage", pageData)
		if err != nil {
			log.Printf("Failed to execute %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		return
	default:
		b, err := json.MarshalIndent(pageData, "", " ")
		if err != nil {
			log.Printf("Failed marshal %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		_, err = w.Write(b)
		if err != nil {
			log.Printf("Incomplete write %v", err)
		}
	}
	return
}

//User Groups page
func (state *RuntimeState) mygroupsHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	isAdmin := state.Userinfo.UserisadminOrNot(username)
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	pageData := myGroupsPageData{
		UserName: username,
		IsAdmin:  isAdmin,
		Title:    "My Groups",
	}
	log.Printf("myGroupsPageData=%+v", pageData)
	err = state.htmlTemplate.ExecuteTemplate(w, "myGroupsPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	return
	//generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, "my_groups")
}

func (state *RuntimeState) getPendingRequestGroupsofUser(username string) ([][]string, error) {
	go state.Userinfo.GetAllGroupsManagedBy()
	t0 := time.Now()
	groupsPendingInDB, _, err := findrequestsofUserinDB(username, state)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	t1 := time.Now()
	log.Printf("findrequestsofUserinDB Took %v to run", t1.Sub(t0))
	var actualPendingGroups []string
	// TODO: replace this loop for another one where we iterate over the
	// groups of the user. This would lead to only 1 new DB connection per
	// pending group request
	for _, groupname := range groupsPendingInDB {
		t0 := time.Now()
		Ismember, _, err := state.Userinfo.IsgroupmemberorNot(groupname, username)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		t1 := time.Now()
		log.Printf("IsgroupmemberorNo Took %v to run", t1.Sub(t0))
		if Ismember {
			err := deleteEntryInDB(username, groupname, state)
			if err != nil {
				log.Println(err)
				return nil, err
			}
			continue
		}
		actualPendingGroups = append(actualPendingGroups, groupname)
	}
	log.Printf("ctualPendingGroups=%+v", actualPendingGroups)
	return state.Userinfo.GetGroupandManagedbyAttributeValue(actualPendingGroups)

}

//user's pending requests
func (state *RuntimeState) pendingRequests(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	_, hasRequests, err := findrequestsofUserinDB(username, state)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	isAdmin := state.Userinfo.UserisadminOrNot(username)
	pageData := pendingRequestsPageData{
		UserName:           username,
		IsAdmin:            isAdmin,
		Title:              "Pending Group Requests",
		HasPendingRequests: hasRequests,
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "pendingRequestsPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
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
	Allusers, err := state.Userinfo.GetallUsers()
	if err != nil {
		log.Printf("creategroupWebpageHandler, GetallUser err: %s", err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	response := Response{username, [][]string{Allgroups}, Allusers, nil, "", "", nil}

	generateHTML(w, response, state.Config.Base.TemplatesPath, "index", "admins_sidebar", "create_group")

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
	Allgroups, err := state.Userinfo.GetallGroups()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	sort.Strings(Allgroups)

	response := Response{username, [][]string{Allgroups}, nil, nil, "", "", nil}

	generateHTML(w, response, state.Config.Base.TemplatesPath, "index", "admins_sidebar", "delete_group")

}

//requesting access by users to join in groups...
func (state *RuntimeState) requestAccessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	userExistsornot, err := state.Userinfo.UsernameExistsornot(username)
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
		err = state.groupExistsorNot(w, entry)
		if err != nil {
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
	generateHTML(w, Response{UserName: username}, state.Config.Base.TemplatesPath, "index", sidebarType, "Accessrequestsent")

}

//delete access requests made by user
func (state *RuntimeState) deleteRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
		return
	}
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	userExistsornot, err := state.Userinfo.UsernameExistsornot(username)
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
	var out map[string][]string
	err = json.NewDecoder(r.Body).Decode(&out)
	if err != nil {
		log.Print(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	for _, entry := range out["groups"] {
		err = state.groupExistsorNot(w, entry)
		if err != nil {
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
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
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
		err = state.groupExistsorNot(w, entry)
		if err != nil {
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
		state.sysLog.Write([]byte(fmt.Sprintf("%s"+" exited from Group "+"%s", username, entry)))
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
			err := deleteEntryInDB(user, groupName, state)
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
		generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, "no_pending_actions")

	} else {
		generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, "pending_actions")

	}
}

//Approving
func (state *RuntimeState) approveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
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
		err = state.groupExistsorNot(w, entry[1])
		if err != nil {
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

			state.sysLog.Write([]byte(fmt.Sprintf("%s"+" joined Group "+"%s"+" approved by "+"%s", entry[0], entry[1], username)))
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
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
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
		if !entryExists {
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

	Allusers, err := state.Userinfo.GetallUsers()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	response := Response{username, [][]string{Allgroups}, Allusers, nil, "", "", nil}

	sidebarType := "sidebar"
	if state.Userinfo.UserisadminOrNot(username) {
		sidebarType = "admins_sidebar"
	}

	generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, "addpeopletogroups")

}

func (state *RuntimeState) addmemberstoExistingGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
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
	err = state.groupExistsorNot(w, groupinfo.Groupname)
	if err != nil {
		return
	}
	err = state.isGroupAdmin(w, username, groupinfo.Groupname)
	if err != nil {
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
			http.Error(w, fmt.Sprint("Bad request! Username doesn't exist!", member), http.StatusBadRequest)
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
	for _, member := range strings.Split(members, ",") {
		state.sysLog.Write([]byte(fmt.Sprintf("%s"+" was added to Group "+"%s"+" by "+"%s", member, groupinfo.Groupname, username)))
	}
	generateHTML(w, Response{UserName: username}, state.Config.Base.TemplatesPath, "index", "admins_sidebar", "addpeopletogroup_success")

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

	Allusers, err := state.Userinfo.GetallUsers()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	response := Response{username, [][]string{Allgroups}, Allusers, nil, "", "", nil}

	sidebarType := "sidebar"
	if state.Userinfo.UserisadminOrNot(username) {
		sidebarType = "admins_sidebar"
	}

	generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, "deletemembersfromgroup")

}

func (state *RuntimeState) deletemembersfromExistingGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
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
	////// TODO: @SLR9511: why is done this way?... please revisit
	if members == "" {
		AllUsersinGroup, managedby, err := state.Userinfo.GetusersofaGroup(groupinfo.Groupname)
		Allgroups, err := state.Userinfo.GetallGroups()
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		sort.Strings(Allgroups)

		response := Response{username, [][]string{Allgroups}, nil, nil, groupinfo.Groupname, managedby, AllUsersinGroup}
		sidebarType := "sidebar"
		superAdmin := state.Userinfo.UserisadminOrNot(username)
		if superAdmin {
			sidebarType = "admins_sidebar"
		}
		generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, "deletemembersfromgroup")
		return
	}
	log.Println("delete these members", members)
	log.Println("now continue")
	//check if groupname given by user exists or not
	err = state.groupExistsorNot(w, groupinfo.Groupname)
	if err != nil {
		return
	}
	err = state.isGroupAdmin(w, username, groupinfo.Groupname)
	if err != nil {
		return
	}

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
		if !IsgroupMember {
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
	for _, member := range strings.Split(members, ",") {
		state.sysLog.Write([]byte(fmt.Sprintf("%s was deleted from Group %s by %s", member, groupinfo.Groupname, username)))
	}
	generateHTML(w, Response{UserName: username}, state.Config.Base.TemplatesPath, "index", "admins_sidebar", "deletemembersfromgroup_success")

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

	response := Response{username, [][]string{Allgroups}, nil, nil, "", "", nil}

	generateHTML(w, response, state.Config.Base.TemplatesPath, "index", "admins_sidebar", "create_service_account")

}

func (state *RuntimeState) groupExistsorNot(w http.ResponseWriter, groupname string) error {
	GroupExistsornot, _, err := state.Userinfo.GroupnameExistsornot(groupname)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return err
	}
	if !GroupExistsornot {
		log.Println("Bad request!")
		http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
		return err
	}
	return nil
}

func (state *RuntimeState) isGroupAdmin(w http.ResponseWriter, username string, groupname string) error {
	IsgroupAdmin, err := state.Userinfo.IsgroupAdminorNot(username, groupname)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return err
	}
	if !IsgroupAdmin && !state.Userinfo.UserisadminOrNot(username) {
		log.Printf("isGroupAdmin: authorization failed for %s on group %s!", username, groupname)
		http.Error(w, fmt.Sprint("you are not authorized to make changes to this group!"), http.StatusBadRequest)
		return errors.New("you are not authorized to make changes to this group!")
	}
	return nil
}

func (state *RuntimeState) groupInfoWebpage(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
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
	var response Response

	groupName := params[0] //username is "cn" Attribute of a User
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
	AllUsersinGroup, managedby, err := state.Userinfo.GetusersofaGroup(groupName)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	sort.Strings(AllUsersinGroup)

	Allusers, err := state.Userinfo.GetallUsers()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	//response.Users = AllUsersinGroup
	response = Response{username, nil, Allusers, nil, groupName, managedby, AllUsersinGroup}
	superAdmin := state.Userinfo.UserisadminOrNot(username)
	sidebarType := "sidebar"
	if superAdmin {
		sidebarType = "admins_sidebar"
	}
	groupandmanagedby, err := state.Userinfo.GetGroupandManagedbyAttributeValue([]string{groupName})
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprintln(err), http.StatusInternalServerError)
		return
	}
	groupexistsornot, _, err := state.Userinfo.GroupnameExistsornot(groupandmanagedby[0][1])
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprintln(err), http.StatusInternalServerError)
		return
	}

	groupinfowebpageType := "groupinfo_member"

	IsgroupMember, _, err := state.Userinfo.IsgroupmemberorNot(groupName, username)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprintln(err), http.StatusInternalServerError)
		return
	}
	IsgroupAdmin, err := state.Userinfo.IsgroupAdminorNot(username, groupName)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	if groupandmanagedby[0][1] != "self-managed" && !groupexistsornot {
		if !superAdmin {
			groupinfowebpageType = "groupinfo_no_managedby_member_nomem"
			generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, groupinfowebpageType)
			return
		}

		if IsgroupMember {
			groupinfowebpageType = "groupinfo_member_admin"
			generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, groupinfowebpageType)
			return

		} else {
			groupinfowebpageType = "groupinfo_nonmember_admin"
			generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, groupinfowebpageType)
			return

		}
	}

	if IsgroupMember {
		if IsgroupAdmin || superAdmin {
			groupinfowebpageType = "groupinfo_member_admin"
			generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, groupinfowebpageType)

		} else {
			generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, groupinfowebpageType)
		}

	} else {
		if IsgroupAdmin || superAdmin {
			groupinfowebpageType = "groupinfo_nonmember_admin"
			generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, groupinfowebpageType)
		} else {
			groupinfowebpageType = "groupinfo_nonmember"
			generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, groupinfowebpageType)

		}
	}
}

func (state *RuntimeState) changeownershipWebpageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	t0 := time.Now()
	Allgroups, err := state.Userinfo.GetallGroups()
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	t1 := time.Now()
	log.Printf("GetAllGroups Took %v to run", t1.Sub(t0))

	sort.Strings(Allgroups)

	if !state.Userinfo.UserisadminOrNot(username) {
		http.Error(w, "you are not authorized", http.StatusUnauthorized)
		return
	}
	var Allusers []string
	response := Response{username, [][]string{Allgroups}, Allusers, nil, "", "", nil}

	sidebarType := "sidebar"
	if state.Userinfo.UserisadminOrNot(username) {
		sidebarType = "admins_sidebar"
	}

	generateHTML(w, response, state.Config.Base.TemplatesPath, "index", sidebarType, "changeownership")

}
