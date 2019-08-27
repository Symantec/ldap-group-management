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
			log.Printf("ref =%s, host=%s", referer, r.Host)
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
		"default-src 'self';"+
			" script-src 'self' cdn.datatables.net maxcdn.bootstrapcdn.com code.jquery.com; "+
			" style-src 'self' cdn.datatables.net maxcdn.bootstrapcdn.com cdnjs.cloudflare.com fonts.googleapis.com 'unsafe-inline';"+
			" font-src cdnjs.cloudflare.com fonts.gstatic.com fonts.googleapis.com maxcdn.bootstrapcdn.com;"+
			" img-src 'self' cdn.datatables.net")
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

const allUsersCacheDuration = time.Hour * 1

func (state *RuntimeState) createUserorNot(username string) error {
	state.allUsersRWLock.Lock()
	expiration, ok := state.allUsersCacheValue[username]
	state.allUsersRWLock.Unlock()

	if ok && expiration.After(time.Now()) {
		return nil
	}
	found, err := state.Userinfo.UsernameExistsornot(username)
	if err != nil {
		log.Println(err)
		return err
	}
	if !found {
		err := state.Userinfo.CreateUser(username)
		if err != nil {
			log.Println(err)
			return err
		}
	}
	state.allUsersRWLock.Lock()
	state.allUsersCacheValue[username] = time.Now().Add(allUsersCacheDuration)
	state.allUsersRWLock.Unlock()
	return nil
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

	userName := *userInfo.Username

	err = state.createUserorNot(userName)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
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
			err = state.createUserorNot(clientName)
			if err != nil {
				log.Println(err)
				http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
				return "", err
			}
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
		UserName:  username,
		IsAdmin:   isAdmin,
		Title:     "My Groups",
		JSSources: []string{"/getGroups.js"},
	}
	err = state.htmlTemplate.ExecuteTemplate(w, "myGroupsPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	return
}

func (state *RuntimeState) myManagedGroupsHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	isAdmin := state.Userinfo.UserisadminOrNot(username)
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	pageData := myGroupsPageData{
		UserName:  username,
		IsAdmin:   isAdmin,
		Title:     "My Managed Groups",
		JSSources: []string{"/getGroups.js?type=managedByMe"},
	}
	err = state.htmlTemplate.ExecuteTemplate(w, "myGroupsPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	return
}

func (state *RuntimeState) getPendingRequestGroupsofUser(username string) ([][]string, error) {
	go state.Userinfo.GetAllGroupsManagedBy()
	go state.cleanupPendingRequests()
	groupsPendingInDB, _, err := findrequestsofUserinDB(username, state)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Printf("groupsPendingInDB=%+v", groupsPendingInDB)
	if len(groupsPendingInDB) == 0 {
		return [][]string{}, nil
	}

	userGroups, err := state.Userinfo.GetgroupsofUser(username)
	if err != nil {
		log.Printf("getPendingRequestGroupsofUser, GetgroupsofUser, err:%s", err)
		return nil, err
	}
	var actualPendingGroups []string
	var found bool
	for _, requestedGroupName := range groupsPendingInDB {
		found = false
		for _, userGroup := range userGroups {
			if requestedGroupName == userGroup {
				found = true
			}
			break
		}
		if !found {
			actualPendingGroups = append(actualPendingGroups, requestedGroupName)
		}
	}
	log.Printf("actualPendingGroups =%+v, len=%d", actualPendingGroups, len(actualPendingGroups))
	return state.Userinfo.GetGroupandManagedbyAttributeValue(actualPendingGroups)

}

//user's pending requests
func (state *RuntimeState) pendingRequests(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	go state.Userinfo.GetAllGroupsManagedBy() // warm up cache
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

// On cold state: 3569 ms
func (state *RuntimeState) creategroupWebpageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	// next two lines warm up cache
	go state.Userinfo.GetallUsers()
	go state.Userinfo.GetallGroups()

	isAdmin := state.Userinfo.UserisadminOrNot(username)
	pageData := createGroupPageData{
		UserName: username,
		IsAdmin:  isAdmin,
		Title:    "Create Group",
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "createGroupPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

func (state *RuntimeState) deletegroupWebpageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	go state.Userinfo.GetallGroups() //cache warmup
	isAdmin := state.Userinfo.UserisadminOrNot(username)
	pageData := deleteGroupPageData{
		UserName: username,
		IsAdmin:  isAdmin,
		Title:    "Delete Group",
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "deleteGroupPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
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
		log.Println("requestAccessHandler: Bad request! user does not exist")
		http.Error(w, fmt.Sprint("Bad request, user does not exist!"), http.StatusBadRequest)
		return
	}

	var out map[string][]string
	err = json.NewDecoder(r.Body).Decode(&out)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	//fmt.Print(out["groups"])
	for _, entry := range out["groups"] {
		err = state.groupExistsorNot(w, entry)
		if err != nil {
			return
		}
	}
	err = insertRequestInDB(username, out["groups"], state)
	if err != nil {
		log.Printf("requestAccessHandler: Error inserting request into DB err:: %s", err)
		http.Error(w, "oops! an error occured.", http.StatusInternalServerError)
		return
	}
	go state.SendRequestemail(username, out["groups"], r.RemoteAddr, r.UserAgent())

	isAdmin := state.Userinfo.UserisadminOrNot(username)
	pageData := simpleMessagePageData{
		UserName:       username,
		IsAdmin:        isAdmin,
		Title:          "Request sent Successfully",
		SuccessMessage: "Requests sent successfully, to manage your requests please visit My Pending Requests.",
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "simpleMessagePage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
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
	_, ok := out["groups"]
	if !ok {
		log.Println("Bad request, missing required JSON attributes")
		http.Error(w, fmt.Sprint("Bad request!, Bad request, missing required JSON attributes"), http.StatusBadRequest)
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
	_, ok := out["groups"]
	if !ok {
		log.Println("Bad request, missing required JSON attributes")
		http.Error(w, fmt.Sprint("Bad request!, Bad request, missing required JSON attributes"), http.StatusBadRequest)
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
	groupinfo.MemberUid = append(groupinfo.MemberUid, username)
	for _, entry := range out["groups"] {
		groupinfo.Groupname = entry
		err = state.Userinfo.DeletemembersfromGroup(groupinfo)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusBadRequest)
			return
		}
		if state.sysLog != nil {
			state.sysLog.Write([]byte(fmt.Sprintf("%s"+" exited from Group "+"%s", username, entry)))
		}
	}
	w.WriteHeader(http.StatusOK)

}

func (state *RuntimeState) cleanupPendingRequests() error {
	DBentries, err := getDBentries(state)
	if err != nil {
		log.Printf("getUserPendingActions: getDBEntries err: %s", err)
		return err
	}
	for _, entry := range DBentries {
		log.Printf("top of loop entry=%+v", entry)
		groupName := entry[1]
		requestingUser := entry[0]
		invalidGroup := false
		Ismember, _, err := state.Userinfo.IsgroupmemberorNot(groupName, requestingUser)
		if err != nil {
			if err != userinfo.GroupDoesNotExist {
				log.Printf("getUserPendingActions: isggroupmemberor not err: %s", err)
				continue
			}
			invalidGroup = true
		}
		if Ismember || invalidGroup {
			err := deleteEntryInDB(requestingUser, groupName, state)
			if err != nil {
				log.Println(err)
				return err
			}
			continue
		}
	}
	return nil
}

func (state *RuntimeState) getUserPendingActions(username string) ([][]string, error) {
	go state.Userinfo.GetAllGroupsManagedBy() //warm up cache
	go state.cleanupPendingRequests()
	DBentries, err := getDBentries(state)
	if err != nil {
		log.Printf("getUserPendingActions: getDBEntries err: %s", err)
		return nil, err
	}

	//TODO, fast returns on empty DB entries
	var rvalue [][]string

	userGroups, err := state.Userinfo.GetgroupsofUser(username)
	if err != nil {
		return nil, err
	}
	sort.Strings(userGroups)

	allGroups, err := state.Userinfo.GetAllGroupsManagedBy()
	if err != nil {
		return nil, err
	}
	group2manager := make(map[string]string)
	for _, entry := range allGroups {
		group2manager[entry[0]] = entry[1]
	}

	for _, entry := range DBentries {
		log.Printf("top of loop entry=%+v", entry)
		groupName := entry[1]
		//requestingUser := entry[0]
		fmt.Println(groupName)
		managerGroup := group2manager[groupName]

		if managerGroup == descriptionAttribute {
			managerGroup = groupName
		}

		groupIndex := sort.SearchStrings(userGroups, managerGroup)
		if groupIndex >= len(userGroups) {
			continue
		}
		if userGroups[groupIndex] != managerGroup {
			continue
		}

		rvalue = append(rvalue, entry)

	}
	return rvalue, nil
}

//User's Pending Actions
func (state *RuntimeState) pendingActions(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	go state.Userinfo.GetAllGroupsManagedBy() //warm up cache
	//DBentries, err := getDBentries(state)
	userPendingActions, err := state.getUserPendingActions(username)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	isAdmin := state.Userinfo.UserisadminOrNot(username)
	pageData := pendingActionsPageData{
		UserName:          username,
		IsAdmin:           isAdmin,
		Title:             "Pending Group Requests",
		HasPendingActions: len(userPendingActions) > 0,
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "pendingActionsPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

}

//Approving
func (state *RuntimeState) approveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		http.Error(w, "you are not authorized", http.StatusMethodNotAllowed)
		return
	}
	authUser, err := state.GetRemoteUserName(w, r)
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
	userPair, ok := out["groups"]
	if !ok {
		log.Println("Bad request, missing required JSON attributes")
		http.Error(w, fmt.Sprint("Bad request!, Bad request, missing required JSON attributes"), http.StatusBadRequest)
		return
	}
	//entry:[username1 groupname1]

	//check [username1 groupname1] exists or not
	for _, entry := range userPair {
		requestingUser := entry[0]
		requestedGroup := entry[1]
		userExistsornot, err := state.Userinfo.UsernameExistsornot(requestingUser)
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
		log.Printf("after user exists check")
		err = state.groupExistsorNot(w, requestedGroup)
		if err != nil {
			return
		}
		IsgroupAdmin, err := state.Userinfo.IsgroupAdminorNot(authUser, requestedGroup)
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
		requestingUser := entry[0]
		requestedGroup := entry[1]
		log.Printf("Loop2: requestingUser =%s requestedGroup=%s", requestingUser, requestedGroup)
		Isgroupmember, _, err := state.Userinfo.IsgroupmemberorNot(entry[1], requestingUser)
		if err != nil {
			log.Println(err)
		}
		if Isgroupmember {
			err = deleteEntryInDB(requestingUser, entry[1], state)
			if err != nil {
				//fmt.Println("error me")
				log.Println(err)
			}
			continue

		}
		var groupinfo userinfo.GroupInfo
		groupinfo.Groupname = entry[1]
		groupinfo.MemberUid = append(groupinfo.MemberUid, requestingUser)
		err = state.Userinfo.AddmemberstoExisting(groupinfo)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if state.sysLog != nil {
			state.sysLog.Write([]byte(fmt.Sprintf("%s"+" joined Group "+"%s"+" approved by "+"%s", requestingUser, entry[1], authUser)))
		}
		err = deleteEntryInDB(requestingUser, entry[1], state)
		if err != nil {
			fmt.Println("error here!")
			log.Println(err)
		}
	}
	go state.sendApproveemail(authUser, out["groups"], r.RemoteAddr, r.UserAgent())
	w.WriteHeader(http.StatusOK)

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
	_, ok := out["groups"]
	if !ok {
		log.Println("Bad request, missing required JSON attributes")
		http.Error(w, fmt.Sprint("Bad request!, Bad request, missing required JSON attributes"), http.StatusBadRequest)
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
	// warm up caches
	go state.Userinfo.GetallUsers()
	go state.Userinfo.GetallGroups()
	isAdmin := state.Userinfo.UserisadminOrNot(username)
	pageData := addMembersToGroupPagData{
		UserName: username,
		IsAdmin:  isAdmin,
		Title:    "Add Members To Group",
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "addMembersToGroupPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

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
	isAdmin, err := state.isGroupAdmin(username, groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if !isAdmin {
		log.Printf("User %s is not admin for group %s ", username, groupinfo.Groupname)
		http.Error(w, "Not authorized", http.StatusForbidden)
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
	}

	if len(groupinfo.Member) > 0 {
		err = state.Userinfo.AddmemberstoExisting(groupinfo)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
	}
	if state.sysLog != nil {
		for _, member := range strings.Split(members, ",") {
			state.sysLog.Write([]byte(fmt.Sprintf("%s"+" was added to Group "+"%s"+" by "+"%s", member, groupinfo.Groupname, username)))
		}
	}

	isGlobalAdmin := state.Userinfo.UserisadminOrNot(username)
	pageData := simpleMessagePageData{
		UserName:       username,
		IsAdmin:        isGlobalAdmin,
		Title:          "Members Successfully Added",
		SuccessMessage: "Selected Members have been successfully added to the group",
		ContinueURL:    groupinfoPath + "?groupname=" + groupinfo.Groupname,
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "simpleMessagePage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

func (state *RuntimeState) deletemembersfromGroupWebpageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	isAdmin := state.Userinfo.UserisadminOrNot(username)
	pageData := deleteMembersFromGroupPageData{
		UserName: username,
		IsAdmin:  isAdmin,
		Title:    "Delete Memebers From Group",
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "deleteMembersFromGroupPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
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
		log.Printf("no members")
		isAdmin := state.Userinfo.UserisadminOrNot(username)
		pageData := deleteMembersFromGroupPageData{
			UserName:  username,
			IsAdmin:   isAdmin,
			GroupName: groupinfo.Groupname,
			Title:     "Delete Memebers From Group",
		}
		setSecurityHeaders(w)
		w.Header().Set("Cache-Control", "private, max-age=30")
		err = state.htmlTemplate.ExecuteTemplate(w, "deleteMembersFromGroupPage", pageData)
		if err != nil {
			log.Printf("Failed to execute %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		return
	}
	log.Println("delete these members", members)
	log.Println("now continue")
	//check if groupname given by user exists or not
	err = state.groupExistsorNot(w, groupinfo.Groupname)
	if err != nil {
		return
	}
	isAdmin, err := state.isGroupAdmin(username, groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if !isAdmin {
		log.Printf("Unauthorized")
		http.Error(w, fmt.Sprint(err), http.StatusForbidden)
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
	}

	err = state.Userinfo.DeletemembersfromGroup(groupinfo)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if state.sysLog != nil {
		for _, member := range strings.Split(members, ",") {
			state.sysLog.Write([]byte(fmt.Sprintf("%s was deleted from Group %s by %s", member, groupinfo.Groupname, username)))
		}
	}
	isGlobalAdmin := state.Userinfo.UserisadminOrNot(username)
	pageData := simpleMessagePageData{
		UserName:       username,
		IsAdmin:        isGlobalAdmin,
		Title:          "Members Successfully Deleted",
		SuccessMessage: "Selected Members have been successfully deleted from the group",
		ContinueURL:    groupinfoPath + "?groupname=" + groupinfo.Groupname,
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "simpleMessagePage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

func (state *RuntimeState) createserviceAccountPageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	isAdmin := state.Userinfo.UserisadminOrNot(username)
	if !isAdmin {
		http.Error(w, "you are not authorized", http.StatusForbidden)
		return
	}
	pageData := createServiceAccountPageData{
		UserName: username,
		IsAdmin:  isAdmin,
		Title:    "Create Service Account",
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "createServiceAccountPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

func (state *RuntimeState) groupExistsorNot(w http.ResponseWriter, groupname string) error {
	GroupExistsornot, _, err := state.Userinfo.GroupnameExistsornot(groupname)
	if err != nil {
		log.Println(err)
		if err == userinfo.GroupDoesNotExist {
			http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
		} else {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		}
		return err
	}
	if !GroupExistsornot {
		log.Println("Bad request!")
		http.Error(w, fmt.Sprint("Bad request!"), http.StatusBadRequest)
		return err
	}
	return nil
}

func (state *RuntimeState) isGroupAdmin(username string, groupname string) (bool, error) {
	IsgroupAdmin, err := state.Userinfo.IsgroupAdminorNot(username, groupname)
	if err != nil {
		if err == userinfo.GroupDoesNotExist {
			return false, nil
		}
		return false, err
	}
	if IsgroupAdmin {
		return true, nil
	}
	return state.Userinfo.UserisadminOrNot(username), nil
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

	go state.Userinfo.GetallUsers() //warm up cache

	//var response Response

	groupName := params[0] //username is "cn" Attribute of a User
	groupMembers, managerMembers, managedby, err := state.Userinfo.GetGroupUsersAndManagers(groupName)
	if err != nil {
		log.Println(err)
		if err == userinfo.GroupDoesNotExist {
			http.Error(w, fmt.Sprint("Group doesn't exist!"), http.StatusBadRequest)
			return
		}
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	IsgroupMember := false
	for _, user := range groupMembers {
		if user == username {
			IsgroupMember = true
			break
		}
	}
	IsgroupAdmin := false
	for _, user := range managerMembers {
		if user == username {
			IsgroupAdmin = true
			break
		}
	}

	isAdmin := state.Userinfo.UserisadminOrNot(username)
	pageData := groupInfoPageData{
		UserName:            username,
		IsAdmin:             isAdmin,
		Title:               "Group information for group X",
		IsMember:            IsgroupMember,
		IsGroupAdmin:        IsgroupAdmin || isAdmin,
		GroupName:           groupName,
		GroupManagedbyValue: managedby,
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=15")
	err = state.htmlTemplate.ExecuteTemplate(w, "groupInfoPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

func (state *RuntimeState) changeownershipWebpageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	isAdmin := state.Userinfo.UserisadminOrNot(username)
	if !isAdmin {
		http.Error(w, "you are not authorized", http.StatusForbidden)
		return
	}
	pageData := changeGroupOwnershipPageData{
		UserName: username,
		IsAdmin:  isAdmin,
		Title:    "Change Group OwnerShip",
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "changeGroupOwnershipPage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}
