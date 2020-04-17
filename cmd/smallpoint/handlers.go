package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Symantec/ldap-group-management/lib/userinfo"

	"github.com/Symantec/keymaster/lib/instrumentedwriter"
)

const postMethod = "POST"
const getMethod = "GET"

var errCSRFToRootRedirected = errors.New("POST to /  detected... redirecting")

func checkCSRF(w http.ResponseWriter, r *http.Request) (bool, error) {
	if r.Method != getMethod {
		//Plain post to / will receive a redirect for compatibility
		if r.Method == "POST" && r.URL.Path[:] == "/" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return false, errCSRFToRootRedirected
		}
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

func (state *RuntimeState) writeFailureResponse(w http.ResponseWriter, r *http.Request, message string, code int) {
	pageData := simpleMessagePageData{
		Title:        "Error",
		ErrorMessage: fmt.Sprintf("%d %s. %s\n", code, http.StatusText(code), message),
	}
	if code == 404 {
		pageData.ContinueURL = "/"
	}
	w.WriteHeader(code)
	state.renderTemplateOrReturnJson(w, r, "simpleMessagePage", pageData)

}

func (state *RuntimeState) defaultPathHandler(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path == "/favicon.ico" {
		w.Header().Set("Cache-Control", "public, max-age=120")
		http.Redirect(w, r, "/images/favicon.ico", http.StatusFound)
		return
	}

	//redirect to profile
	if r.URL.Path[:] == "/" {
		//landing page
		state.mygroupsHandler(w, r)
		return

	}
	state.writeFailureResponse(w, r, "The URL you are looking for does not exist. You might be lost", http.StatusNotFound)
}

func (state *RuntimeState) autoAddtoGroups(username string) error {
	addtoGroups := state.Config.Base.AutoGroups
	for _, group := range addtoGroups {
		var groupinfo userinfo.GroupInfo
		groupinfo.Groupname = group
		groupinfo.MemberUid = append(groupinfo.MemberUid, username)

		err := state.Userinfo.AddmemberstoExisting(groupinfo)
		if err != nil {
			log.Println(err)
			return err
		}
	}
	return nil
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
		email, givenName, err := state.UserSourceinfo.GetUserAttributes(username)
		if err != nil {
			log.Println(err)
			return err
		}
		if len(email) == 0 {
			log.Println(fmt.Errorf("No email found for %s from Okta", username))
			return err
		}
		oktaid := username
		username = strings.Join(strings.Split(strings.Split(email[0], "@")[0], "."), "_")

		err = state.Userinfo.CreateOktaUser(username, oktaid, givenName, email)
		if err != nil {
			log.Println(err)
			return err
		}
		err = state.autoAddtoGroups(username)
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

func setLoggerUsername(w http.ResponseWriter, authUser string) {
	_, ok := w.(*instrumentedwriter.LoggingWriter)
	if ok {
		w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
	}
}

func (state *RuntimeState) GetRemoteUserName(w http.ResponseWriter, r *http.Request) (string, error) {
	_, err := checkCSRF(w, r)
	if err != nil {
		log.Println(err)
		if err != errCSRFToRootRedirected {
			http.Error(w, fmt.Sprint(err), http.StatusUnauthorized)
		}
		return "", err
	}
	username, err := state.authenticator.GetRemoteUserName(w, r)
	if err != nil {
		return "", err
	}
	setLoggerUsername(w, username)

	//TODO: add test case for it
	err = state.createUserorNot(username)
	if err != nil {
		log.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return "", err
	}
	return username, err
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
	state.renderTemplateOrReturnJson(w, r, "allGroupsPage", pageData)
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
		state.writeFailureResponse(w, r, "POST Method is required", http.StatusMethodNotAllowed)
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
	state.renderTemplateOrReturnJson(w, r, "simpleMessagePage", pageData)
}

//delete access requests made by user
func (state *RuntimeState) deleteRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != postMethod {
		state.writeFailureResponse(w, r, "POST Method is required", http.StatusMethodNotAllowed)
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
		state.writeFailureResponse(w, r, "POST Method is required", http.StatusMethodNotAllowed)
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
		//log.Printf("cleanupPendingRequests: top of loop entry=%+v", entry)
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

const userPendingActionsCacheDuration = time.Second * 5

func (state *RuntimeState) getUserPendingActions(username string) ([][]string, error) {
	var err error
	state.pendingUserActionsCacheMutex.Lock()
	entry, ok := state.pendingUserActionsCache[username]
	state.pendingUserActionsCacheMutex.Unlock()
	if !ok { //new value
		entry.Groups, err = state.getUserPendingActionsNonCached(username)
		if err != nil {
			return nil, err
		}
		entry.Expiration = time.Now().Add(userPendingActionsCacheDuration)
		state.pendingUserActionsCacheMutex.Lock()
		state.pendingUserActionsCache[username] = entry
		state.pendingUserActionsCacheMutex.Unlock()
		return entry.Groups, nil
	}
	if entry.Expiration.After(time.Now()) {
		return entry.Groups, nil
	}
	groups, err := state.getUserPendingActionsNonCached(username)
	if err != nil {
		//send cached data
		return entry.Groups, nil
	}
	entry.Groups = groups
	entry.Expiration = time.Now().Add(userPendingActionsCacheDuration)
	state.pendingUserActionsCacheMutex.Lock()
	state.pendingUserActionsCache[username] = entry
	state.pendingUserActionsCacheMutex.Unlock()
	return entry.Groups, nil
}

func (state *RuntimeState) getUserPendingActionsNonCached(username string) ([][]string, error) {
	go state.Userinfo.GetAllGroupsManagedBy() //warm up cache
	go state.cleanupPendingRequests()

	c := make(chan error)

	var DBentries [][]string
	go func(c chan error, DBentries *[][]string) {
		var err error
		*DBentries, err = getDBentries(state)
		if err != nil {
			log.Printf("getUserPendingActions: getDBEntries err: %s", err)
			c <- err
		}
		c <- nil
	}(c, &DBentries)

	var userGroups []string
	go func(c chan error, userGroups *[]string) {
		var err error
		*userGroups, err = state.Userinfo.GetgroupsofUser(username)
		if err != nil {
			c <- err
		}
		c <- nil
	}(c, &userGroups)
	//wait and check for err
	for i := 0; i < 2; i++ {
		err := <-c
		if err != nil {
			return nil, err
		}
	}
	//TODO, fast returns on empty DB entries

	sort.Strings(userGroups)

	//no need to paralelize this explicitly as it is paralelized by the cache warmup
	allGroups, err := state.Userinfo.GetAllGroupsManagedBy()
	if err != nil {
		return nil, err
	}
	group2manager := make(map[string]string)
	for _, entry := range allGroups {
		group2manager[entry[0]] = entry[1]
	}

	var rvalue [][]string
	for _, entry := range DBentries {
		//log.Printf("getUserPendingActions: top of loop entry=%+v", entry)
		groupName := entry[1]
		//requestingUser := entry[0]
		//fmt.Println(groupName)
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
		state.writeFailureResponse(w, r, "POST Method is required", http.StatusMethodNotAllowed)
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
			err = deleteEntryInDB(requestingUser, requestedGroup, state)
			if err != nil {
				//fmt.Println("error me")
				log.Println(err)
			}
			continue

		}
		var groupinfo userinfo.GroupInfo
		groupinfo.Groupname = requestedGroup
		groupinfo.MemberUid = append(groupinfo.MemberUid, requestingUser)
		err = state.Userinfo.AddmemberstoExisting(groupinfo)
		if err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		if state.sysLog != nil {
			state.sysLog.Write([]byte(fmt.Sprintf("%s"+" joined Group "+"%s"+" approved by "+"%s", requestingUser, requestedGroup, authUser)))
		}
		err = deleteEntryInDB(requestingUser, requestedGroup, state)
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
		state.writeFailureResponse(w, r, "POST Method is required", http.StatusMethodNotAllowed)
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

	if len(groupinfo.MemberUid) > 0 {
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
	state.renderTemplateOrReturnJson(w, r, "simpleMessagePage", pageData)
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
	state.renderTemplateOrReturnJson(w, r, "simpleMessagePage", pageData)
}

func (state *RuntimeState) createserviceAccountPageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	isAdmin := state.Userinfo.UserisadminOrNot(username)

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

func (state *RuntimeState) permissionmanageWebpageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := state.GetRemoteUserName(w, r)
	if err != nil {
		return
	}
	isAdmin := state.Userinfo.UserisadminOrNot(username)
	if !isAdmin {
		http.Error(w, "you are not authorized", http.StatusForbidden)
		return
	}
	pageData := permManagePageData{
		Title:    "Permission Management",
		IsAdmin:  isAdmin,
		UserName: username,
	}
	setSecurityHeaders(w)
	w.Header().Set("Cache-Control", "private, max-age=30")
	err = state.htmlTemplate.ExecuteTemplate(w, "permManagePage", pageData)
	if err != nil {
		log.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}
