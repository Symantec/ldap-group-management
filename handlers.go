package main

import (
	"net/http"
	"log"
	"sort"
	"fmt"
	"strings"
	"encoding/json"
)

//Main page with all LDAP groups displayed
func  (state *RuntimeState) Index_Handler(w http.ResponseWriter, r *http.Request) {
	userInfo, err := authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	Allgroups, err := state.get_allGroups(state.Config.TargetLDAP.GroupSearchBaseDNs)

	if err != nil {
		log.Panic(err)
	}
	sort.Strings(Allgroups)
	user := *userInfo.Username
	response := Response{user, Allgroups, nil,nil}
	//response.UserName=*userInfo.Username
	if (state.userisAdminOrNot(user)==true) {
		generateHTML(w,response,"index","admins_sidebar","groups")

	} else {
		generateHTML(w, response, "index", "sidebar","groups")
	}
}


//Group page.
func (state *RuntimeState) Group_Handler(w http.ResponseWriter, r *http.Request){
	vals := r.URL.Query()

	generateHTML(w,vals.Get("groupname"),"index","sidebar","group_info")

}


//User Groups page
func (state *RuntimeState) MyGroups_Handler(w http.ResponseWriter,r *http.Request){
	userInfo, err := authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	username := *userInfo.Username
	user_groups,err:=state.getGroupsOfUser(state.Config.TargetLDAP.GroupSearchBaseDNs,username)
	if(err!=nil){
		log.Println(err)
	}
	sort.Strings(user_groups)
	response:=Response{username,user_groups,nil,nil}
	if state.userisAdminOrNot(response.UserName) {
		generateHTML(w, response, "index", "admins_sidebar", "my_groups")
	} else{
		generateHTML(w,response,"index","sidebar","my_groups")
	}
}


//user's pending requests
func (state *RuntimeState) pending_Requests(w http.ResponseWriter,r *http.Request) {
	userInfo, err := authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	username := *userInfo.Username
	groupnames, _, _ := state.findrequestsofUserinDB(username)
	response := Response{UserName: username, Groups: groupnames, Users: nil,Pending_actions:nil}
	if groupnames == nil {
		if state.userisAdminOrNot(username) == true {
			generateHTML(w, response, "index", "admins_sidebar", "no_pending_requests")

		} else {
			generateHTML(w, response, "index", "sidebar", "no_pending_requests")
		}
	} else {
		if state.userisAdminOrNot(username) == true {
			generateHTML(w, response, "index", "admins_sidebar", "pending_requests")

		} else {
			generateHTML(w, response, "index", "sidebar", "pending_requests")
		}
	}
}


func (state *RuntimeState) creategroup_WebpageHandler(w http.ResponseWriter, r *http.Request){
	userInfo, err := authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	username := *userInfo.Username
	Allgroups, err := state.get_allGroups(state.Config.TargetLDAP.GroupSearchBaseDNs)

	if err != nil {
		log.Panic(err)
	}
	sort.Strings(Allgroups)
	response:=Response{username,Allgroups,nil,nil}
	if state.userisAdminOrNot(username){
		generateHTML(w,response,"index","admins_sidebar","create_group")
	} else {
		http.NotFoundHandler()
	}
}


func (state *RuntimeState) deletegroup_WebpageHandler(w http.ResponseWriter, r *http.Request){
	userInfo, err := authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	username := *userInfo.Username
	response:=Response{username,nil,nil,nil}
	if state.userisAdminOrNot(username){
		generateHTML(w,response,"index","admins_sidebar","delete_group")
	} else {
		http.NotFoundHandler()
	}
}


//requesting access by users to join in groups...
func (state *RuntimeState) request_AccessHandler(w http.ResponseWriter,r *http.Request) {
	userInfo, err := authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	username := *userInfo.Username
	var out map[string][]string
	err = json.NewDecoder(r.Body).Decode(&out)
	if err != nil {
		panic(err)
	}
	log.Println(out)
	fmt.Print(out["groups"])
	err = state.insertRequestInDB(username, out["groups"])
	if err != nil {
		http.Error(w, "oops! an error occured.", http.StatusInternalServerError)
		log.Println(err)
	}
	if state.userisAdminOrNot(username) == true {
		generateHTML(w, Response{UserName:username}, "index","admins_sidebar", "Accessrequestsent")

	} else {
		generateHTML(w, Response{UserName:username}, "index","sidebar","Accessrequestsent")
	}
}


//delete access requests made by user
func (state *RuntimeState) delete_requests(w http.ResponseWriter,r *http.Request) {
	userInfo, err :=authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	username := *userInfo.Username
	var out map[string][]string
	err = json.NewDecoder(r.Body).Decode(&out)
	if err != nil {
		panic(err)
	}
	for _,entry := range out["groups"] {
		err = state.deleteEntryInDB(username,entry)
		if err!=nil{
			log.Println(err)
		}
	}
}

//Parses post info from create group button click.
func (state *RuntimeState) Addmembers_toGroup(w http.ResponseWriter,r *http.Request){
	userInfo, err :=authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	username := *userInfo.Username
	if state.userisAdminOrNot(username) {
		err := r.ParseForm()
		if err != nil {
			panic("Cannot parse form")
		}
		var groupinfo group_info
		groupinfo.groupname = r.PostFormValue("groupname")
		members := r.PostFormValue("members")
		for _, member := range strings.Split(members, ",") {
			groupinfo.memberUid = append(groupinfo.memberUid, member)
			groupinfo.member = append(groupinfo.member, state.Create_UserDN(member))
		}
		err = state.create_Group(groupinfo)
		if err != nil {
			panic(err)
		}
	} else {
		http.NotFoundHandler()
	}

}


func (state *RuntimeState) exitfrom_group(w http.ResponseWriter,r *http.Request){
	userInfo, err :=authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	username := *userInfo.Username
	var out map[string][]string
	err = json.NewDecoder(r.Body).Decode(&out)
	if err != nil {
		panic(err)
	}
	var groupinfo group_info
	groupinfo.member=append(groupinfo.member,state.Create_UserDN(username))
	groupinfo.memberUid=append(groupinfo.memberUid,username)
	for _,entry := range out["groups"] {
		groupinfo.groupname=entry
		err = state.Deletemembers_fromgroup(groupinfo)
		if err!=nil{
			log.Println(err)
		}
	}
}




func (state *RuntimeState) Addmembers_webpagehandler(w http.ResponseWriter,r *http.Request){


}


//User's Pending Actions
func (state *RuntimeState) pending_Actions(w http.ResponseWriter,r *http.Request){
	userInfo, err :=authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	username := *userInfo.Username
	DB_entries,err:=state.getDB_entries()
	if err!=nil{
		panic(err)
	}
	var description string
	var response Response
	response.UserName=username
	for _,entry:=range DB_entries{
		description,err=state.getDescription_value(entry[1])
		if err!=nil{
			panic(err)
		}
		if description=="self-managed"{
			if state.isGroupMemberorNot(entry[1],username){
				response.Pending_actions=append(response.Pending_actions,entry)
			}else{
				continue
			}
		} else if state.isGroupMemberorNot(description,username){
			response.Pending_actions=append(response.Pending_actions,entry)
		}
		continue
	}
	if response.Pending_actions==nil{
		if state.userisAdminOrNot(username) == true {
			generateHTML(w, response, "index", "admins_sidebar", "no_pending_actions")

		} else {
			generateHTML(w, response, "index", "sidebar", "no_pending_actions")
		}
	} else {
		if state.userisAdminOrNot(username) == true {
			generateHTML(w, response, "index", "admins_sidebar", "pending_actions")

		} else {
			generateHTML(w, response, "index", "sidebar", "pending_actions")
		}
	}
}


//Approving
func (state *RuntimeState) approve_handler(w http.ResponseWriter,r *http.Request) {
	userInfo, err :=authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	username := *userInfo.Username
	var out map[string][][]string
	err = json.NewDecoder(r.Body).Decode(&out)
	if err != nil {
		panic(err)
	}
	log.Println(out)
	log.Println(out["groups"])
	var user_pair = out["groups"]
	for _, entry := range user_pair {
		if state.isGroupMemberorNot(entry[1],entry[0]) {
			err=state.deleteEntryInDB(entry[0], entry[1])
			if err!=nil{
				fmt.Println("error me")
				log.Println(err)
			}

		} else if state.entryExistsorNot(entry[0],entry[1]) {
			var groupinfo group_info
			groupinfo.groupname = entry[1]
			groupinfo.memberUid = append(groupinfo.memberUid, entry[0])
			groupinfo.member = append(groupinfo.member, state.Create_UserDN(entry[0]))
			err := state.Addmembers_toexisting(groupinfo)
			if err != nil {
				panic(err)
			}
			err=state.deleteEntryInDB(entry[0],entry[1])
			if err!=nil{
				fmt.Println("error here!")
				log.Println(err)
			}
		}
	}
	go state.send_approve_email(username,out["groups"],r.RemoteAddr,r.UserAgent())
	//generateHTML(w,username,"index","sidebar","Accessrequestsent")
}


//Reject handler
func (state *RuntimeState) reject_handler(w http.ResponseWriter,r *http.Request){
	userInfo, err :=authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	username := *userInfo.Username
	var out map[string][][]string
	err=json.NewDecoder(r.Body).Decode(&out)
	if err!=nil{
		panic(err)
	}
	log.Println(out)
	fmt.Print(out["groups"])//[[username1,groupname1][username2,groupname2]]
	for _,entry:=range out["groups"]{
		fmt.Println(entry[0],entry[1])
		err=state.deleteEntryInDB(entry[0], entry[1])
		if err!=nil{
			fmt.Println("I am the error")
			log.Println(err)
		}
		//write logs code here
	}
	go state.send_reject_email(username,out["groups"],r.RemoteAddr,r.UserAgent())

}



// POST
// Create a group handler --required
func (state *RuntimeState) createGroup_handler(w http.ResponseWriter,r *http.Request){
	userInfo, err := authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	//vals:=r.URL.Query()
	username:=*userInfo.Username
	if state.userisAdminOrNot(username){
		err := r.ParseForm()
		if err != nil {
			panic("Cannot parse form")
		}
		var groupinfo group_info
		groupinfo.groupname = r.PostFormValue("groupname")
		groupinfo.description = r.PostFormValue("description")
		members := r.PostFormValue("members")
		for _, member := range strings.Split(members, ",") {
			groupinfo.memberUid = append(groupinfo.memberUid, member)
			groupinfo.member = append(groupinfo.member, state.Create_UserDN(member))
		}
		err = state.create_Group(groupinfo)
		if err != nil {
			http.Error(w,"error occurred! May be group name exists or may be members are not available!",http.StatusInternalServerError)
			log.Print(err)
		}
		if state.userisAdminOrNot(username) == true {
			generateHTML(w, Response{UserName:username}, "index","admins_sidebar", "groupcreation_success")

		} else {
			generateHTML(w, Response{UserName:username}, "index","sidebar","groupcreation_success")
		}
	} else {
		http.NotFoundHandler()
	}
}



//Delete groups handler --required
func (state *RuntimeState) deleteGroup_handler(w http.ResponseWriter,r *http.Request){
	userInfo, err := authSource.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	//vals:=r.URL.Query()
	username:=*userInfo.Username
	if state.userisAdminOrNot(username) {
		err := r.ParseForm()
		if err != nil {
			panic("Cannot parse form")
		}
		var groupnames []string
		groups := r.PostFormValue("groupnames")
		for _, eachGroup := range strings.Split(groups, ",") {
			groupnames = append(groupnames, eachGroup)
		}
		err = state.delete_Group(groupnames)
		if err != nil {
			http.Error(w,"error occurred! May be there is no such group!",http.StatusInternalServerError)
			log.Print(err)
		}
		err=state.deleteEntryofGroupsInDB(groupnames)
		if err!=nil{
			panic(err)
		}
		if state.userisAdminOrNot(username) == true {
			generateHTML(w, Response{UserName:username}, "index","admins_sidebar", "groupdeletion_success")

		} else {
			generateHTML(w, Response{UserName:username}, "index","sidebar","groupdeletion_success")
		}
	} else{
		http.NotFoundHandler()
	}
}

