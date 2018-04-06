package main

import (
	"strings"
	"fmt"
	"log"
	"gopkg.in/ldap.v2"

	"strconv"
)

//Get all ldap users and put that in map ---required
func (state *RuntimeState) GetallUsers(UserSearchBaseDNs string, UserSearchFilter string, Attributes []string) (map[string]string, error) {
	AllUsersinLdap := make(map[string]string)

	searchrequest := ldap.NewSearchRequest(UserSearchBaseDNs, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false, UserSearchFilter, Attributes, nil)
	result, err := state.target_ldap.Search(searchrequest)
	if err != nil {
		return nil, err
	}

	if len(result.Entries) == 0 {
		log.Println("No records found")
	}
	for _, entry := range result.Entries {
		uid := entry.GetAttributeValue("uid")
		AllUsersinLdap[uid] = uid
	}

	return AllUsersinLdap, nil
}




//To build a user base DN using uid only for Target LDAP.
func (state *RuntimeState) Create_UserDN(username string) string {
	//uid := username
	result := "uid=" + username + "," +state.Config.TargetLDAP.UserSearchBaseDNs

	return string(result)

}



//To build a GroupDN for a particular group in Target ldap
func (state *RuntimeState) Create_GroupDN(groupname string) string {
	result := "cn=" + groupname + "," + state.Config.TargetLDAP.GroupSearchBaseDNs

	return string(result)

}

//Creating a Group --required
func (state *RuntimeState) create_Group(groupinfo group_info) error{
	entry:=state.Create_GroupDN(groupinfo.groupname)
	gidnum,err:=state.current_maximumGidNumber()
	if err!=nil{
		panic(err)
	}
	group:=ldap.NewAddRequest(entry)
	group.Attribute("objectClass",[]string{"posixGroup","top","groupOfNames"})
	group.Attribute("cn",[]string{groupinfo.groupname})
	group.Attribute("description",[]string{groupinfo.description})
	group.Attribute("member",groupinfo.member)
	group.Attribute("memberUid",groupinfo.memberUid)
	group.Attribute("gidNumber",[]string{gidnum})
	err=state.target_ldap.Add(group)
	if err!=nil{
		return err
	}
	return nil
}

//deleting a Group from target ldap. --required
func (state *RuntimeState) delete_Group(groupnames []string) error{
	for _,entry:=range groupnames {
		group_dn:=state.Create_GroupDN(entry)

		del_req := ldap.NewDelRequest(group_dn,nil)
		err:=state.target_ldap.Del(del_req)
		if(err!=nil){
			return err
		}

	}
	return nil
}


//Adding an attritube called 'description' to a dn in Target Ldap --required
func (state *RuntimeState) addAtributeDescription(groupname string)error{

	entry:=state.Create_GroupDN(groupname)
	modify := ldap.NewModifyRequest(entry)
	modify.Delete("description", []string{"self-managed"})

	//modify.Add("description", []string{"created by me"})
	err := state.target_ldap.Modify(modify)
	if err != nil {
		return err
	}
	return nil

}

//Deleting the attribute in a dn in Target Ldap. --required
func (state *RuntimeState) deleteDescription(result []string) error {
	for _, entry := range result {
		entry = state.Create_GroupDN(entry)

		modify := ldap.NewModifyRequest(entry)

		modify.Delete("description", []string{"created by Midpoint"})
		err := state.target_ldap.Modify(modify)
		if err != nil {
			return err
		}
	}
	return nil
}


//function to get details of a user from Target ldap.(should make some changes) --required
func (state *RuntimeState) UserInfo(User_dn string) ([]string, error) {
	var user_info []string
	searchrequest := ldap.NewSearchRequest(User_dn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "((objectClass=*))", nil, nil)
	result, err := state.target_ldap.Search(searchrequest)
	if err != nil {
		return nil, err
	}
	for _, entry := range result.Entries {
		user_info = entry.GetAttributeValues("objectClass")
		//println(entry.GetAttributeValue(entry.Attributes[5].Name))
	}
	return user_info, nil
}



//function to get all the groups in Target ldap and put it in array --required
func (state *RuntimeState) get_allGroups(Group_dn string) ([]string, error) {
	var All_Groups []string
	searchrequest := ldap.NewSearchRequest(Group_dn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(|(objectClass=posixGroup)(objectClass=groupofNames))", []string{"cn"}, nil)
	result, err := state.target_ldap.Search(searchrequest)
	if err != nil {
		return nil, err
	}
	for _, entry := range result.Entries {
		All_Groups = append(All_Groups, entry.GetAttributeValue("cn"))
	}
	return All_Groups, nil
}



// GetGroupsOfUser returns the all groups of a user. --required
func (state *RuntimeState) getGroupsOfUser(groupdn string, username string) ([]string, error) {
	Base := groupdn
	searchRequest := ldap.NewSearchRequest(
		Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(memberUid="+username+" ))",
		[]string{"cn"}, //memberOf (if searching other way around using usersdn instead of groupdn)
		nil,
	)
	sr, err := state.target_ldap.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}



//returns all the users of a group --required
func (state *RuntimeState) getUsersofaGroup(groupname string) ([][]string, error) {
	Base := state.Create_GroupDN(groupname)

	searchRequest := ldap.NewSearchRequest(
		Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"((objectClass=*))",
		[]string{"memberUid"},
		nil,
	)
	sr, err := state.target_ldap.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	users := [][]string{}
	for _, entry := range sr.Entries {
		users = append(users, entry.GetAttributeValues("memberUid"))
	}
	return users, nil
}





//parse super admins of Target Ldap
func (state *RuntimeState) parseSuperAdmins()([]string){
	var superAdminsInfo []string
	for _, admin := range strings.Split(state.Config.TargetLDAP.Admins, ",") {
		fmt.Print(admin)
		superAdminsInfo = append(superAdminsInfo,admin)
	}
	return superAdminsInfo
}

//if user is super admin or not
func (state *RuntimeState) userisAdminOrNot(username string)(bool){
	superAdmins:=state.parseSuperAdmins()
	fmt.Print(superAdmins)
	for _,user:=range superAdmins{
		if user==username{
			return true
		}
	}
	return false
}



//it helps to findout the current maximum gid number in ldap.
func (state *RuntimeState) current_maximumGidNumber()(string,error){
	searchRequest := ldap.NewSearchRequest(
		state.Config.TargetLDAP.GroupSearchBaseDNs,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(|(objectClass=posixGroup)(objectClass=groupOfNames))",
		[]string{"gidNumber"},
		nil,
	)
	sr, err := state.target_ldap.Search(searchRequest)
	if err != nil {
		return "error in ldapsearch", err
	}
	var max=0
	for _,entry:=range sr.Entries{
		gidnum:=entry.GetAttributeValue("gidNumber")
		value,_:=strconv.Atoi(gidnum)
		//if err!=nil{
		//	panic(err)
		//}
		if value>max {
			max=value
		}
	}
	fmt.Println(max)
	return string(max+1),nil
}


//adding members to existing group
func (state *RuntimeState) Addmembers_toexisting(groupinfo group_info)error{
	entry:=state.Create_GroupDN(groupinfo.groupname)
	modify := ldap.NewModifyRequest(entry)
	modify.Add("memberUid", groupinfo.memberUid)
	modify.Add("member",groupinfo.member)
	err := state.target_ldap.Modify(modify)
	if err != nil {
		return err
	}
	return nil
}

//remove members from existing group
func (state *RuntimeState) Deletemembers_fromgroup(groupinfo group_info)error{
	entry:=state.Create_GroupDN(groupinfo.groupname)
	modify:=ldap.NewModifyRequest(entry)
	modify.Delete("memberUid",groupinfo.memberUid)
	modify.Delete("member",groupinfo.member)
	err:=state.target_ldap.Modify(modify)
	if err!=nil{
		return err
	}
	return nil
}


//if user is already a member of group or not
func (state *RuntimeState) isGroupMemberorNot(groupname string,username string)bool{

	AllUsersinGroup, err := state.getUsersofaGroup(groupname)
	if err!=nil{
		panic(err)
	}
	for _,entry:=range AllUsersinGroup[0]{
		if entry==username{
			return true
		}
	}
	return false
}

//get description of a group
func (state *RuntimeState) getDescription_value(groupname string)(string,error){
	Base := state.Create_GroupDN(groupname)

	searchRequest := ldap.NewSearchRequest(
		Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"((objectClass=*))",
		[]string{"description"},
		nil,
	)
	sr, err := state.target_ldap.Search(searchRequest)
	if err != nil {
		return "",err
	}
	var result string
	for _,entry:= range sr.Entries{
		result=entry.GetAttributeValue("description")
	}
	return result,nil
}

//get email of a user
func (state *RuntimeState) getEmailofaUser(username string)([]string,error){
	var user_email []string
	User_dn := state.Create_UserDN(username)
	searchrequest := ldap.NewSearchRequest(User_dn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "((objectClass=*))", []string{"mail"}, nil)
	result, err := state.target_ldap.Search(searchrequest)
	if err != nil {
		return nil, err
	}
	user_email = append(user_email, result.Entries[0].GetAttributeValues("mail")[0])
	return user_email,nil

}

//get email of all users in the given group
func (state *RuntimeState) getEmailofUsersinGroup(groupname string)([]string,error){
	group_users,err:=state.getUsersofaGroup(groupname)
	if err!=nil{
		log.Println(err)
	}
	var user_email []string
	for _,entry:=range group_users[0]{
		value,err:=state.getEmailofaUser(entry)
		if err != nil {
			return nil, err
		}
		user_email=append(user_email,value[0])

	}
	return user_email, nil
}

