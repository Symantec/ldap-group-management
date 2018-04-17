package main

import (
	"fmt"
	"gopkg.in/ldap.v2"
	"log"
	"strings"

	"strconv"
)

//Get all ldap users and put that in map ---required
func (state *RuntimeState) GetallUsers(UserSearchBaseDNs string, UserSearchFilter string, Attributes []string,TargetLDAPConn *ldap.Conn) (map[string]string, error) {
	AllUsersinLdap := make(map[string]string)

	searchrequest := ldap.NewSearchRequest(UserSearchBaseDNs, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false, UserSearchFilter, Attributes, nil)
	result, err := TargetLDAPConn.Search(searchrequest)
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
func (state *RuntimeState) CreateuserDn(username string) string {
	//uid := username
	result := "uid=" + username + "," + state.Config.TargetLDAP.UserSearchBaseDNs

	return string(result)

}

//To build a GroupDN for a particular group in Target ldap
func (state *RuntimeState) CreategroupDn(groupname string) string {
	result := "cn=" + groupname + "," + state.Config.TargetLDAP.GroupSearchBaseDNs

	return string(result)

}

//Creating a Group --required
func (state *RuntimeState) createGroup(groupinfo groupInfo,TargetLDAPConn *ldap.Conn) error {
	entry := state.CreategroupDn(groupinfo.groupname)
	gidnum, err := state.GetmaximumGidnumber(TargetLDAPConn)
	if err != nil {
		panic(err)
	}
	group := ldap.NewAddRequest(entry)
	group.Attribute("objectClass", []string{"posixGroup", "top", "groupOfNames"})
	group.Attribute("cn", []string{groupinfo.groupname})
	group.Attribute("description", []string{groupinfo.description})
	group.Attribute("member", groupinfo.member)
	group.Attribute("memberUid", groupinfo.memberUid)
	group.Attribute("gidNumber", []string{gidnum})
	err = TargetLDAPConn.Add(group)
	if err != nil {
		return err
	}
	return nil
}

//deleting a Group from target ldap. --required
func (state *RuntimeState) deleteGroup(groupnames []string,TargetLDAPConn *ldap.Conn) error {
	for _, entry := range groupnames {
		groupdn := state.CreategroupDn(entry)

		DelReq := ldap.NewDelRequest(groupdn, nil)
		err := TargetLDAPConn.Del(DelReq)
		if err != nil {
			return err
		}

	}
	return nil
}

//Adding an attritube called 'description' to a dn in Target Ldap --required
func (state *RuntimeState) AddAtributedescription(groupname string,TargetLDAPConn *ldap.Conn) error {

	entry := state.CreategroupDn(groupname)
	modify := ldap.NewModifyRequest(entry)
	modify.Delete("description", []string{"self-managed"})

	//modify.Add("description", []string{"created by me"})
	err := TargetLDAPConn.Modify(modify)
	if err != nil {
		return err
	}
	return nil

}

//Deleting the attribute in a dn in Target Ldap. --required
func (state *RuntimeState) deleteDescription(result []string,TargetLDAPConn *ldap.Conn) error {
	for _, entry := range result {
		entry = state.CreategroupDn(entry)

		modify := ldap.NewModifyRequest(entry)

		modify.Delete("description", []string{"created by Midpoint"})
		err := TargetLDAPConn.Modify(modify)
		if err != nil {
			return err
		}
	}
	return nil
}

//function to get details of a user from Target ldap.(should make some changes) --required
func (state *RuntimeState) UserInfo(Userdn string,TargetLDAPConn *ldap.Conn) ([]string, error) {
	var userinfo []string
	searchrequest := ldap.NewSearchRequest(Userdn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "((objectClass=*))", nil, nil)
	result, err := TargetLDAPConn.Search(searchrequest)
	if err != nil {
		return nil, err
	}
	for _, entry := range result.Entries {
		userinfo = entry.GetAttributeValues("objectClass")
		//println(entry.GetAttributeValue(entry.Attributes[5].Name))
	}
	return userinfo, nil
}

//function to get all the groups in Target ldap and put it in array --required
func (state *RuntimeState) getallGroups(Groupdn string,TargetLDAPConn *ldap.Conn) ([]string, error) {
	var AllGroups []string
	searchrequest := ldap.NewSearchRequest(Groupdn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(|(objectClass=posixGroup)(objectClass=groupofNames))", []string{"cn"}, nil)
	result, err := TargetLDAPConn.Search(searchrequest)
	if err != nil {
		return nil, err
	}
	for _, entry := range result.Entries {
		AllGroups = append(AllGroups, entry.GetAttributeValue("cn"))
	}
	return AllGroups, nil
}

// GetGroupsOfUser returns the all groups of a user. --required
func (state *RuntimeState) GetgroupsofUser(groupdn string, username string,TargetLDAPConn *ldap.Conn) ([]string, error) {
	Base := groupdn
	searchRequest := ldap.NewSearchRequest(
		Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(memberUid="+username+" ))",
		[]string{"cn"}, //memberOf (if searching other way around using usersdn instead of groupdn)
		nil,
	)
	sr, err := TargetLDAPConn.Search(searchRequest)
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
func (state *RuntimeState) GetusersofaGroup(groupname string,TargetLDAPConn *ldap.Conn) ([][]string, error) {
	Base := state.CreategroupDn(groupname)

	searchRequest := ldap.NewSearchRequest(
		Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"((objectClass=*))",
		[]string{"memberUid"},
		nil,
	)
	sr, err := TargetLDAPConn.Search(searchRequest)
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
func (state *RuntimeState) ParseSuperadmins() []string {
	var superAdminsInfo []string
	for _, admin := range strings.Split(state.Config.TargetLDAP.Admins, ",") {
		fmt.Print(admin)
		superAdminsInfo = append(superAdminsInfo, admin)
	}
	return superAdminsInfo
}

//if user is super admin or not
func (state *RuntimeState) UserisadminOrNot(username string) bool {
	superAdmins := state.ParseSuperadmins()
	fmt.Print(superAdmins)
	for _, user := range superAdmins {
		if user == username {
			return true
		}
	}
	return false
}

//it helps to findout the current maximum gid number in ldap.
func (state *RuntimeState) GetmaximumGidnumber(TargetLDAPConn *ldap.Conn) (string, error) {
	searchRequest := ldap.NewSearchRequest(
		state.Config.TargetLDAP.GroupSearchBaseDNs,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(|(objectClass=posixGroup)(objectClass=groupOfNames))",
		[]string{"gidNumber"},
		nil,
	)
	sr, err := TargetLDAPConn.Search(searchRequest)
	if err != nil {
		return "error in ldapsearch", err
	}
	var max = 0
	for _, entry := range sr.Entries {
		gidnum := entry.GetAttributeValue("gidNumber")
		value, _ := strconv.Atoi(gidnum)
		//if err!=nil{
		//	panic(err)
		//}
		if value > max {
			max = value
		}
	}
	fmt.Println(max)
	return fmt.Sprint(max + 1), nil
}

//adding members to existing group
func (state *RuntimeState) AddmemberstoExisting(groupinfo groupInfo,TargetLDAPConn *ldap.Conn) error {
	entry := state.CreategroupDn(groupinfo.groupname)
	modify := ldap.NewModifyRequest(entry)
	modify.Add("memberUid", groupinfo.memberUid)
	modify.Add("member", groupinfo.member)
	err := TargetLDAPConn.Modify(modify)
	if err != nil {
		return err
	}
	return nil
}

//remove members from existing group
func (state *RuntimeState) DeletemembersfromGroup(groupinfo groupInfo,TargetLDAPConn *ldap.Conn) error {
	entry := state.CreategroupDn(groupinfo.groupname)
	modify := ldap.NewModifyRequest(entry)
	modify.Delete("memberUid", groupinfo.memberUid)
	modify.Delete("member", groupinfo.member)
	err := TargetLDAPConn.Modify(modify)
	if err != nil {
		return err
	}
	return nil
}

//if user is already a member of group or not
func (state *RuntimeState) IsgroupmemberorNot(groupname string, username string,TargetLDAPConn *ldap.Conn) bool {

	AllUsersinGroup, err := state.GetusersofaGroup(groupname,TargetLDAPConn)
	if err != nil {
		panic(err)
	}
	for _, entry := range AllUsersinGroup[0] {
		if entry == username {
			return true
		}
	}
	return false
}

//get description of a group
func (state *RuntimeState) GetDescriptionvalue(groupname string,TargetLDAPConn *ldap.Conn) (string, error) {
	Base := state.CreategroupDn(groupname)

	searchRequest := ldap.NewSearchRequest(
		Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"((objectClass=*))",
		[]string{"description"},
		nil,
	)
	sr, err := TargetLDAPConn.Search(searchRequest)
	if err != nil {
		return "", err
	}
	var result string
	for _, entry := range sr.Entries {
		result = entry.GetAttributeValue("description")
	}
	return result, nil
}

//get email of a user
func (state *RuntimeState) GetEmailofauser(username string,TargetLDAPConn *ldap.Conn) ([]string, error) {
	var userEmail []string
	Userdn := state.CreateuserDn(username)
	searchrequest := ldap.NewSearchRequest(Userdn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "((objectClass=*))", []string{"mail"}, nil)
	result, err := TargetLDAPConn.Search(searchrequest)
	if err != nil {
		return nil, err
	}
	userEmail = append(userEmail, result.Entries[0].GetAttributeValues("mail")[0])
	return userEmail, nil

}

//get email of all users in the given group
func (state *RuntimeState) GetEmailofusersingroup(groupname string,TargetLDAPConn *ldap.Conn) ([]string, error) {

	groupUsers, err := state.GetusersofaGroup(groupname,TargetLDAPConn)
	if err != nil {
		log.Println(err)
	}
	var userEmail []string
	for _, entry := range groupUsers[0] {
		value, err := state.GetEmailofauser(entry,TargetLDAPConn)
		if err != nil {
			return nil, err
		}
		userEmail = append(userEmail, value[0])

	}
	return userEmail, nil
}
