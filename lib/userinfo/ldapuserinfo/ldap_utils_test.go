package ldapuserinfo

import (
	"log"
	"testing"
)

const (
	groupname = "aaa.test.yunchao"
	username  = "yunchao_liu"
)

func Test_GetallUsers(t *testing.T) {
	//var result []string
	var u UserInfoLDAPSource
	_, err := u.GetallUsers()
	if err != nil {
		log.Println(err)
	}
}

func Test_GetallGroups(t *testing.T) {
	//var result []string
	var u UserInfoLDAPSource
	_, err := u.GetallGroups()
	if err != nil {
		log.Println(err)
	}
}

func Test_GetgroupsofUser(t *testing.T) {
	var groups []string
	var u UserInfoLDAPSource
	groups, err := u.GetgroupsofUser(username)
	if err != nil {
		log.Println(err)
	}
	if len(groups) != 7 {
		log.Println(groups)
	}
}

func Test_GetusersofGroup(t *testing.T) {
	var u UserInfoLDAPSource
	users, description, err := u.GetusersofaGroup(groupname)
	if err != nil {
		log.Println(err)
	}
	if len(users) != 1 {
		log.Println(description)
	}
}

func Test_isgroupmemberornot(t *testing.T) {
	var u UserInfoLDAPSource
	result, description, err := u.IsgroupmemberorNot(groupname, username)
	if err != nil {
		log.Println(err)
	}
	if !result {
		log.Println(description)
	}
}

func Test_GetDescriptionvalue(t *testing.T) {
	var u UserInfoLDAPSource
	description, err := u.GetDescriptionvalue(groupname)
	if err != nil {
		log.Println(err)
	}
	if description != "" {
		log.Println(description)
	}
}

func Test_UsernameExistsornot(t *testing.T) {
	var u UserInfoLDAPSource
	result, err := u.UsernameExistsornot(username)
	if err != nil {
		log.Println(err)
	}
	if !result {
		log.Println(username)
	}
}

func Test_GroupnameExistsornot(t *testing.T) {
	var u UserInfoLDAPSource
	result, description, err := u.GroupnameExistsornot(groupname)
	if err != nil {
		log.Println(err)
	}
	if !result {
		log.Println(description)
	}
}
