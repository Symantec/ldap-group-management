package main

import (
	"fmt"
	"github.com/Symantec/ldap-group-management/lib/userinfo"
	"log"
	"strconv"
	"strings"
)

type MockLdap struct {
	Groups      map[string]LdapGroupInfo
	Users       map[string]LdapUserInfo
	SuperAdmins string
	Services    map[string]LdapGroupInfo
}

type LdapGroupInfo struct {
	dn          string
	description string
	gidNumber   string
	cn          string
	objectClass []string
	member      []string
	memberUid   []string
}

const LdapUserDN = "ou=people,dc=mgmt,dc=example,dc=com"
const LdapGroupDN = "ou=groups,dc=mgmt,dc=example,dc=com"
const LdapServiceDN = "ou=services,dc=mgmt,dc=example,dc=com"

type LdapUserInfo struct {
	dn          string
	memberOf    []string
	objectClass []string
	uid         string
	mail        string
	cn          string
	description string
}

func New() *MockLdap {
	var testldap MockLdap
	testldap.Groups = make(map[string]LdapGroupInfo)
	testldap.Users = make(map[string]LdapUserInfo)
	testldap.SuperAdmins = "user1,user2"
	testldap.Services = make(map[string]LdapGroupInfo)

	testldap.Groups["cn=group1,ou=groups,dc=mgmt,dc=example,dc=com"] = LdapGroupInfo{cn: "group1",
		dn: "cn=group1,ou=groups,dc=mgmt,dc=example,dc=com", gidNumber: "20001", description: "self-managed", objectClass: []string{"posixGroup", "top", "groupOfNames"},
		memberUid: []string{"user1", "user2"},
		member:    []string{"uid=user1,ou=people,dc=mgmt,dc=example,dc=com", "uid=user2,ou=people,dc=mgmt,dc=example,dc=com"},
	}

	testldap.Groups["cn=group2,ou=groups,dc=mgmt,dc=example,dc=com"] = LdapGroupInfo{cn: "group2",
		dn: "cn=group2,ou=groups,dc=mgmt,dc=example,dc=com", description: "self-managed", gidNumber: "20001", objectClass: []string{"posixGroup", "top", "groupOfNames"},
		memberUid: []string{"user1", "user2"},
		member:    []string{"uid=user1,ou=people,dc=mgmt,dc=example,dc=com", "uid=user2,ou=people,dc=mgmt,dc=example,dc=com"}}

	testldap.Users["uid=user1,ou=people,dc=mgmt,dc=example,dc=com"] = LdapUserInfo{dn: "uid=user1,ou=people,dc=mgmt,dc=example,dc=com",
		memberOf:    []string{"cn=group1,ou=groups,dc=mgmt,dc=example,dc=com", "cn=group2,ou=groups,dc=mgmt,dc=example,dc=com"},
		objectClass: []string{"top", "person", "inetOrgPerson", "posixAccount", "organizationalPerson"}, uid: "user1", cn: "user1", mail: "user1@example.com",
	}
	testldap.Users["uid=user2,ou=people,dc=mgmt,dc=example,dc=com"] = LdapUserInfo{dn: "uid=user2,ou=people,dc=mgmt,dc=example,dc=com",
		memberOf:    []string{"cn=group1,ou=groups,dc=mgmt,dc=example,dc=com", "cn=group2,ou=groups,dc=mgmt,dc=example,dc=com"},
		objectClass: []string{"top", "person", "inetOrgPerson", "posixAccount", "organizationalPerson"}, uid: "user1", cn: "user1", mail: "user2@example.com",
	}
	return &testldap
}

func removeElements(s []string, r []string) []string {
	for _, str := range r {
		for pos, value := range s {
			if value == str {
				s = append(s[:pos], s[pos+1:]...)
			}
		}
	}
	return s
}

func (m *MockLdap) GetallUsers() (map[string]string, error) {
	users := make(map[string]string)
	for _, value := range m.Users {
		uid := value.uid
		users[uid] = value.uid
	}

	return users, nil
}

func (m *MockLdap) CreateuserDn(username string) string {
	userDN := "uid=" + username + "," + LdapUserDN
	return userDN
}

func (m *MockLdap) CreategroupDn(groupname string) string {
	groupDN := "cn=" + groupname + "," + LdapGroupDN
	return groupDN

}

func (m *MockLdap) CreateserviceDn(groupname string) string {
	serviceDN := "cn=" + groupname + "," + LdapServiceDN
	return serviceDN

}

func (m *MockLdap) CreateGroup(groupinfo userinfo.GroupInfo) error {
	groupdn := m.CreategroupDn(groupinfo.Groupname)
	var group LdapGroupInfo
	group.cn = groupinfo.Groupname
	group.description = groupinfo.Description
	group.memberUid = groupinfo.MemberUid
	group.objectClass = []string{"posixGroup", "top", "groupOfNames"}
	group.gidNumber, _ = m.GetmaximumGidnumber()
	m.Groups[groupdn] = group

	return nil

}

func (m *MockLdap) DeleteGroup(groupnames []string) error {
	for _, groupname := range groupnames {
		groupdn := m.CreategroupDn(groupname)
		delete(m.Groups, groupdn)
	}
	return nil

}

func (m *MockLdap) AddAtributedescription(groupname string) error {
	groupdn := m.CreategroupDn(groupname)
	GroupInfo := m.Groups[groupdn]
	GroupInfo.description = descriptionAttribute
	m.Groups[groupdn] = GroupInfo
	return nil

}

func (m *MockLdap) DeleteDescription(groupnames []string) error {
	for _, groupname := range groupnames {
		groupdn := m.CreategroupDn(groupname)
		GroupInfo := m.Groups[groupdn]
		GroupInfo.description = ""
		m.Groups[groupdn] = GroupInfo
	}
	return nil
}

func (m *MockLdap) GetallGroups() ([]string, error) {
	var groups []string
	for _, value := range m.Groups {
		groups = append(groups, value.cn)
	}

	return groups, nil

}

func (m *MockLdap) GetgroupsofUser(username string) ([]string, error) {
	var usergroups []string
	userdn := m.CreateuserDn(username)
	Userinfo := m.Users[userdn]
	for _, groupdn := range Userinfo.memberOf {
		Groupinfo := m.Groups[groupdn]
		usergroups = append(usergroups, Groupinfo.cn)
	}
	return usergroups, nil
}

func (m *MockLdap) GetusersofaGroup(groupname string) ([]string, error) {
	groupdn := m.CreategroupDn(groupname)
	groupinfo := m.Groups[groupdn]
	return groupinfo.memberUid, nil
}

func (m *MockLdap) ParseSuperadmins() []string {
	var superAdminsInfo []string
	for _, admin := range strings.Split(m.SuperAdmins, ",") {
		superAdminsInfo = append(superAdminsInfo, admin)
	}
	return superAdminsInfo
}

func (m *MockLdap) UserisadminOrNot(username string) bool {
	superAdmins := m.ParseSuperadmins()
	for _, user := range superAdmins {
		if user == username {
			return true
		}
	}
	return false
}

func (m *MockLdap) GetmaximumGidnumber() (string, error) {
	var max = 0
	for _, value := range m.Groups {
		gidnum, err := strconv.Atoi(value.gidNumber)
		if err != nil {
			return "", err
		}
		if gidnum > max {
			max = gidnum
		}
	}
	return fmt.Sprint(max + 1), nil
}

func (m *MockLdap) AddmemberstoExisting(groupinfo userinfo.GroupInfo) error {
	groupdn := m.CreategroupDn(groupinfo.Groupname)
	groupinformation := m.Groups[groupdn]
	for _, memberUid := range groupinfo.MemberUid {
		groupinformation.memberUid = append(groupinformation.memberUid, memberUid)
	}
	for _, member := range groupinfo.Member {
		groupinformation.member = append(groupinformation.member, member)
	}
	m.Groups[groupdn] = groupinformation
	return nil
}

func (m *MockLdap) DeletemembersfromGroup(groupinfo userinfo.GroupInfo) error {
	groupdn := m.CreategroupDn(groupinfo.Groupname)
	groupinformation := m.Groups[groupdn]
	groupinformation.memberUid = removeElements(groupinformation.memberUid, groupinfo.MemberUid)
	groupinformation.member = removeElements(groupinformation.member, groupinfo.Member)
	m.Groups[groupdn] = groupinformation
	return nil
}

func (m *MockLdap) IsgroupmemberorNot(groupname string, username string) (bool, error) {
	AllUsersinGroup, err := m.GetusersofaGroup(groupname)
	if err != nil {
		log.Println(err)
		return false, err
	}
	for _, entry := range AllUsersinGroup {
		if entry == username {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockLdap) GetDescriptionvalue(groupname string) (string, error) {
	groupdn := m.CreategroupDn(groupname)
	groupinfo := m.Groups[groupdn]

	return groupinfo.description, nil
}

func (m *MockLdap) GetEmailofauser(username string) ([]string, error) {
	userdn := m.CreateuserDn(username)
	usersinfo := m.Users[userdn]

	return []string{usersinfo.mail}, nil
}

func (m *MockLdap) GetEmailofusersingroup(groupname string) ([]string, error) {
	groupUsers, err := m.GetusersofaGroup(groupname)
	if err != nil {
		log.Println(err)
	}
	var userEmail []string
	for _, entry := range groupUsers[0] {
		value, err := m.GetEmailofauser(entry)
		if err != nil {
			return nil, err
		}
		userEmail = append(userEmail, value[0])

	}
	return userEmail, nil
}

func (m *MockLdap) CreateServiceAccount(groupinfo userinfo.GroupInfo) error {

	groupdn := m.CreateserviceDn(groupinfo.Groupname)
	var group LdapGroupInfo
	group.cn = groupinfo.Groupname
	group.description = groupinfo.Description
	group.objectClass = []string{"posixGroup", "top", "groupOfNames"}
	group.gidNumber, _ = m.GetmaximumGidnumber()
	m.Services[groupdn] = group

	return nil
}

func (m *MockLdap) IsgroupAdminorNot(username string, groupname string) (bool, error) {
	managedby, err := m.GetDescriptionvalue(groupname)
	if managedby == "self-managed" {
		Isgroupmember, err := m.IsgroupmemberorNot(groupname, username)
		if !Isgroupmember && err != nil {
			return false, err
		}
		return true, nil
	}
	Isgroupmember, err := m.IsgroupmemberorNot(managedby, username)
	if !Isgroupmember && err != nil {
		return false, err
	}

	return true, nil
}
