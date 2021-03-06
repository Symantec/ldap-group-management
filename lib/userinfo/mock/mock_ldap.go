package mock

import (
	"errors"
	"fmt"
	"github.com/Symantec/ldap-group-management/lib/userinfo"
	"log"
	"sort"
	"strconv"
)

const descriptionAttribute = "self-managed"

const UserServiceAccount userinfo.AccountType = 1
const GroupServiceAccount userinfo.AccountType = 2

type MockLdap struct {
	Groups          map[string]LdapGroupInfo
	Users           map[string]LdapUserInfo
	SuperAdminGroup string
	Services        map[string]LdapServiceInfo
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
	uidNumber   string
	mail        string
	cn          string
	description string
	givenName   string
}
type LdapServiceInfo struct {
	dn          string
	memberOf    []string
	objectClass []string
	uid         string
	uidNumber   string
	gidNumber   string
	mail        string
	cn          string
	description string
}

func New() *MockLdap {
	var testldap MockLdap
	testldap.Groups = make(map[string]LdapGroupInfo)
	testldap.Users = make(map[string]LdapUserInfo)
	testldap.SuperAdminGroup = "group3" // was: user1,user2
	testldap.Services = make(map[string]LdapServiceInfo)

	testldap.Groups["cn=group1,ou=groups,dc=mgmt,dc=example,dc=com"] = LdapGroupInfo{cn: "group1",
		dn: "cn=group1,ou=groups,dc=mgmt,dc=example,dc=com", gidNumber: "20001", description: "self-managed", objectClass: []string{"posixGroup", "top", "groupOfNames"},
		memberUid: []string{"user1", "user2"},
		member:    []string{"uid=user1,ou=people,dc=mgmt,dc=example,dc=com", "uid=user2,ou=people,dc=mgmt,dc=example,dc=com"},
	}

	testldap.Groups["cn=group2,ou=groups,dc=mgmt,dc=example,dc=com"] = LdapGroupInfo{cn: "group2",
		dn: "cn=group2,ou=groups,dc=mgmt,dc=example,dc=com", description: "self-managed", gidNumber: "20001", objectClass: []string{"posixGroup", "top", "groupOfNames"},
		memberUid: []string{"user1", "user3"},
		member:    []string{"uid=user1,ou=people,dc=mgmt,dc=example,dc=com", "uid=user3,ou=people,dc=mgmt,dc=example,dc=com"}}

	testldap.Groups["cn=group3,ou=groups,dc=mgmt,dc=example,dc=com"] = LdapGroupInfo{cn: "group3",
		dn:          "cn=group3,ou=groups,dc=mgmt,dc=example,dc=com",
		description: "group1", gidNumber: "20000",
		objectClass: []string{"posixGroup", "top", "groupOfNames"},
		memberUid:   []string{"user1"},
		member:      []string{"uid=user1,ou=people,dc=mgmt,dc=example,dc=com"},
	}

	//TODO: better labels for future.
	testldap.Users["uid=user1,ou=people,dc=mgmt,dc=example,dc=com"] = LdapUserInfo{dn: "uid=user1,ou=people,dc=mgmt,dc=example,dc=com",
		memberOf:    []string{"cn=group1,ou=groups,dc=mgmt,dc=example,dc=com", "cn=group2,ou=groups,dc=mgmt,dc=example,dc=com", "cn=group3,ou=groups,dc=mgmt,dc=example,dc=com"},
		objectClass: []string{"top", "person", "inetOrgPerson", "posixAccount", "organizationalPerson"}, uid: "user1", cn: "user1", mail: "user1@example.com", givenName: "user1",
	}
	testldap.Users["uid=user2,ou=people,dc=mgmt,dc=example,dc=com"] = LdapUserInfo{dn: "uid=user2,ou=people,dc=mgmt,dc=example,dc=com",
		memberOf:    []string{"cn=group1,ou=groups,dc=mgmt,dc=example,dc=com"},
		objectClass: []string{"top", "person", "inetOrgPerson", "posixAccount", "organizationalPerson"}, uid: "user2", cn: "user2", mail: "user2@example.com", givenName: "user2",
	}
	testldap.Users["uid=user3,ou=people,dc=mgmt,dc=example,dc=com"] = LdapUserInfo{
		dn:          "uid=user3,ou=people,dc=mgmt,dc=example,dc=com",
		memberOf:    []string{"cn=group2,ou=groups,dc=mgmt,dc=example,dc=com"},
		objectClass: []string{"top", "person", "inetOrgPerson", "posixAccount", "organizationalPerson"},
		uid:         "user3", cn: "user3", mail: "user3@example.com", givenName: "user3",
	}

	testldap.Services["cn=group1,ou=services,dc=mgmt,dc=example,dc=com"] = LdapServiceInfo{cn: "group1",
		dn: "cn=group1,ou=services,dc=mgmt,dc=example,dc=com", gidNumber: "20010", mail: "group1@example.com", objectClass: []string{"posixGroup", "top", "groupOfNames"},
	}

	testldap.Services["uid=user2,ou=services,dc=mgmt,dc=example,dc=com"] = LdapServiceInfo{dn: "uid=user2,ou=people,dc=mgmt,dc=example,dc=com", uidNumber: "20009",
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

func (m *MockLdap) GetallUsers() ([]string, error) {
	var allusers []string
	for _, value := range m.Users {
		allusers = append(allusers, value.uid)
	}

	return allusers, nil
}

func (m *MockLdap) createUserDN(username string) string {
	userDN := "uid=" + username + "," + LdapUserDN
	return userDN
}

func (m *MockLdap) CreategroupDn(groupname string) string {
	groupDN := "cn=" + groupname + "," + LdapGroupDN
	return groupDN

}

func (m *MockLdap) createServiceDN(groupname string, accountType userinfo.AccountType) string {
	var serviceDN string
	if accountType == UserServiceAccount {
		serviceDN = "uid=" + groupname + "," + LdapServiceDN
	}
	if accountType == GroupServiceAccount {
		serviceDN = "cn=" + groupname + "," + LdapServiceDN
	}
	return string(serviceDN)
}

func (m *MockLdap) CreateGroup(groupinfo userinfo.GroupInfo) error {
	groupdn := m.CreategroupDn(groupinfo.Groupname)
	var group LdapGroupInfo
	group.cn = groupinfo.Groupname
	group.description = groupinfo.Description
	group.memberUid = groupinfo.MemberUid
	group.objectClass = []string{"posixGroup", "top", "groupOfNames"}
	group.gidNumber, _ = m.GetmaximumGidnumber(LdapGroupDN)
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

func (m *MockLdap) GetallGroups() ([]string, error) {
	var groups []string
	for _, value := range m.Groups {
		groups = append(groups, value.cn)
	}

	return groups, nil

}

func (m *MockLdap) GetgroupsofUser(username string) ([]string, error) {
	var usergroups []string
	userdn := m.createUserDN(username)
	Userinfo := m.Users[userdn]
	for _, groupdn := range Userinfo.memberOf {
		Groupinfo := m.Groups[groupdn]
		usergroups = append(usergroups, Groupinfo.cn)
	}
	return usergroups, nil
}

func (m *MockLdap) GetusersofaGroup(groupname string) ([]string, string, error) {
	groupdn := m.CreategroupDn(groupname)
	groupinfo, ok := m.Groups[groupdn]
	if !ok {
		return nil, "", userinfo.GroupDoesNotExist
	}
	return groupinfo.memberUid, groupinfo.description, nil
}

func (m *MockLdap) GetGroupUsersAndManagers(groupname string) ([]string, []string, string, error) {
	groupdn := m.CreategroupDn(groupname)
	groupinfo, ok := m.Groups[groupdn]
	if !ok {
		return nil, nil, "", userinfo.GroupDoesNotExist
	}
	managergroupDN := m.CreategroupDn(groupinfo.description)
	var managerMembers []string
	managerGroupInfo, ok := m.Groups[managergroupDN]
	if ok {
		managerMembers = managerGroupInfo.memberUid
	}
	return groupinfo.memberUid, managerMembers, groupinfo.description, nil

}

func (m *MockLdap) ParseSuperadmins() []string {
	var superAdminsList []string
	superAdminsList, _, err := m.GetusersofaGroup(m.SuperAdminGroup)
	if err != nil {
		return nil
	}
	sort.Strings(superAdminsList)
	return superAdminsList
}

func (m *MockLdap) UserisadminOrNot(username string) bool {
	superAdmins := m.ParseSuperadmins()
	index := sort.SearchStrings(superAdmins, username)
	if index < len(superAdmins) && superAdmins[index] == username {
		return true
	}
	return false
}

func (m *MockLdap) GetmaximumGidnumber(s string) (string, error) {
	var max = 0
	if s == LdapGroupDN {
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
	} else if s == LdapServiceDN {
		for _, value := range m.Services {
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
	return "", errors.New("choose LdapGroupDN or LdapServiceDN")
}

func (m *MockLdap) GetmaximumUidnumber(s string) (string, error) {
	var max = 0
	for _, value := range m.Services {
		uidnum, err := strconv.Atoi(value.uidNumber)
		if err != nil {
			return "", err
		}
		if uidnum > max {
			max = uidnum
		}
	}
	return fmt.Sprint(max + 1), nil
}

func (m *MockLdap) AddmemberstoExisting(groupinfo userinfo.GroupInfo) error {
	groupdn := m.CreategroupDn(groupinfo.Groupname)
	groupinformation, ok := m.Groups[groupdn]
	if !ok {
		return userinfo.GroupDoesNotExist
	}
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
	groupinformation, ok := m.Groups[groupdn]
	if !ok {
		return userinfo.GroupDoesNotExist
	}
	groupinformation.memberUid = removeElements(groupinformation.memberUid, groupinfo.MemberUid)
	groupinformation.member = removeElements(groupinformation.member, groupinfo.Member)
	m.Groups[groupdn] = groupinformation
	return nil
}

func (m *MockLdap) IsgroupmemberorNot(groupname string, username string) (bool, string, error) {
	AllUsersinGroup, description, err := m.GetusersofaGroup(groupname)
	if err != nil {
		log.Println(err)
		return false, "", err
	}
	for _, entry := range AllUsersinGroup {
		if entry == username {
			return true, description, nil
		}
	}
	return false, description, nil
}

func (m *MockLdap) GetDescriptionvalue(groupname string) (string, error) {
	groupdn := m.CreategroupDn(groupname)
	groupinfo, ok := m.Groups[groupdn]

	if !ok {
		return "", userinfo.GroupDoesNotExist
	}

	return groupinfo.description, nil
}

func (m *MockLdap) GetEmailofauser(username string) ([]string, error) {
	userdn := m.createUserDN(username)
	usersinfo := m.Users[userdn]

	return []string{usersinfo.mail}, nil
}

func (m *MockLdap) GetEmailofusersingroup(groupname string) ([]string, error) {
	groupUsers, _, err := m.GetusersofaGroup(groupname)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	var userEmail []string
	for _, entry := range groupUsers {
		value, err := m.GetEmailofauser(entry)
		if err != nil {
			return nil, err
		}
		userEmail = append(userEmail, value[0])

	}
	return userEmail, nil
}

func (m *MockLdap) CreateServiceAccount(groupinfo userinfo.GroupInfo) error {

	gidNum, _ := m.GetmaximumGidnumber(LdapServiceDN)
	groupdn := m.createServiceDN(groupinfo.Groupname, GroupServiceAccount)
	var group LdapServiceInfo
	group.cn = groupinfo.Groupname
	group.mail = groupinfo.Mail
	group.objectClass = []string{"posixGroup", "top", "groupOfNames"}
	group.gidNumber = gidNum
	m.Services[groupdn] = group

	userdn := m.createServiceDN(groupinfo.Groupname, UserServiceAccount)
	var user LdapServiceInfo
	user.cn = groupinfo.Groupname
	user.uid = groupinfo.Groupname
	user.mail = groupinfo.Mail
	user.objectClass = []string{"top", "person", "inetOrgPerson", "posixAccount", "organizationalPerson"}
	user.gidNumber = gidNum
	user.uidNumber, _ = m.GetmaximumUidnumber(LdapServiceDN)
	m.Services[userdn] = user

	return nil
}

func (m *MockLdap) IsgroupAdminorNot(username string, groupname string) (bool, error) {
	managedby, err := m.GetDescriptionvalue(groupname)
	if err != nil {
		return false, err
	}
	if managedby == "self-managed" {
		Isgroupmember, _, err := m.IsgroupmemberorNot(groupname, username)
		if !Isgroupmember && err != nil {
			return false, err
		}
		return true, nil
	}
	Isgroupmember, _, err := m.IsgroupmemberorNot(managedby, username)
	if !Isgroupmember && err != nil {
		return false, err
	}

	return true, nil
}

func (m *MockLdap) UsernameExistsornot(username string) (bool, error) {

	for _, entry := range m.Users {
		uid := entry.uid
		if uid == username {
			return true, nil
		}

	}

	return false, nil
}

func (m *MockLdap) GroupnameExistsornot(groupname string) (bool, string, error) {
	for _, entry := range m.Groups {
		uid := entry.cn
		if uid == groupname {
			return true, entry.description, nil
		}

	}

	return false, "", nil
}

func (m *MockLdap) ServiceAccountExistsornot(groupname string) (bool, string, error) {
	for _, entry := range m.Services {
		uid := entry.cn
		if uid == groupname {

			return true, entry.dn, nil
		}

	}
	return false, "", nil
}

func (m *MockLdap) getGroupDN(groupname string) (string, error) {
	for _, entry := range m.Groups {
		cn := entry.cn
		if cn == groupname {
			return entry.dn, nil
		}

	}
	return "", nil
}

func (m *MockLdap) GetAllGroupsManagedBy() ([][]string, error) {
	var groups [][]string
	var eachGroup []string
	for _, value := range m.Groups {
		eachGroup = append(eachGroup, value.cn, value.description)
		groups = append(groups, eachGroup)
		eachGroup = nil
	}

	return groups, nil
}

func (m *MockLdap) GetGroupsInfoOfUser(groupdn string, username string) ([][]string, error) {
	var usergroupsinfo [][]string
	var usergroups []string
	userdn := m.createUserDN(username)
	Userinfo := m.Users[userdn]
	for _, groupdn := range Userinfo.memberOf {
		Groupinfo := m.Groups[groupdn]
		usergroups = append(usergroups, Groupinfo.cn, Groupinfo.description)
		usergroupsinfo = append(usergroupsinfo, usergroups)
		usergroups = nil
	}
	return usergroupsinfo, nil
}

func (m *MockLdap) GetGroupandManagedbyAttributeValue(groupnames []string) ([][]string, error) {
	var UserGroupInfo [][]string
	var groupcndescription []string
	for _, eachgroup := range groupnames {
		groupdescription, err := m.GetDescriptionvalue(eachgroup)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		groupcndescription = append(groupcndescription, eachgroup, groupdescription)
		UserGroupInfo = append(UserGroupInfo, groupcndescription)
		groupcndescription = nil
	}
	return UserGroupInfo, nil
}

func (m *MockLdap) ChangeDescription(groupname string, managegroup string) error {
	return nil
}

func (m *MockLdap) CreateUser(username string, givenName, email []string) error {

	userdn := m.createUserDN(username)
	var user LdapUserInfo
	user.objectClass = []string{"posixAccount", "person", "ldapPublicKey", "organizationalPerson", "inetOrgPerson", "shadowAccount", "top", "inetUser", "pwmuser"}
	user.uid = username
	user.uidNumber, _ = m.GetmaximumUidnumber(LdapUserDN)
	user.mail = email[0]
	user.cn = username
	m.Users[userdn] = user
	return nil
}

func (m *MockLdap) getallUsersNonCached() ([]string, error) {
	var allusers []string
	for _, value := range m.Users {
		allusers = append(allusers, value.uid)
	}

	return allusers, nil
}

func (m *MockLdap) GetUserAttributes(username string) ([]string, []string, error) {
	userdn := m.createUserDN(username)
	usersinfo := m.Users[userdn]

	return []string{usersinfo.mail}, []string{usersinfo.givenName}, nil
}
