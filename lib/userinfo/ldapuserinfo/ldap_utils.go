package ldapuserinfo

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/Symantec/keymaster/lib/authutil"
	"github.com/Symantec/ldap-group-management/lib/userinfo"
	"gopkg.in/ldap.v2"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const ldapTimeoutSecs = 10

const HomeDirectory = "/home/"
const objectClassgroupofNames = "groupOfNames"

const (
	UserServiceAccount  userinfo.AccountType = 1
	GroupServiceAccount userinfo.AccountType = 2
)

type UserInfoLDAPSource struct {
	BindUsername          string `yaml:"bind_username"`
	BindPassword          string `yaml:"bind_password"`
	LDAPTargetURLs        string `yaml:"ldap_target_urls"`
	UserSearchBaseDNs     string `yaml:"user_search_base_dns"`
	UserSearchFilter      string `yaml:"user_search_filter"`
	GroupSearchBaseDNs    string `yaml:"group_search_base_dns"`
	GroupSearchFilter     string `yaml:"group_search_filter"`
	Admins                string `yaml:"super_admins"`
	ServiceAccountBaseDNs string `yaml:"service_search_base_dns"`
	MainBaseDN            string `yaml:"Main_base_dns"`
	GroupManageAttribute  string `yaml:"group_Manage_Attribute"`
}

func (u *UserInfoLDAPSource) objectClassExistsorNot(groupname string, objectclass string) (bool, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return false, err
	}
	defer conn.Close()

	searchrequest := ldap.NewSearchRequest(u.GroupSearchBaseDNs, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(&(cn="+groupname+" )(objectClass=posixGroup))", []string{"objectClass"}, nil)
	result, err := conn.Search(searchrequest)
	if err != nil {
		log.Println(err)
		return false, err
	}
	if len(result.Entries) > 1 {
		log.Println("multiple entries found")
		return false, errors.New("Multiple entries found!")
	}
	for _, value := range result.Entries[0].GetAttributeValues("objectClass") {
		if value == objectclass {
			return true, nil
		}
	}
	return false, nil
}

func getLDAPConnection(u url.URL, timeoutSecs uint, rootCAs *x509.CertPool) (*ldap.Conn, string, error) {

	if u.Scheme != "ldaps" {
		err := errors.New("Invalid ldaputil scheme (we only support ldaps)")
		log.Println(err)
		return nil, "", err
	}

	serverPort := strings.Split(u.Host, ":")
	port := "636"

	if len(serverPort) == 2 {
		port = serverPort[1]
	}

	server := serverPort[0]
	hostnamePort := server + ":" + port

	timeout := time.Duration(time.Duration(timeoutSecs) * time.Second)
	start := time.Now()

	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp",
		hostnamePort, &tls.Config{ServerName: server, RootCAs: rootCAs})

	if err != nil {
		log.Printf("rooCAs=%+v,  serverName=%s, hostnameport=%s, tlsConn=%+v", rootCAs, server, hostnamePort, tlsConn)
		errorTime := time.Since(start).Seconds() * 1000
		log.Printf("connection failure for:%s (%s)(time(ms)=%v)", server, err.Error(), errorTime)
		return nil, "", err
	}

	// we dont close the tls connection directly  close defer to the new ldaputil connection
	conn := ldap.NewConn(tlsConn, true)
	return conn, server, nil
}

func (u *UserInfoLDAPSource) getTargetLDAPConnection() (*ldap.Conn, error) {
	var ldapURL []*url.URL
	for _, ldapURLString := range strings.Split(u.LDAPTargetURLs, ",") {
		newURL, err := authutil.ParseLDAPURL(ldapURLString)
		if err != nil {
			log.Println(err)
			continue
		}
		ldapURL = append(ldapURL, newURL)
	}

	for _, TargetLdapUrl := range ldapURL {
		conn, _, err := getLDAPConnection(*TargetLdapUrl, ldapTimeoutSecs, nil)

		if err != nil {
			log.Println(err)
			continue
		}
		timeout := time.Duration(time.Duration(ldapTimeoutSecs) * time.Second)
		conn.SetTimeout(timeout)
		conn.Start()

		err = conn.Bind(u.BindUsername, u.BindPassword)
		if err != nil {
			log.Println(err)
			continue
		}
		return conn, nil
	}
	return nil, errors.New("cannot connect to LDAP server")
}

//Get all ldaputil users and put that in map ---required
func (u *UserInfoLDAPSource) GetallUsers() ([]string, error) {

	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer conn.Close()

	var AllUsers []string
	Attributes := []string{"uid"}
	searchrequest := ldap.NewSearchRequest(u.UserSearchBaseDNs, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false, u.UserSearchFilter, Attributes, nil)
	result, err := conn.Search(searchrequest)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	if len(result.Entries) == 0 {
		log.Println("No records found")
		return nil, errors.New("No records found")
	}
	for _, entry := range result.Entries {
		uid := entry.GetAttributeValue("uid")
		AllUsers = append(AllUsers, uid)
	}

	return AllUsers, nil
}

//To build a user base DN using uid only for Target LDAP.
func (u *UserInfoLDAPSource) CreateuserDn(username string) string {
	//uid := username
	result := "uid=" + username + "," + u.UserSearchBaseDNs

	return string(result)

}

//To build a GroupDN for a particular group in Target ldaputil
func (u *UserInfoLDAPSource) CreategroupDn(groupname string) string {
	result := "cn=" + groupname + "," + u.GroupSearchBaseDNs

	return string(result)

}

func (u *UserInfoLDAPSource) CreateserviceDn(groupname string, a userinfo.AccountType) string {
	var serviceDN string
	if a == UserServiceAccount {
		serviceDN = "uid=" + groupname + "," + u.ServiceAccountBaseDNs
	}
	if a == GroupServiceAccount {
		serviceDN = "cn=" + groupname + "," + u.ServiceAccountBaseDNs
	}
	return string(serviceDN)
}

//Creating a Group --required
func (u *UserInfoLDAPSource) CreateGroup(groupinfo userinfo.GroupInfo) error {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()

	entry := u.CreategroupDn(groupinfo.Groupname)
	gidnum, err := u.GetmaximumGidnumber(u.GroupSearchBaseDNs)
	if err != nil {
		log.Println(err)
		return err
	}
	group := ldap.NewAddRequest(entry)
	group.Attribute("objectClass", []string{"posixGroup", "top", "groupOfNames"})
	group.Attribute("cn", []string{groupinfo.Groupname})
	group.Attribute(u.GroupManageAttribute, []string{groupinfo.Description})
	group.Attribute("member", groupinfo.Member)
	group.Attribute("memberUid", groupinfo.MemberUid)
	group.Attribute("gidNumber", []string{gidnum})
	err = conn.Add(group)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

//deleting a Group from target ldaputil. --required
func (u *UserInfoLDAPSource) DeleteGroup(groupnames []string) error {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()

	for _, entry := range groupnames {
		groupdn, err := u.GetGroupDN(entry)
		if err != nil {
			log.Println(err)
			return err
		}
		DelReq := ldap.NewDelRequest(groupdn, nil)
		err = conn.Del(DelReq)
		if err != nil {
			log.Println(err)
			return err
		}

	}
	return nil
}

//Adding an attritube called 'description' to a dn in Target Ldap
func (u *UserInfoLDAPSource) AddAtributedescription(groupname string) error {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()

	entry, err := u.GetGroupDN(groupname)
	if err != nil {
		log.Println(err)
		return err
	}
	modify := ldap.NewModifyRequest(entry)
	modify.Add(u.GroupManageAttribute, []string{"self-managed"})

	//modify.Add("description", []string{"created by me"})
	err = conn.Modify(modify)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil

}

//Deleting the attribute in a dn in Target Ldap. --required
func (u *UserInfoLDAPSource) DeleteDescription(groupnames []string) error {

	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()

	for _, entry := range groupnames {
		entry, err = u.GetGroupDN(entry)
		if err != nil {
			log.Println(err)
			return err
		}

		modify := ldap.NewModifyRequest(entry)

		modify.Delete("description", []string{"created by Midpoint"})
		err := conn.Modify(modify)
		if err != nil {
			log.Println(err)
			return err
		}
	}
	return nil
}

//Change group description --required
func (u *UserInfoLDAPSource) ChangeDescription(groupname string, managegroup string) error {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()
	entry, err := u.GetGroupDN(groupname)
	if err != nil {
		log.Println(err)
		return err
	}
	modify := ldap.NewModifyRequest(entry)
	modify.Replace("description", []string{managegroup})
	err = conn.Modify(modify)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

//function to get all the groups in Target ldaputil and put it in array --required
func (u *UserInfoLDAPSource) GetallGroups() ([]string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer conn.Close()

	var AllGroups []string
	searchrequest := ldap.NewSearchRequest(u.GroupSearchBaseDNs, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, u.GroupSearchFilter, []string{"cn"}, nil)
	result, err := conn.Search(searchrequest)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	for _, entry := range result.Entries {
		AllGroups = append(AllGroups, entry.GetAttributeValue("cn"))
	}
	return AllGroups, nil
}

// GetGroupsOfUser returns the all groups of a user. --required
func (u *UserInfoLDAPSource) GetgroupsofUser(username string) ([]string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		u.GroupSearchBaseDNs,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(memberUid="+username+" ))",
		[]string{"cn"}, //memberOf (if searching other way around using usersdn instead of groupdn)
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}

//returns all the users of a group --required
func (u *UserInfoLDAPSource) GetusersofaGroup(groupname string) ([]string, string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return nil, "", err
	}
	defer conn.Close()
	//Base := u.CreategroupDn(groupname)

	searchRequest := ldap.NewSearchRequest(
		u.GroupSearchBaseDNs,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(cn="+groupname+" )(objectClass=posixGroup))",
		nil,
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Println(err)
		return nil, "", err
	}
	if len(sr.Entries) > 1 {
		log.Println("Duplicate entries found")
		return nil, "", errors.New("Multiple entries found, Contact the administrator!")
	}
	users := sr.Entries[0].GetAttributeValues("memberUid")
	if sr.Entries[0].GetAttributeValues(u.GroupManageAttribute) == nil {
		return users, "", nil
	}
	GroupmanagedbyValue := sr.Entries[0].GetAttributeValue(u.GroupManageAttribute)
	return users, GroupmanagedbyValue, nil
}

//parse super admins of Target Ldap
func (u *UserInfoLDAPSource) ParseSuperadmins() []string {
	var superAdminsInfo []string
	for _, admin := range strings.Split(u.Admins, ",") {
		superAdminsInfo = append(superAdminsInfo, admin)
	}
	return superAdminsInfo
}

//if user is super admin or not
func (u *UserInfoLDAPSource) UserisadminOrNot(username string) bool {
	superAdmins := u.ParseSuperadmins()
	for _, user := range superAdmins {
		if user == username {
			return true
		}
	}
	return false
}

//it helps to findout the current maximum gid number in ldaputil.
func (u *UserInfoLDAPSource) GetmaximumGidnumber(searchBaseDN string) (string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return "error in getTargetLDAPConnection", err
	}
	defer conn.Close()
	searchRequest := ldap.NewSearchRequest(
		searchBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(gidNumber=*))",
		[]string{"gidNumber"},
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Println(err)
		return "error in ldapsearch", err
	}
	var max = 0
	for _, entry := range sr.Entries {
		gidnum := entry.GetAttributeValue("gidNumber")
		value, err := strconv.Atoi(gidnum)
		if err != nil {
			log.Println(err)
		}
		if value > max {
			max = value
		}
	}
	//fmt.Println(max)
	return fmt.Sprint(max + 1), nil
}

func (u *UserInfoLDAPSource) GetmaximumUidnumber(searchBaseDN string) (string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return "error in getTargetLDAPConnection", err
	}
	defer conn.Close()
	searchRequest := ldap.NewSearchRequest(
		searchBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(uidNumber=*))",
		[]string{"uidNumber"},
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Println(err)
		return "error in ldapsearch", err
	}
	var max = 0
	for _, entry := range sr.Entries {
		uidnum := entry.GetAttributeValue("uidNumber")
		value, err := strconv.Atoi(uidnum)
		if err != nil {
			log.Println(err)
		}
		if value > max {
			max = value
		}
	}
	//fmt.Println(max)
	return fmt.Sprint(max + 1), nil
}

//adding members to existing group
func (u *UserInfoLDAPSource) AddmemberstoExisting(groupinfo userinfo.GroupInfo) error {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()
	objectExists, err := u.objectClassExistsorNot(groupinfo.Groupname, objectClassgroupofNames)
	if err != nil {
		log.Println(err)
		return err
	}
	entry, err := u.GetGroupDN(groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		return err
	}
	modify := ldap.NewModifyRequest(entry)
	if objectExists {
		modify.Add("member", groupinfo.Member)
	}
	modify.Add("memberUid", groupinfo.MemberUid)
	err = conn.Modify(modify)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

//remove members from existing group
func (u *UserInfoLDAPSource) DeletemembersfromGroup(groupinfo userinfo.GroupInfo) error {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()
	objectExists, err := u.objectClassExistsorNot(groupinfo.Groupname, objectClassgroupofNames)
	if err != nil {
		log.Println(err)
		return err
	}
	entry, err := u.GetGroupDN(groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		return err
	}
	modify := ldap.NewModifyRequest(entry)
	modify.Delete("memberUid", groupinfo.MemberUid)
	if objectExists {
		modify.Delete("member", groupinfo.Member)
	}
	err = conn.Modify(modify)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

//if user is already a member of group or not
func (u *UserInfoLDAPSource) IsgroupmemberorNot(groupname string, username string) (bool, string, error) {

	AllUsersinGroup, GroupmanagedbyValue, err := u.GetusersofaGroup(groupname)
	if err != nil {
		log.Println(err)
		return false, GroupmanagedbyValue, err
	}
	for _, entry := range AllUsersinGroup {
		if entry == username {
			return true, GroupmanagedbyValue, nil
		}
	}
	return false, GroupmanagedbyValue, nil
}

//get description of a group
func (u *UserInfoLDAPSource) GetDescriptionvalue(groupname string) (string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return "Error in getTargetLDAPConnection", err
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		u.GroupSearchBaseDNs,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(cn="+groupname+" )(objectClass=posixGroup))",
		nil,
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Println(err)
		return "", err
	}
	if len(sr.Entries) > 1 {
		log.Println("Duplicate entries found")
		return "", errors.New("Multiple entries found, Contact the administrator!")
	}
	if sr.Entries[0].GetAttributeValues(u.GroupManageAttribute) == nil {
		log.Println("No group managed attribute")
		return "", nil
	}
	GroupmanagedbyValue := sr.Entries[0].GetAttributeValue(u.GroupManageAttribute)

	return GroupmanagedbyValue, nil
}

//get email of a user
func (u *UserInfoLDAPSource) GetEmailofauser(username string) ([]string, error) {
	var userEmail []string
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer conn.Close()
	Userdn := u.CreateuserDn(username)
	searchrequest := ldap.NewSearchRequest(Userdn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(&(uid="+username+")(objectClass=*))", []string{"mail"}, nil)
	result, err := conn.Search(searchrequest)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	userEmail = append(userEmail, result.Entries[0].GetAttributeValues("mail")[0])
	return userEmail, nil

}

//get email of all users in the given group
func (u *UserInfoLDAPSource) GetEmailofusersingroup(groupname string) ([]string, error) {

	groupUsers, _, err := u.GetusersofaGroup(groupname)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	var userEmail []string
	for _, entry := range groupUsers {
		value, err := u.GetEmailofauser(entry)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		userEmail = append(userEmail, value[0])

	}
	return userEmail, nil
}

func (u *UserInfoLDAPSource) CreateServiceAccount(groupinfo userinfo.GroupInfo) error {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()

	gidnum, err := u.GetmaximumGidnumber(u.ServiceAccountBaseDNs)
	if err != nil {
		log.Println(err)
		return err
	}
	uidnum, err := u.GetmaximumUidnumber(u.ServiceAccountBaseDNs)
	if err != nil {
		log.Println(err)
		return err
	}
	serviceDN := u.CreateserviceDn(groupinfo.Groupname, GroupServiceAccount)

	group := ldap.NewAddRequest(serviceDN)
	group.Attribute("objectClass", []string{"posixGroup", "top", "groupOfNames"})
	group.Attribute("cn", []string{groupinfo.Groupname})
	group.Attribute("gidNumber", []string{gidnum})
	err = conn.Add(group)
	if err != nil {
		log.Println(err)
		return err
	}

	serviceDN = u.CreateserviceDn(groupinfo.Groupname, UserServiceAccount)

	user := ldap.NewAddRequest(serviceDN)
	user.Attribute("objectClass", []string{"posixAccount", "person", "ldapPublicKey", "organizationalPerson", "inetOrgPerson", "shadowAccount", "top"})
	user.Attribute("cn", []string{groupinfo.Groupname})
	user.Attribute("uid", []string{groupinfo.Groupname})
	user.Attribute("gecos", []string{groupinfo.Groupname})
	user.Attribute("givenName", []string{groupinfo.Groupname})
	user.Attribute("displayName", []string{groupinfo.Groupname})
	user.Attribute("sn", []string{groupinfo.Groupname})

	user.Attribute("homeDirectory", []string{HomeDirectory + groupinfo.Groupname})
	user.Attribute("loginShell", []string{groupinfo.LoginShell})
	user.Attribute("sshPublicKey", []string{""})
	user.Attribute("shadowExpire", []string{"-1"})
	user.Attribute("shadowFlag", []string{"0"})
	user.Attribute("shadowLastChange", []string{"15528"})
	user.Attribute("shadowMax", []string{"99999"})
	user.Attribute("shadowMin", []string{"0"})
	user.Attribute("shadowWarning", []string{"7"})
	user.Attribute("mail", []string{groupinfo.Mail})
	user.Attribute("gidNumber", []string{gidnum})
	user.Attribute("uidNumber", []string{uidnum})

	err = conn.Add(user)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func (u *UserInfoLDAPSource) IsgroupAdminorNot(username string, groupname string) (bool, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return false, err
	}
	defer conn.Close()

	managedby, err := u.GetDescriptionvalue(groupname)
	if err != nil {
		log.Println(err)
		return false, err
	}
	//check if user is admin (super admin)
	if u.UserisadminOrNot(username) {
		return true, nil
	}
	if managedby == "self-managed" {
		Isgroupmember, _, err := u.IsgroupmemberorNot(groupname, username)
		if !Isgroupmember || err != nil {
			log.Println(err)
			return false, err
		}
		return true, nil
	}
	groupExists, _, err := u.GroupnameExistsornot(managedby)
	if !groupExists {
		return false, nil
	}
	Isgroupmember, _, err := u.IsgroupmemberorNot(managedby, username)
	if !Isgroupmember || err != nil {
		log.Println(err)
		return false, err
	}

	return true, nil
}

func (u *UserInfoLDAPSource) UsernameExistsornot(username string) (bool, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return false, err
	}
	defer conn.Close()

	Attributes := []string{"uid"}
	searchrequest := ldap.NewSearchRequest(u.MainBaseDN, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false, "(&(uid="+username+" ))", Attributes, nil)
	result, err := conn.Search(searchrequest)
	if err != nil {
		log.Println("Error in Ldap Search")
		return false, err
	}

	if len(result.Entries) == 0 {
		log.Println("No records found")
		return false, nil
	}
	if len(result.Entries) > 1 {
		log.Println("duplicate entries!")
		return true, errors.New("Multiple entries available! Contact the administration!")
	}
	if username == result.Entries[0].GetAttributeValue("uid") {
		return true, nil
	}

	return false, nil
}

func (u *UserInfoLDAPSource) GroupnameExistsornot(groupname string) (bool, string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return false, "", err
	}
	defer conn.Close()

	searchrequest := ldap.NewSearchRequest(u.GroupSearchBaseDNs, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false, "(&(cn="+groupname+")(objectClass=posixGroup))",
		nil, nil)

	result, err := conn.Search(searchrequest)
	if err != nil {
		log.Println("Error in ldap search")
		return false, "", err
	}

	if len(result.Entries) == 0 {
		log.Println("No records found")
		return false, "", nil
	}
	if len(result.Entries) > 1 {
		log.Println("duplicate entries!")
		return true, "", errors.New("Multiple entries available! Contact the administration!")
	}
	if groupname != result.Entries[0].GetAttributeValue("cn") {
		return false, "", errors.New("something wrong in ldapsearch!")
	}

	if result.Entries[0].GetAttributeValues(u.GroupManageAttribute) == nil {
		return true, "", nil
	}
	Groupmanagedby := result.Entries[0].GetAttributeValue(u.GroupManageAttribute)

	return true, Groupmanagedby, nil
}

func (u *UserInfoLDAPSource) ServiceAccountExistsornot(groupname string) (bool, string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return false, "", err
	}
	defer conn.Close()

	Attributes := []string{"cn", "uid"}
	searchrequest := ldap.NewSearchRequest(u.ServiceAccountBaseDNs, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false, "(|(cn="+groupname+" )(uid="+groupname+"))",
		Attributes, nil)
	result, err := conn.Search(searchrequest)
	if err != nil {
		log.Println(err)
		return false, "", err
	}

	if len(result.Entries) == 0 {
		log.Println("No records found")
		return false, "", nil
	}
	if len(result.Entries) > 2 {
		log.Println("duplicate entries!")
		return true, "", errors.New("Multiple entries available! Contact the administration!")
	}
	if groupname != result.Entries[0].GetAttributeValue("cn") {
		serviceAccountDN := result.Entries[0].DN
		return false, serviceAccountDN, errors.New("something wrong in ldapsearch!")
	}
	serviceAccountDN := result.Entries[0].DN

	return true, serviceAccountDN, nil
}

func (u *UserInfoLDAPSource) GetGroupDN(groupname string) (string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return "", err
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		u.GroupSearchBaseDNs,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(cn="+groupname+" ))",
		nil,
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Println(err)
		return "", err
	}
	if len(sr.Entries) > 1 {
		log.Println("Duplicate entries found")
		return "", errors.New("Multiple entries found, Contact the administrator!")
	}
	users := sr.Entries[0].DN
	return users, nil
}

func (u *UserInfoLDAPSource) GetGroupsInfoOfUser(groupdn string, username string) ([][]string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var GroupandDescriptionPair [][]string
	var Groupattributes []string

	searchRequest := ldap.NewSearchRequest(
		groupdn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(memberUid="+username+" ))",
		nil, //memberOf (if searching other way around using usersdn instead of groupdn)
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	for _, entry := range sr.Entries {
		Groupattributes = append(Groupattributes, entry.GetAttributeValue("cn"), entry.GetAttributeValue(u.GroupManageAttribute))
		GroupandDescriptionPair = append(GroupandDescriptionPair, Groupattributes)
		Groupattributes = nil
	}
	return GroupandDescriptionPair, nil
}

func (u *UserInfoLDAPSource) GetallGroupsandDescription(grouddn string) ([][]string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var GroupandDescriptionPair [][]string
	var Groupattributes []string

	searchrequest := ldap.NewSearchRequest(grouddn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(|(objectClass=posixGroup)(objectClass=groupofNames))", []string{"cn", u.GroupManageAttribute}, nil)
	result, err := conn.Search(searchrequest)
	if err != nil {
		return nil, err
	}
	for _, entry := range result.Entries {
		Groupattributes = append(Groupattributes, entry.GetAttributeValue("cn"), entry.GetAttributeValue(u.GroupManageAttribute))
		GroupandDescriptionPair = append(GroupandDescriptionPair, Groupattributes)
		Groupattributes = nil
	}
	return GroupandDescriptionPair, nil

}

func (u *UserInfoLDAPSource) GetGroupandManagedbyAttributeValue(groupnames []string) ([][]string, error) {

	GroupandDescriptionPair, err := u.GetallGroupsandDescription(u.GroupSearchBaseDNs)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	var UserGroupInfo [][]string
	for _, eachgroup := range groupnames {
		for _, eachEntry := range GroupandDescriptionPair {
			if eachEntry[0] == eachgroup {
				UserGroupInfo = append(UserGroupInfo, eachEntry)
				break
			}
		}
	}
	return UserGroupInfo, nil
}
