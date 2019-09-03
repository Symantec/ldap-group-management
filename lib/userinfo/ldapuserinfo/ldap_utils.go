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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const ldapTimeoutSecs = 10
const pageSearchSize = 1024

const HomeDirectory = "/home/"
const objectClassgroupofNames = "groupOfNames"

const (
	UserServiceAccount  userinfo.AccountType = 1
	GroupServiceAccount userinfo.AccountType = 2
)

const LoginShell = "/bin/bash"

const searchLDAPparam = "uid"
const searchADparam = "sAMAccountName"

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

	RootCAs *x509.CertPool

	allUsersRWLock                     sync.RWMutex
	allUsersCacheValue                 []string
	allUsersCacheExpiration            time.Time
	allGroupsMutex                     sync.Mutex
	allGroupsCacheValue                []string
	allGroupsCacheExpiration           time.Time
	allGroupsAndManagerCacheMutex      sync.Mutex
	allGroupsAndManagerCacheValue      [][]string
	allGroupsAndManagerCacheExpiration time.Time

	userAttribute string
}

func (u *UserInfoLDAPSource) GetInfoFromAD(username, userattribute string) ([]string, []string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	u.userAttribute = userattribute
	result, err := u.getInfoofUserInternal(conn, username, []string{u.UserSearchBaseDNs}, []string{"mail", "givenName"})
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	email, ok := result["mail"]
	if !ok {
		log.Println("error parse mail")
		return nil, nil, errors.New("error parse mail")
	}
	givenName, ok := result["givenName"]
	if !ok {
		log.Println("error parse givenName")
		return nil, nil, errors.New("error parse givenName")
	}
	return email, givenName, nil
}

func (u *UserInfoLDAPSource) flushGroupCaches() {
	u.allGroupsMutex.Lock()
	defer u.allGroupsMutex.Unlock()
	u.allGroupsCacheExpiration = time.Now()
	u.allGroupsAndManagerCacheMutex.Lock()
	defer u.allGroupsAndManagerCacheMutex.Unlock()
	u.allGroupsAndManagerCacheExpiration = time.Now()

}

func extractCNFromDNString(input []string) (output []string, err error) {
	re := regexp.MustCompile("^cn=([^,]+),.*")
	for _, dn := range input {
		matches := re.FindStringSubmatch(dn)
		if len(matches) == 2 {
			output = append(output, matches[1])
		} else {
			//log.Printf("dn='%s' matches=%v", dn, matches)
			output = append(output, dn)
		}
	}
	return output, nil
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
		conn, _, err := getLDAPConnection(*TargetLdapUrl, ldapTimeoutSecs, u.RootCAs)

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
func (u *UserInfoLDAPSource) getallUsersNonCached() ([]string, error) {
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
	t0 := time.Now()
	result, err := conn.SearchWithPaging(searchrequest, pageSearchSize)
	t1 := time.Now()
	log.Printf("GetallUsers search Took %v to run", t1.Sub(t0))
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

const allUsersCacheDuration = time.Second * 60

func (u *UserInfoLDAPSource) GetallUsers() ([]string, error) {
	u.allUsersRWLock.Lock()
	defer u.allUsersRWLock.Unlock()
	if u.allUsersCacheExpiration.After(time.Now()) {
		allUsers := u.allUsersCacheValue
		return allUsers, nil
	}
	allUsers, err := u.getallUsersNonCached()
	if err != nil {
		return nil, err
	}
	u.allUsersCacheValue = allUsers
	u.allUsersCacheExpiration = time.Now().Add(allUsersCacheDuration)
	return allUsers, nil
}

//To build a user base DN using uid only for Target LDAP.
func (u *UserInfoLDAPSource) createUserDN(username string) string {
	//uid := username
	result := "uid=" + username + "," + u.UserSearchBaseDNs
	return string(result)
}

//To build a GroupDN for a particular group in Target ldaputil
func (u *UserInfoLDAPSource) createGroupDN(groupname string) string {
	result := "cn=" + groupname + "," + u.GroupSearchBaseDNs
	return string(result)
}

func (u *UserInfoLDAPSource) createServiceDN(groupname string, a userinfo.AccountType) string {
	var serviceDN string
	if a == UserServiceAccount {
		serviceDN = "uid=" + groupname + "," + u.ServiceAccountBaseDNs
	}
	if a == GroupServiceAccount {
		serviceDN = "cn=" + groupname + "," + u.ServiceAccountBaseDNs
	}
	return string(serviceDN)
}

////
// GetGroupsOfUser returns the all groups of a user. --required
func (u *UserInfoLDAPSource) getUserDN(conn *ldap.Conn, username string, searchPaths []string) (string, error) {
	for _, searchPath := range searchPaths {
		searchRequest := ldap.NewSearchRequest(
			searchPath,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(&("+u.userAttribute+"="+username+"))",
			[]string{"uid", "dn"}, //memberOf (if searching other way around using usersdn instead of groupdn)
			nil,
		)
		sr, err := conn.Search(searchRequest)
		if err != nil {
			log.Println(err)
			return "", err
		}
		if len(sr.Entries) < 1 {
			continue
		}

		if len(sr.Entries) != 1 {
			log.Printf("User does not exist or too many entries returned")
			return "", errors.New("user does not exist or too many users")
		}
		return sr.Entries[0].DN, nil
	}
	return "", userinfo.UserDoesNotExist

}

//Creating a Group --required
func (u *UserInfoLDAPSource) CreateGroup(groupinfo userinfo.GroupInfo) error {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()

	entry := u.createGroupDN(groupinfo.Groupname)
	gidnum, err := u.getMaximumGIDNumber(conn, u.GroupSearchBaseDNs)
	if err != nil {
		log.Println(err)
		return err
	}

	var managerAttributeValue string
	switch strings.ToLower(u.GroupManageAttribute) {
	case "owner":
		if groupinfo.Description == "self-managed" {
			managerAttributeValue = entry
			break
		}
		managerDN, err := u.getGroupDN(conn, groupinfo.Description)
		if err != nil {
			log.Println(err)
			return err
		}
		managerAttributeValue = managerDN
	default:
		managerAttributeValue = groupinfo.Description
	}

	if len(groupinfo.Member) == 0 {
		for _, memberUid := range groupinfo.MemberUid {
			groupinfo.Member = append(groupinfo.Member, u.createUserDN(memberUid))
		}
	}

	group := ldap.NewAddRequest(entry)
	group.Attribute("objectClass", []string{"posixGroup", "top", "groupOfNames"})
	group.Attribute("cn", []string{groupinfo.Groupname})
	group.Attribute(u.GroupManageAttribute, []string{managerAttributeValue})
	group.Attribute("member", groupinfo.Member)
	group.Attribute("memberUid", groupinfo.MemberUid)
	group.Attribute("gidNumber", []string{gidnum})
	err = conn.Add(group)
	if err != nil {
		log.Println(err)
		return err
	}
	log.Printf("Created new group (%+v)?", groupinfo)

	//flush group caches
	u.flushGroupCaches()

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
		groupdn, err := u.getGroupDN(conn, entry)
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

	entry, err := u.getGroupDN(conn, groupname)
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
func (u *UserInfoLDAPSource) deleteDescription(groupnames []string) error {

	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()

	for _, entry := range groupnames {
		entry, err = u.getGroupDN(conn, entry)
		if err != nil {
			log.Println(err)
			return err
		}

		modify := ldap.NewModifyRequest(entry)

		modify.Delete(u.GroupManageAttribute, []string{"created by Midpoint"})
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
	entry, err := u.getGroupDN(conn, groupname)
	if err != nil {
		log.Println(err)
		return err
	}
	var attributeValue string
	switch strings.ToLower(u.GroupManageAttribute) {
	case "owner":
		managerDN, err := u.getGroupDN(conn, managegroup)
		if err != nil {
			log.Println(err)
			return err
		}
		attributeValue = managerDN
	default:
		attributeValue = managegroup
	}
	log.Printf("attributeValue=%s", attributeValue)
	modify := ldap.NewModifyRequest(entry)
	modify.Replace(u.GroupManageAttribute, []string{attributeValue})
	err = conn.Modify(modify)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

//function to get all the groups in Target ldaputil and put it in array --required
func (u *UserInfoLDAPSource) getallGroupsNonCached() ([]string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer conn.Close()

	var AllGroups []string
	searchrequest := ldap.NewSearchRequest(u.GroupSearchBaseDNs, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, u.GroupSearchFilter, []string{"cn"}, nil)
	t0 := time.Now()
	result, err := conn.SearchWithPaging(searchrequest, pageSearchSize)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	t1 := time.Now()
	log.Printf("GetAllGroups: search Took %v to run", t1.Sub(t0))
	for _, entry := range result.Entries {
		AllGroups = append(AllGroups, entry.GetAttributeValue("cn"))
	}
	return AllGroups, nil
}

const allGroupsCacheDuration = time.Second * 30

func (u *UserInfoLDAPSource) GetallGroups() ([]string, error) {

	u.allGroupsMutex.Lock()
	defer u.allGroupsMutex.Unlock()
	if u.allGroupsCacheExpiration.After(time.Now()) {
		return u.allGroupsCacheValue, nil
	}
	allGroups, err := u.getallGroupsNonCached()
	if err != nil {
		return nil, err
	}
	u.allGroupsCacheValue = allGroups
	u.allGroupsCacheExpiration = time.Now().Add(allGroupsCacheDuration)
	return allGroups, nil
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
	return u.getGroupUsersInternal(conn, groupname)
}

// This might become unndded if we can get connection reuse.
func (u *UserInfoLDAPSource) GetGroupUsersAndManagers(groupname string) ([]string, []string, string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return nil, nil, "", err
	}
	defer conn.Close()
	groupUsers, managerGroupName, err := u.getGroupUsersInternal(conn, groupname)
	if err != nil {
		return nil, nil, "", err
	}
	managerUsers, _, err := u.getGroupUsersInternal(conn, managerGroupName)
	if err != nil {
		if err == userinfo.GroupDoesNotExist {
			var emptyUsers []string
			return groupUsers, emptyUsers, managerGroupName, nil
		}
		return nil, nil, "", err
	}
	return groupUsers, managerUsers, managerGroupName, nil
}

func (u *UserInfoLDAPSource) getGroupUsersInternal(conn *ldap.Conn, groupname string) ([]string, string, error) {

	searchRequest := ldap.NewSearchRequest(
		u.GroupSearchBaseDNs,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(cn="+groupname+" )(objectClass=posixGroup))",
		[]string{"memberUid", u.GroupManageAttribute},
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
	if len(sr.Entries) < 1 {
		return nil, "", userinfo.GroupDoesNotExist
	}
	users := sr.Entries[0].GetAttributeValues("memberUid")
	if sr.Entries[0].GetAttributeValues(u.GroupManageAttribute) == nil {
		return users, "", nil
	}

	GroupmanagedbyValue := sr.Entries[0].GetAttributeValue(u.GroupManageAttribute)
	switch strings.ToLower(u.GroupManageAttribute) {
	case "owner":
		groupCN, err := extractCNFromDNString([]string{GroupmanagedbyValue})
		if err != nil {
			log.Println(err)
			return users, "", err
		}
		GroupmanagedbyValue = groupCN[0]
	default:
		GroupmanagedbyValue = GroupmanagedbyValue
	}

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
func (u *UserInfoLDAPSource) getMaximumGIDNumber(conn *ldap.Conn, searchBaseDN string) (string, error) {
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

func (u *UserInfoLDAPSource) getMaximumUIDNumber(conn *ldap.Conn, searchBaseDN string) (string, error) {
	searchRequest := ldap.NewSearchRequest(
		searchBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(uidNumber=*))",
		[]string{"uidNumber"},
		nil,
	)
	sr, err := conn.SearchWithPaging(searchRequest, pageSearchSize)
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
	entry, err := u.getGroupDN(conn, groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		return err
	}
	u.userAttribute = searchLDAPparam
	if len(groupinfo.Member) == 0 {
		for _, memberUid := range groupinfo.MemberUid {
			userDN, err := u.getUserDN(conn, memberUid, []string{u.UserSearchBaseDNs, u.ServiceAccountBaseDNs})
			if err != nil {
				return err
			}
			groupinfo.Member = append(groupinfo.Member, userDN)
		}
	}
	modify := ldap.NewModifyRequest(entry)
	modify.Add("member", groupinfo.Member)
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

	entry, err := u.getGroupDN(conn, groupinfo.Groupname)
	if err != nil {
		log.Println(err)
		return err
	}
	modify := ldap.NewModifyRequest(entry)
	modify.Delete("memberUid", groupinfo.MemberUid)

	u.userAttribute = searchLDAPparam
	if len(groupinfo.Member) == 0 {
		for _, memberUid := range groupinfo.MemberUid {
			userDN, err := u.getUserDN(conn, memberUid, []string{u.UserSearchBaseDNs, u.ServiceAccountBaseDNs})
			if err != nil {
				return err
			}
			groupinfo.Member = append(groupinfo.Member, userDN)
		}
	}

	modify.Delete("member", groupinfo.Member)
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
		[]string{u.GroupManageAttribute, "cn"},
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
	if len(sr.Entries) < 1 {
		return "", userinfo.GroupDoesNotExist
	}
	if sr.Entries[0].GetAttributeValues(u.GroupManageAttribute) == nil {
		log.Println("No group managed attribute")
		return "", nil
	}
	GroupmanagedbyValue := sr.Entries[0].GetAttributeValue(u.GroupManageAttribute)
	switch strings.ToLower(u.GroupManageAttribute) {
	case "owner":
		groupCN, err := extractCNFromDNString([]string{GroupmanagedbyValue})
		if err != nil {
			log.Println(err)
			return "", err
		}
		GroupmanagedbyValue = groupCN[0]
	default:
		GroupmanagedbyValue = GroupmanagedbyValue
	}
	log.Printf("groupmanagedbyValue=%s", GroupmanagedbyValue)

	return GroupmanagedbyValue, nil
}

//get email of a user
func (u *UserInfoLDAPSource) GetEmailofauser(username string) ([]string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer conn.Close()
	u.userAttribute = searchLDAPparam
	result, err := u.getInfoofUserInternal(conn, username, []string{u.UserSearchBaseDNs}, []string{"mail"})
	if err != nil {
		log.Println(err)
		return nil, err
	}
	email, ok := result["mail"]
	if !ok {
		log.Println("Failed to parse email")
		return nil, errors.New("Failed to parse email")
	}
	return email, nil
}

func (u *UserInfoLDAPSource) getInfoofUserInternal(conn *ldap.Conn, username string, searchPath, searchParams []string) (map[string][]string, error) {
	Userdn, err := u.getUserDN(conn, username, searchPath)
	if err != nil {
		return nil, err
	}

	searchrequest := ldap.NewSearchRequest(Userdn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(&("+u.userAttribute+"="+username+"))", searchParams, nil)
	result, err := conn.Search(searchrequest)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if len(result.Entries) < 1 {
		log.Printf("no such user")
		return nil, userinfo.UserDoesNotExist
	}

	resultInfo := make(map[string][]string)
	for _, param := range searchParams {
		if len(result.Entries[0].GetAttributeValues(param)) < 1 {
			return nil, errors.New("User does not have " + param)
		}
		resultInfo[param] = result.Entries[0].GetAttributeValues(param)
	}
	return resultInfo, nil
}

//get email of all users in the given group
func (u *UserInfoLDAPSource) GetEmailofusersingroup(groupname string) ([]string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer conn.Close()

	groupUsers, _, err := u.getGroupUsersInternal(conn, groupname)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	var userEmail []string
	log.Printf("GetEmailofusersingroup:%s, %+v", groupname, groupUsers)
	u.userAttribute = searchLDAPparam
	for _, entry := range groupUsers {
		value, err := u.getInfoofUserInternal(conn, entry, []string{u.UserSearchBaseDNs}, []string{"mail"})
		if err != nil {
			log.Println(err)
			if err == userinfo.UserDoesNotHaveEmail {
				continue
			}
			return nil, err
		}
		mail, ok := value["mail"]
		if !ok {
			log.Println("error parse user email")
			return nil, errors.New("error parse user email")
		}
		userEmail = append(userEmail, mail[0])

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

	gidnum, err := u.getMaximumGIDNumber(conn, u.ServiceAccountBaseDNs)
	if err != nil {
		log.Println(err)
		return err
	}
	uidnum, err := u.getMaximumUIDNumber(conn, u.ServiceAccountBaseDNs)
	if err != nil {
		log.Println(err)
		return err
	}
	serviceDN := u.createServiceDN(groupinfo.Groupname, GroupServiceAccount)

	group := ldap.NewAddRequest(serviceDN)
	group.Attribute("objectClass", []string{"posixGroup", "top", "groupOfNames"})
	group.Attribute("cn", []string{groupinfo.Groupname})
	group.Attribute("gidNumber", []string{gidnum})
	err = conn.Add(group)
	if err != nil {
		log.Println(err)
		return err
	}

	serviceDN = u.createServiceDN(groupinfo.Groupname, UserServiceAccount)

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

func (u *UserInfoLDAPSource) getGroupDN(conn *ldap.Conn, groupname string) (string, error) {
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
	if len(sr.Entries) < 1 {
		log.Printf("No DN found for group:%s", groupname)
		return "", userinfo.GroupDoesNotExist
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
		[]string{"dn", "cn", u.GroupManageAttribute},
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	for _, entry := range sr.Entries {
		managerValue := entry.GetAttributeValue(u.GroupManageAttribute)
		switch strings.ToLower(u.GroupManageAttribute) {
		case "owner":
			groupCN, err := extractCNFromDNString([]string{managerValue})
			if err != nil {
				log.Println(err)
				return nil, err
			}
			managerValue = groupCN[0]
		default:
			managerValue = managerValue
		}
		Groupattributes = append(Groupattributes, entry.GetAttributeValue("cn"), managerValue)
		GroupandDescriptionPair = append(GroupandDescriptionPair, Groupattributes)
		Groupattributes = nil
	}
	return GroupandDescriptionPair, nil
}

func (u *UserInfoLDAPSource) getAllGroupsManagedByNonCached() ([][]string, error) {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var GroupandDescriptionPair [][]string
	var Groupattributes []string

	searchrequest := ldap.NewSearchRequest(u.GroupSearchBaseDNs, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(|(objectClass=posixGroup)(objectClass=groupofNames))", []string{"cn", u.GroupManageAttribute}, nil)

	t0 := time.Now()
	result, err := conn.Search(searchrequest)
	if err != nil {
		return nil, err
	}
	t1 := time.Now()
	log.Printf("getAllGroupsAndManagedby Search Took %v to run", t1.Sub(t0))
	for _, entry := range result.Entries {
		managerValue := entry.GetAttributeValue(u.GroupManageAttribute)
		switch strings.ToLower(u.GroupManageAttribute) {
		case "owner":
			groupCN, err := extractCNFromDNString([]string{managerValue})
			if err != nil {
				log.Println(err)
				return nil, err
			}
			managerValue = groupCN[0]
		default:
			managerValue = managerValue
		}

		Groupattributes = append(Groupattributes, entry.GetAttributeValue("cn"), managerValue)
		GroupandDescriptionPair = append(GroupandDescriptionPair, Groupattributes)
		Groupattributes = nil
	}
	return GroupandDescriptionPair, nil
}

func (u *UserInfoLDAPSource) GetAllGroupsManagedBy() ([][]string, error) {

	u.allGroupsAndManagerCacheMutex.Lock()
	defer u.allGroupsAndManagerCacheMutex.Unlock()
	if u.allGroupsAndManagerCacheExpiration.After(time.Now()) {
		return u.allGroupsAndManagerCacheValue, nil
	}
	allGroups, err := u.getAllGroupsManagedByNonCached()
	if err != nil {
		return nil, err
	}
	u.allGroupsAndManagerCacheValue = allGroups
	u.allGroupsAndManagerCacheExpiration = time.Now().Add(allGroupsCacheDuration)
	return allGroups, nil
}

func (u *UserInfoLDAPSource) GetGroupandManagedbyAttributeValue(groupnames []string) ([][]string, error) {

	GroupandDescriptionPair, err := u.GetAllGroupsManagedBy()
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

func (u *UserInfoLDAPSource) CreateUser(username string, givenName, email []string) error {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()

	uidnum, err := u.getMaximumUIDNumber(conn, u.UserSearchBaseDNs)
	if err != nil {
		log.Println(err)
		return err
	}

	userDN := u.createUserDN(username)

	user := ldap.NewAddRequest(userDN)
	user.Attribute("objectClass", []string{"posixAccount", "person", "ldapPublicKey", "organizationalPerson", "inetOrgPerson", "shadowAccount", "top", "inetUser", "pwmuser"})
	user.Attribute("cn", []string{username})
	user.Attribute("uid", []string{username})
	user.Attribute("gecos", []string{username})
	user.Attribute("givenName", givenName)
	user.Attribute("displayName", []string{username})
	user.Attribute("sn", []string{username})

	user.Attribute("homeDirectory", []string{HomeDirectory + username})
	user.Attribute("loginShell", []string{LoginShell})
	user.Attribute("sshPublicKey", []string{""})
	user.Attribute("shadowExpire", []string{"-1"})
	user.Attribute("shadowFlag", []string{"0"})
	user.Attribute("shadowLastChange", []string{"1"})
	user.Attribute("shadowMax", []string{"99999"})
	user.Attribute("shadowMin", []string{"0"})
	user.Attribute("shadowWarning", []string{"7"})
	user.Attribute("mail", email)
	user.Attribute("uidNumber", []string{uidnum})
	user.Attribute("gidNumber", []string{"100"})

	err = conn.Add(user)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}
