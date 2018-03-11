package main

import (
	"net/url"
	"crypto/x509"
	"strings"
	"time"
	"crypto/tls"
	"gopkg.in/ldap.v2"
	"net"
	"log"
	"errors"
	"flag"
	"gopkg.in/yaml.v2"
	"os"
	"io/ioutil"
	//"fmt"
	"github.com/Symantec/keymaster/lib/authutil"
	"github.com/gorilla/mux"
	"net/http"
	"encoding/json"
	"sort"
)


type baseConfig struct {
	HttpAddress           string `yaml:"http_address"`
	TLSCertFilename       string `yaml:"tls_cert_filename"`
	TLSKeyFilename        string `yaml:"tls_key_filename"`
	StorageURL            string `yaml:"storage_url"`
	OpenIDCConfigFilename string `yaml:"openidc_config_filename"`
}

type UserInfoLDAPSource struct {
	BindUsername       string   `yaml:"bind_username"`
	BindPassword       string   `yaml:"bind_password"`
	LDAPTargetURLs     string   `yaml:"ldap_target_urls"`
	UserSearchBaseDNs  string `yaml:"user_search_base_dns"`
	UserSearchFilter   string   `yaml:"user_search_filter"`
	GroupSearchBaseDNs string `yaml:"group_search_base_dns"`
	GroupSearchFilter  string   `yaml:"group_search_filter"`
}

type AppConfigFile struct {
	Base       baseConfig         `yaml:"base"`
	SourceLDAP UserInfoLDAPSource `yaml:"source_config"`
	TargetLDAP UserInfoLDAPSource `yaml:"target_config"`
}

type RuntimeState struct {
	Config       AppConfigFile
	ADldap       *ldap.Conn
	CPEldap      *ldap.Conn

}
type GetGroups struct{
	AllGroups []string `json:"allgroups"`

}
type GetUsers struct{
	Users []string `json:"Users"`
}

type GetUserGroups struct{
	UserName string `json:"Username"`
	UserGroups []string `json:"usergroups"`
}

type GetGroupUsers struct{
	GroupName string `json:"groupname"`
	Groupusers []string `json:"Groupusers"`

}



const ldapTimeoutSecs = 3


//maximum possible paging size number
const maximum_pagingsize =2147483647


var (
	configFilename = flag.String("config", "config.yml", "The filename of the configuration")
	//debug          = flag.Bool("debug", false, "enable debugging output")
	//authSource     *authhandler.SimpleOIDCAuth
)


//parses the config file
func loadConfig(configFilename string) (RuntimeState, error) {

	var state RuntimeState

	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return state, err
	}

	//ioutil.ReadFile returns a byte slice (i.e)(source)
	source, err := ioutil.ReadFile(configFilename)
	if err != nil {
		err = errors.New("cannot read config file")
		return state, err
	}

	//Unmarshall(source []byte,out interface{})decodes the source byte slice/value and puts them in out.
	err = yaml.Unmarshal(source, &state.Config)

	if err != nil {
		err = errors.New("Cannot parse config file")
		log.Printf("Source=%s", source)
		return state, err
	}
	return state,err
}




func getLDAPConnection(u url.URL, timeoutSecs uint, rootCAs *x509.CertPool) (*ldap.Conn, string, error) {

	if u.Scheme != "ldaps" {
		err := errors.New("Invalid ldap scheme (we only support ldaps)")
		return nil, "", err
	}

	//hostnamePort := server + ":636"

	serverPort := strings.Split(u.Host, ":")
	port := "636"

	if len(serverPort) == 2 {
		port = serverPort[1]
	}

	server := serverPort[0]
	hostnamePort := server + ":" + port

	timeout := time.Duration(time.Duration(timeoutSecs) * time.Second)
	start := time.Now()

	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", hostnamePort,nil)
	//&tls.Config{ServerName: server, RootCAs: rootCAs})

	if err != nil {
		errorTime := time.Since(start).Seconds() * 1000
		log.Printf("connection failure for:%s (%s)(time(ms)=%v)", server, err.Error(), errorTime)
		return nil, "", err
	}

	// we dont close the tls connection directly  close defer to the new ldap connection
	conn := ldap.NewConn(tlsConn, true)
	return conn, server, nil
}

//establishing the connection.
func getLDAPConnection1(u url.URL, timeoutSecs uint) (*ldap.Conn, string, error) {

	if u.Scheme != "ldaps" {
		err := errors.New("Invalid ldap scheme (we only support ldaps)")
		return nil, "", err
	}

	//hostnamePort := server + ":636"

	serverPort := strings.Split(u.Host, ":")
	port := "636"

	if len(serverPort) == 2 {
		port = serverPort[1]
	}

	server := serverPort[0]
	hostnamePort := server + ":" + port

	//timeout := time.Duration(time.Duration(timeoutSecs) * time.Second)
	start := time.Now()

	//tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", hostnamePort,&tls.Config{InsecureSkipVerify:true,ServerName:server})
	conn,err :=  ldap.DialTLS("tcp",hostnamePort,&tls.Config{InsecureSkipVerify:true,ServerName:server})
	if err != nil {
		errorTime := time.Since(start).Seconds() * 1000
		log.Printf("connection failure for:%s (%s)(time(ms)=%v)", server, err.Error(), errorTime)
		return nil, "", err
	}

	// we dont close the tls connection directly  close defer to the new ldap connection
	//conn := ldap.NewConn(tlsConn, true)
	return conn, server, nil
}



//Function which returns the array of disabled accounts from Active Directory AD.
func (state *RuntimeState) DisabledAccountsinAD(UserSearchBaseDNs string, UserSearchFilter string, Attributes []string)([]string,error){
	var disabled_accounts []string

	searchrequest := ldap.NewSearchRequest(UserSearchBaseDNs,ldap.ScopeWholeSubtree,ldap.NeverDerefAliases, 0,0,false,UserSearchFilter,Attributes,nil)

	result, err:= state.ADldap.SearchWithPaging(searchrequest,maximum_pagingsize)
	if err !=nil{
		return nil,err
	}
	if len(result.Entries)==0{
		log.Println("No records found")
	}
	for _,entry := range result.Entries{
		cname := entry.GetAttributeValue("sAMAccountName")
		disabled_accounts=append(disabled_accounts,strings.ToLower(cname))
	}
	return disabled_accounts,nil
}



//function which compares the users disabled accounts in AD with CPE LDAP and adds the attribute nsaccountLock in CPE ldap for the disbaled USer.
func (state *RuntimeState) CompareDisabledaccounts(userdn string,result []string)(error){
	for _,entry:=range result{
		entry=userDN(userdn,entry)

		modify := ldap.NewModifyRequest(entry)
		modify.Replace("nsaccountLock",[]string{"True"})
		err:=state.CPEldap.Modify(modify)
		if err !=nil{
			return err
		}
	}
	return nil

}



//Get all ldap users and put that in map
func (state *RuntimeState) GetallUsers(UserSearchBaseDNs string, UserSearchFilter string, hello []string) (map[string]string,error){
	AllUsersinLdap := make(map[string]string)

	searchrequest := ldap.NewSearchRequest(UserSearchBaseDNs,ldap.ScopeWholeSubtree,ldap.NeverDerefAliases, 0,0,false,UserSearchFilter,hello,nil)
	result, err := state.CPEldap.Search(searchrequest)
	if err !=nil{
		return nil,err
	}

	if len(result.Entries)==0{
		log.Println("No records found")
	}
	for _,entry := range result.Entries{
		uid := entry.GetAttributeValue("uid")
		AllUsersinLdap[uid]=uid
	}

	return AllUsersinLdap,nil
}


//find out which accounts need to be locked in cpe ldap(i.e. which accounts needs attribute nsaccountLock=True
func FindLockAccountsinCPELdap(finalLdap map[string]string,finalAD []string ) ([]string,error){
	var lock_accounts []string
	for _,entry:=range finalAD{
		if entry, ok := finalLdap[entry]; ok{

			lock_accounts=append(lock_accounts,entry)
		}

	}
	return lock_accounts,nil
}


//To build a user base DN using uid only for CPE LDAP.
func userDN(usersdn string,username string)(string){
	//uid := username
	result := "uid="+ username +","+usersdn

	return string(result)

}

//To build a GroupDN for a particular group in cpe ldap
func GroupDN(groupdn string,groupname string)(string){
	result := "cn="+groupname+","+groupdn

	return string(result)

}


//function to get details of a user from cpe ldap.(should make some changes)
func (state *RuntimeState) UserInfo(userdn string)([]string,error) {
	var user_info []string
	searchrequest := ldap.NewSearchRequest(userdn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "((objectClass=*))", nil, nil)
	result, err := state.CPEldap.Search(searchrequest)
	if err != nil {
		return nil, err
	}
	for _, entry := range result.Entries {
		user_info = entry.GetAttributeValues("objectClass")
		//println(entry.GetAttributeValue(entry.Attributes[5].Name))
	}
	return user_info, nil
}

//function to get all the groups in cpe ldap and put it in array
func (state *RuntimeState) GetAllGroupsinCPELdap(groupdn string)([]string,error){
	var all_groups []string
	searchrequest := ldap.NewSearchRequest(groupdn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(&(objectClass=posixGroup)(objectClass=groupofNames)(objectClass=top))", nil, nil)
	result, err := state.CPEldap.Search(searchrequest)
	if err !=nil{
		return nil,err
	}
	for _,entry:=range result.Entries{
		all_groups=append(all_groups,entry.GetAttributeValue("cn"))
	}
	return all_groups,nil
}


// GetGroupsOfUser returns the all groups of a user.
func (state *RuntimeState) GetGroupsOfUser(groupdn string,username string) ([]string, error) {
	//Base:=userDN(username)
	Base:=groupdn
	searchRequest := ldap.NewSearchRequest(
		Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(memberUid="+username+" ))",
		[]string{"cn"},//memberOf (if searching other way around using usersdn instead of groupdn)
		nil,
	)
	sr, err := state.CPEldap.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		groups = append(groups,entry.GetAttributeValue("cn"))
	}
	return groups, nil
}


//returns all the users of a group
func (state *RuntimeState) GetUsersofaGroup(groupdn string,groupname string) ([][]string, error) {
	Base:=GroupDN(groupdn,groupname)

	searchRequest := ldap.NewSearchRequest(
		Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"((objectClass=*))",
		[]string{"memberUid"},
		nil,
	)
	sr, err := state.CPEldap.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	users := [][]string{}
	for _, entry := range sr.Entries {
		users = append(users, entry.GetAttributeValues("memberUid"))
	}
	return users, nil
}





//All handlers and API endpoints starts from here.

//Display all groups in CPE LDAP
func (state *RuntimeState) GetAllGroups(w http.ResponseWriter, r *http.Request) {
	var AllGroupsinCPE GetGroups

	Allgroups,err:=state.GetAllGroupsinCPELdap(state.Config.SourceLDAP.GroupSearchBaseDNs)

	if err!=nil{
		log.Panic(err)
	}
	sort.Strings(Allgroups)
	AllGroupsinCPE.AllGroups=Allgroups
	json.NewEncoder(w).Encode(AllGroupsinCPE)

}

//Display all users in CPE LDAP
func (state *RuntimeState) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	var AllUsersinCPE GetUsers

	AllUsers,err:=state.GetallUsers(state.Config.SourceLDAP.UserSearchBaseDNs,state.Config.SourceLDAP.UserSearchFilter,[]string{"uid"})

	if err!=nil{
		log.Println(err)
	}

	for k := range AllUsers {
		AllUsersinCPE.Users = append(AllUsersinCPE.Users, k)
	}

	json.NewEncoder(w).Encode(AllUsersinCPE)
}


//Displays all Groups of a User.
func (state *RuntimeState) GetUserAllGroups(w http.ResponseWriter, r *http.Request){
	params := mux.Vars(r)
	var user_groups GetUserGroups

	_ = json.NewDecoder(r.Body).Decode(&user_groups)
	user_groups.UserName = params["username"] //username is "cn" Attribute of a User
	UsersAllgroups,err:=state.GetGroupsOfUser(state.Config.SourceLDAP.GroupSearchBaseDNs,user_groups.UserName)
	sort.Strings(UsersAllgroups)
	user_groups.UserGroups=UsersAllgroups

	if err!=nil{
		log.Println(err)
	}

	json.NewEncoder(w).Encode(user_groups)
}


//Displays All Users in a Group
func (state *RuntimeState) GetUsersinGroup(w http.ResponseWriter, r *http.Request){
	params := mux.Vars(r)
	var group_users GetGroupUsers

	_ = json.NewDecoder(r.Body).Decode(&group_users)
	group_users.GroupName = params["groupname"] //username is "cn" Attribute of a User
	AllUsersinGroup,err:=state.GetUsersofaGroup(state.Config.SourceLDAP.GroupSearchBaseDNs,group_users.GroupName)
	sort.Strings(AllUsersinGroup[0])
	group_users.Groupusers=AllUsersinGroup[0]

	if err!=nil{
		log.Println(err)
	}

	json.NewEncoder(w).Encode(group_users)
}


func (state *RuntimeState) CreateGroup(w http.ResponseWriter, r *http.Request) {



}


func (state *RuntimeState) DeleteGroup(w http.ResponseWriter, r *http.Request) {



}











func main(){
	flag.Parse()

	state, err := loadConfig(*configFilename)
	if err != nil {
		panic(err)
	}

	//Parsing AD URL, establishing connection and binding user.
	LdapAdUrl,err:= authutil.ParseLDAPURL(state.Config.TargetLDAP.LDAPTargetURLs)

	state.ADldap,_,err= getLDAPConnection1(*LdapAdUrl,ldapTimeoutSecs)
	if err != nil {
		panic(err)
	}

	err=state.ADldap.Bind(state.Config.TargetLDAP.BindUsername,state.Config.TargetLDAP.BindPassword)

	if err!=nil{
		panic(err)
	}


	//Parsing CPE LDAP, establishing connection and binding user.
	CpeLdapUrl,err:= authutil.ParseLDAPURL(state.Config.SourceLDAP.LDAPTargetURLs)

	state.CPEldap,_,err=getLDAPConnection1(*CpeLdapUrl,ldapTimeoutSecs)
	if err != nil {
		panic(err)
	}

	err=state.CPEldap.Bind(state.Config.SourceLDAP.BindUsername,state.Config.SourceLDAP.BindPassword)

	if err!=nil{
		panic(err)
	}

	router := mux.NewRouter()

	router.HandleFunc("/allgroups",state.GetAllGroups ).Methods("GET")
	router.HandleFunc("/allusers", state.GetAllUsers).Methods("GET")
	router.HandleFunc("/create_group",state.CreateGroup ).Methods("POST")
    router.HandleFunc("/user_groups/{username}",state.GetUserAllGroups).Methods("GET")
    router.HandleFunc("/group_users/{groupname}",state.GetUsersinGroup).Methods("GET")

    router.HandleFunc("/Delete_group",state.DeleteGroup ).Methods("DELETE")
	log.Fatal(http.ListenAndServe(":11000", router))

}
