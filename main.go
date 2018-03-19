package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"gopkg.in/ldap.v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
	"html/template"
	"github.com/Symantec/keymaster/lib/authutil"
	"github.com/cviecco/go-simple-oidc-auth/authhandler"
	"net/http"
	"encoding/json"
	"sort"
	"fmt"
)



type baseConfig struct {
	HttpAddress           string `yaml:"http_address"`
	TLSCertFilename       string `yaml:"tls_cert_filename"`
	TLSKeyFilename        string `yaml:"tls_key_filename"`
	StorageURL            string `yaml:"storage_url"`
	OpenIDCConfigFilename string `yaml:"openidc_config_filename"`
}

type UserInfoLDAPSource struct {
	BindUsername       string `yaml:"bind_username"`
	BindPassword       string `yaml:"bind_password"`
	LDAPTargetURLs     string `yaml:"ldap_target_urls"`
	UserSearchBaseDNs  string `yaml:"user_search_base_dns"`
	UserSearchFilter   string `yaml:"user_search_filter"`
	GroupSearchBaseDNs string `yaml:"group_search_base_dns"`
	GroupSearchFilter  string `yaml:"group_search_filter"`
}

type AppConfigFile struct {
	Base       baseConfig         `yaml:"base"`
	SourceLDAP UserInfoLDAPSource `yaml:"source_config"`
	TargetLDAP UserInfoLDAPSource `yaml:"target_config"`
}


type RuntimeState struct {
	Config      AppConfigFile
	source_ldap *ldap.Conn
	target_ldap *ldap.Conn
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

type Response struct{
	UserName string
	Groups []string
	Users []string
}


const ldapTimeoutSecs = 10

//maximum possible paging size number
const maximum_pagingsize = 2147483647


var nsaccount_lock = []string{"True"}

var (
	configFilename = flag.String("config", "config.yml", "The filename of the configuration")
	tpl *template.Template
	//debug          = flag.Bool("debug", false, "enable debugging output")
	authSource     *authhandler.SimpleOIDCAuth
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
	return state, err
}



//Establishing connection
func GetLDAPConnection(u url.URL, timeoutSecs uint, rootCAs *x509.CertPool) (*ldap.Conn, string, error) {

	if u.Scheme != "ldaps" {
		err := errors.New("Invalid ldap scheme (we only support ldaps)")
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

	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", hostnamePort, &tls.Config{ServerName: server, RootCAs: rootCAs, InsecureSkipVerify: true})

	if err != nil {
		log.Printf("rooCAs=%+v,  serverName=%s, hostnameport=%s, tlsConn=%+v", rootCAs, server, hostnamePort, tlsConn)
		errorTime := time.Since(start).Seconds() * 1000
		log.Printf("connection failure for:%s (%s)(time(ms)=%v)", server, err.Error(), errorTime)
		return nil, "", err
	}

	// we dont close the tls connection directly  close defer to the new ldap connection
	conn := ldap.NewConn(tlsConn, true)
	return conn, server, nil
}



//Function which returns the array of disabled accounts from Source LDAP.
func (state *RuntimeState) DisabledAccountsinSourceLDAP(UserSearchBaseDNs string, UserSearchFilter string, Attributes []string) ([]string, error) {
	var disabled_accounts []string

	searchrequest := ldap.NewSearchRequest(UserSearchBaseDNs, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, UserSearchFilter, Attributes, nil)

	result, err := state.source_ldap.SearchWithPaging(searchrequest, maximum_pagingsize)
	if err != nil {
		return nil, err
	}
	if len(result.Entries) == 0 {
		log.Println("No records found")
	}
	for _, entry := range result.Entries {
		cname := entry.GetAttributeValue("sAMAccountName")
		disabled_accounts = append(disabled_accounts, strings.ToLower(cname))
	}
	return disabled_accounts, nil
}



//function which compares the users disabled accounts in Source LDAP and Target LDAP and adds the attribute nsaccountLock in TARGET LDAP for the disbaled USer.
func (state *RuntimeState) CompareDisabledaccounts(userdn string, result []string) error {
	for _, entry := range result {
		entry = Create_UserDN(userdn, entry)

		modify := ldap.NewModifyRequest(entry)
		modify.Replace("nsaccountLock", nsaccount_lock)
		err := state.target_ldap.Modify(modify)
		if err != nil {
			return err
		}
	}
	return nil

}



//Get all ldap users and put that in map
func (state *RuntimeState) GetallUsers(UserSearchBaseDNs string, UserSearchFilter string, Attributes []string) (map[string]string, error) {
	AllUsersinLdap := make(map[string]string)

	searchrequest := ldap.NewSearchRequest(UserSearchBaseDNs, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, UserSearchFilter, Attributes, nil)
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



//find out which accounts need to be locked in Target ldap(i.e. which accounts needs attribute nsaccountLock=True)
func FindLockAccountsinTargetLdap(TargetLDAP_Users map[string]string, LockedAccounts_SourceLDAP []string) ([]string, error) {
	var lock_accounts []string
	for _, entry := range LockedAccounts_SourceLDAP {
		if entry, ok := TargetLDAP_Users[entry]; ok {

			lock_accounts = append(lock_accounts, entry)
		}

	}
	return lock_accounts, nil
}



//To build a user base DN using uid only for Target LDAP.
func Create_UserDN(usersdn string, username string) string {
	//uid := username
	result := "uid=" + username + "," + usersdn

	return string(result)

}



//To build a GroupDN for a particular group in Target ldap
func Create_GroupDN(groupdn string, groupname string) string {
	result := "cn=" + groupname + "," + groupdn

	return string(result)

}



//function to get details of a user from Target ldap.(should make some changes)
func (state *RuntimeState) UserInfo(User_dn string) ([]string, error) {
	var user_info []string
	searchrequest := ldap.NewSearchRequest(User_dn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "((objectClass=*))", nil, nil)
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



//function to get all the groups in Target ldap and put it in array
func (state *RuntimeState) Get_allGroups(Group_dn string) ([]string, error) {
	var All_Groups []string
	searchrequest := ldap.NewSearchRequest(Group_dn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(&(objectClass=posixGroup)(objectClass=groupofNames)(objectClass=top))", []string{"cn"}, nil)
	result, err := state.target_ldap.Search(searchrequest)
	if err != nil {
		return nil, err
	}
	for _, entry := range result.Entries {
		All_Groups = append(All_Groups, entry.GetAttributeValue("cn"))
	}
	return All_Groups, nil
}



// GetGroupsOfUser returns the all groups of a user.
func (state *RuntimeState) GetGroupsOfUser(groupdn string, username string) ([]string, error) {
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



//returns all the users of a group
func (state *RuntimeState) GetUsersofaGroup(groupdn string, groupname string) ([][]string, error) {
	Base := Create_GroupDN(groupdn, groupname)

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




// parse HTML templates and pass in a list of file names, and get a template

func parseTemplateFiles(filenames ...string) (t *template.Template) {
	var files []string
	t = template.New("index")
	for _, file := range filenames {
		files = append(files, fmt.Sprintf("templates/%s.html", file))
	}
	t = template.Must(t.ParseFiles(files...))
	return
}



func generateHTML(writer http.ResponseWriter, data interface{}, filenames ...string) {
	var files []string
	for _, file := range filenames {
		files = append(files, fmt.Sprintf("templates/%s.html", file))
	}

	templates := template.Must(template.ParseFiles(files...))
	templates.ExecuteTemplate(writer, "index", data)
}



//All handlers and API endpoints starts from here.

//Display all groups in Target LDAP
func (state *RuntimeState) GetallGroups_Handler(w http.ResponseWriter, r *http.Request) {
	var AllGroups_TargetLdap GetGroups

	Allgroups, err := state.Get_allGroups(state.Config.TargetLDAP.GroupSearchBaseDNs)

	if err != nil {
		log.Panic(err)
	}
	sort.Strings(Allgroups)
	AllGroups_TargetLdap.AllGroups = Allgroups
	json.NewEncoder(w).Encode(AllGroups_TargetLdap)

}




//Display all users in Target LDAP
func (state *RuntimeState) GetallUsers_Handler(w http.ResponseWriter, r *http.Request) {
	var AllUsers_TargetLdap GetUsers

	AllUsers, err := state.GetallUsers(state.Config.TargetLDAP.UserSearchBaseDNs, state.Config.TargetLDAP.UserSearchFilter, []string{"uid"})

	if err != nil {
		log.Println(err)
	}

	for k := range AllUsers {
		AllUsers_TargetLdap.Users = append(AllUsers_TargetLdap.Users, k)
	}

	json.NewEncoder(w).Encode(AllUsers_TargetLdap)
}




//Displays all Groups of a User.
func (state *RuntimeState) GetGroupsofUser_Handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params, ok := q["username"]
	if ok {

		var user_groups GetUserGroups

		user_groups.UserName = params[0] //username is "cn" Attribute of a User
		UsersAllgroups, err := state.GetGroupsOfUser(state.Config.TargetLDAP.GroupSearchBaseDNs, user_groups.UserName)
		sort.Strings(UsersAllgroups)
		user_groups.UserGroups = UsersAllgroups

		if err != nil {
			log.Println(err)
		}

		json.NewEncoder(w).Encode(user_groups)
	}
	http.NotFoundHandler()
}




//Displays All Users in a Group
func (state *RuntimeState) GetUsersinGroup_Handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params, ok := q["groupname"]
	if ok {
		var group_users GetGroupUsers

		group_users.GroupName = params[0] //username is "cn" Attribute of a User
		AllUsersinGroup, err := state.GetUsersofaGroup(state.Config.TargetLDAP.GroupSearchBaseDNs, group_users.GroupName)
		sort.Strings(AllUsersinGroup[0])
		group_users.Groupusers = AllUsersinGroup[0]

		if err != nil {
			log.Println(err)
		}

		json.NewEncoder(w).Encode(group_users)
	}
	http.NotFoundHandler()
}




func (state *RuntimeState) CreateGroup(w http.ResponseWriter, r *http.Request) {

}


func (state *RuntimeState) DeleteGroup(w http.ResponseWriter, r *http.Request) {

}



//Main page with all LDAP groups displayed
func  (state *RuntimeState) Index_Handler(w http.ResponseWriter, r *http.Request){

	Allgroups,err:= state.Get_allGroups(state.Config.TargetLDAP.GroupSearchBaseDNs)

	if err != nil {
		log.Panic(err)
	}
	sort.Strings(Allgroups)

	//response.UserName=*userInfo.Username
	response:=Response{"",Allgroups,nil}
	fmt.Println(response.Groups)

	generateHTML(w,response,"index","sidebar","groups")
	//tpl=parseTemplateFiles("index","sidebar","groups")


	//tpl.Execute(w,response)
}

//Group page.
func (state *RuntimeState) Group_Handler(w http.ResponseWriter, r *http.Request){
	vals := r.URL.Query()

	generateHTML(w,vals.Get("groupname"),"index","sidebar","group_info")

}

//User Groups page
func (state *RuntimeState) MyGroups_Handler(w http.ResponseWriter,r *http.Request){
	vals := r.URL.Query()
	user_groups,err:=state.GetGroupsOfUser(state.Config.TargetLDAP.GroupSearchBaseDNs,vals.Get("username"))
	if(err!=nil){
		log.Println(err)
	}
	sort.Strings(user_groups)
	response:=Response{vals.Get("username"),user_groups,nil}
	generateHTML(w,response,"index","sidebar","my_groups")

}

//User's Pending Actions
func (state *RuntimeState) Pending_Actions(w http.ResponseWriter,r *http.Request){

}

func (state *RuntimeState) userinfo_handler(w http.ResponseWriter, r *http.Request) {
	userInfo, err := authhandler.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	fmt.Fprintf(w, "Hi there, %s loves %s!", *userInfo.Username, r.URL.Path[1:])
}



func main() {
	flag.Parse()

	state, err := loadConfig(*configFilename)
	if err != nil {
		panic(err)
	}
	var openidConfigFilename = state.Config.Base.OpenIDCConfigFilename //"/etc/openidc_config_keymaster.yml"

	// if you alresy use the context:
	simpleOidcAuth, err := authhandler.NewSimpleOIDCAuthFromConfig(&openidConfigFilename, nil)
	if err != nil {
		panic(err)
	}
	authSource = simpleOidcAuth


	//Parsing Source LDAP URL, establishing connection and binding user.
	Source_LdapUrl, err := authutil.ParseLDAPURL(state.Config.SourceLDAP.LDAPTargetURLs)

	state.source_ldap, _, err = GetLDAPConnection(*Source_LdapUrl, ldapTimeoutSecs, nil)
	if err != nil {
		panic(err)
	}

	timeout := time.Duration(time.Duration(ldapTimeoutSecs) * time.Second)
	state.source_ldap.SetTimeout(timeout)
	state.source_ldap.Start()

	err = state.source_ldap.Bind(state.Config.SourceLDAP.BindUsername, state.Config.SourceLDAP.BindPassword)

	if err != nil {
		panic(err)
	}

	//Parsing Target LDAP, establishing connection and binding user.
	Target_LdapUrl, err := authutil.ParseLDAPURL(state.Config.TargetLDAP.LDAPTargetURLs)

	state.target_ldap, _, err = GetLDAPConnection(*Target_LdapUrl, ldapTimeoutSecs, nil)
	if err != nil {
		panic(err)
	}
	state.target_ldap.SetTimeout(timeout)
	state.target_ldap.Start()

	err = state.target_ldap.Bind(state.Config.TargetLDAP.BindUsername, state.Config.TargetLDAP.BindPassword)

	if err != nil {
		panic(err)
	}

	router := http.NewServeMux()

	router.HandleFunc("/allgroups", state.GetallGroups_Handler)
	router.HandleFunc("/allusers", state.GetallUsers_Handler)
	router.HandleFunc("/create_group", state.CreateGroup)
	router.HandleFunc("/user_groups/", state.GetGroupsofUser_Handler)
	router.HandleFunc("/group_users/", state.GetUsersinGroup_Handler)
	router.HandleFunc("/Delete_group", state.DeleteGroup)

	router.Handle("/index.html", simpleOidcAuth.Handler(http.HandlerFunc(state.Index_Handler)))
	router.HandleFunc("/group/",state.Group_Handler)
	router.HandleFunc("/mygroups/",state.MyGroups_Handler)
	router.HandleFunc("/pending-actions/",state.Pending_Actions)
	fs:=http.FileServer(http.Dir("templates"))
	router.Handle("/css/",fs)
	router.Handle("/js/",fs)
	router.Handle("/images/",fs)
	log.Fatal(http.ListenAndServeTLS(":11000", state.Config.Base.TLSCertFilename, state.Config.Base.TLSKeyFilename, router))
}