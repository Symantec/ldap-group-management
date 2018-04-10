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
	"github.com/Symantec/keymaster/lib/authutil"
	"github.com/cviecco/go-simple-oidc-auth/authhandler"
	"net/http"
	"database/sql"
	_"github.com/mattn/go-sqlite3"
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
	Admins 			   string `yaml:"super_admins"`
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
	dbType string
	db *sql.DB
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
	Pending_actions [][]string
}


type group_info struct {
	groupname string
	description string
	memberUid []string
	member []string
	cn string
}

const ldapTimeoutSecs = 10

//maximum possible paging size number
const maximum_pagingsize = 2147483647


var nsaccount_lock = []string{"True"}

var (
	configFilename = flag.String("config", "config.yml", "The filename of the configuration")
	//tpl *template.Template
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
	err = initDB(&state)
	if err != nil {
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

	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp",
	hostnamePort, &tls.Config{ServerName: server, RootCAs: rootCAs})

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




type mailAttributes struct {
	RequestedUser  string
	OtherUser      string
	Groupname      string
	RemoteAddr     string
	Browser        string
	OS             string
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

	http.HandleFunc("/allgroups", state.GetallgroupsHandler)
	http.HandleFunc("/allusers", state.GetallusersHandler)
	http.HandleFunc("/user_groups/", state.GetgroupsofuserHandler)
	http.HandleFunc("/group_users/", state.GetusersingroupHandler)


	http.Handle("/create_group", simpleOidcAuth.Handler(http.HandlerFunc(state.creategroupWebpageHandler)))
	http.Handle("/delete_group", simpleOidcAuth.Handler(http.HandlerFunc(state.deletegroupWebpageHandler)))
	http.Handle("/create_group/",simpleOidcAuth.Handler(http.HandlerFunc(state.createGrouphandler)))
	http.Handle("/delete_group/",simpleOidcAuth.Handler(http.HandlerFunc(state.deleteGrouphandler)))

	http.Handle("/requestaccess",simpleOidcAuth.Handler(http.HandlerFunc(state.requestAccessHandler)))
	http.Handle("/index.html", simpleOidcAuth.Handler(http.HandlerFunc(state.IndexHandler)))
	http.Handle("/group/",simpleOidcAuth.Handler(http.HandlerFunc(state.GroupHandler)))
	http.Handle("/mygroups/",simpleOidcAuth.Handler(http.HandlerFunc(state.MygroupsHandler)))
	http.Handle("/pending-actions",simpleOidcAuth.Handler(http.HandlerFunc(state.pendingActions)))
	http.Handle("/pending-requests",simpleOidcAuth.Handler(http.HandlerFunc(state.pendingRequests)))
	http.Handle("/deleterequests",simpleOidcAuth.Handler(http.HandlerFunc(state.deleteRequests)))
	http.Handle("/exitgroup",simpleOidcAuth.Handler(http.HandlerFunc(state.exitfromGroup)))

	http.Handle("/approve-request",simpleOidcAuth.Handler(http.HandlerFunc(state.approveHandler)))
	http.Handle("/reject-request",simpleOidcAuth.Handler(http.HandlerFunc(state.rejectHandler)))

	http.HandleFunc("/addmembers",state.Addmemberswebpagehandler)
	http.HandleFunc("/addmembers/",state.AddmemberstoGroup)

	fs:=http.FileServer(http.Dir("templates"))
	http.Handle("/css/",fs)
	http.Handle("/js/",fs)
	http.Handle("/images/",fs)
	http.Handle("/fonts/",fs)
	log.Fatal(http.ListenAndServeTLS(state.Config.Base.HttpAddress,state.Config.Base.TLSCertFilename,state.Config.Base.TLSKeyFilename, nil))
}

