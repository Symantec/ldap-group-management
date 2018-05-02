package main

import (
	"database/sql"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
	"gopkg.in/yaml.v2"
	"github.com/cviecco/go-simple-oidc-auth/authhandler"
	"github.com/Symantec/ldap-group-management/lib/userinfo"
	"github.com/Symantec/ldap-group-management/lib/userinfo/ldapuserinfo"
)

type baseConfig struct {
	HttpAddress           string `yaml:"http_address"`
	TLSCertFilename       string `yaml:"tls_cert_filename"`
	TLSKeyFilename        string `yaml:"tls_key_filename"`
	StorageURL            string `yaml:"storage_url"`
	OpenIDCConfigFilename string `yaml:"openidc_config_filename"`
	SMTPserver            string `yaml:"smtp_server"`
	SmtpSenderAddress     string `yaml:"smtp_sender_address"`
}

type AppConfigFile struct {
	Base       baseConfig                      `yaml:"base"`
	SourceLDAP ldapuserinfo.UserInfoLDAPSource `yaml:"source_config"`
	TargetLDAP ldapuserinfo.UserInfoLDAPSource `yaml:"target_config"`
}

type RuntimeState struct {
	Config      AppConfigFile
	dbType      string
	db          *sql.DB
	Userinfo    userinfo.UserInfo
	authcookies map[string]cookieInfo
	cookiemutex       sync.Mutex
}

type cookieInfo struct {
	Username    string
	ExpiresAt   time.Time
}
type GetGroups struct {
	AllGroups []string `json:"allgroups"`
}

type GetUsers struct {
	Users []string `json:"Users"`
}

type GetUserGroups struct {
	UserName   string   `json:"Username"`
	UserGroups []string `json:"usergroups"`
}

type GetGroupUsers struct {
	GroupName  string   `json:"groupname"`
	Groupusers []string `json:"Groupusers"`
}

type Response struct {
	UserName       string
	Groups         []string
	Users          []string
	PendingActions [][]string
}

var (
	configFilename = flag.String("config", "config.yml", "The filename of the configuration")
	//tpl *template.Template
	//debug          = flag.Bool("debug", false, "enable debugging output")
	authSource *authhandler.SimpleOIDCAuth
)


const (
	descriptionAttribute="self-managed"
	cookieExpirationTime  = 12
	cookieName="smallpointauth"

	allgroups="/allgroups"
	allusers="/allusers"
	usergroups="/user_groups/"
	groupusers="/group_users/"
	creategroupWebPage="/create_group"
	deletegroupWebPage="/delete_group"
	creategroup="/create_group/"
	deletegroup="/delete_group/"
	requestaccess="/requestaccess"
	mygroups="/mygroups/"
	pendingactions="/pending-actions"
	pendingrequests="/pending-requests"
	deleterequests="/deleterequests"
	exitgroup="/exitgroup"
	loginpath="/login"
	approverequest="/approve-request"
	rejectrequest="/reject-request"
	addmembers="/addmembers"
	indexpath="/"

	templatesdirectory="templates"
	csspath="/css/"
	images="/images/"

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
	state.Userinfo = &state.Config.TargetLDAP
	state.authcookies=make(map[string]cookieInfo)
	return state, err
}

type mailAttributes struct {
	RequestedUser string
	OtherUser     string
	Groupname     string
	RemoteAddr    string
	Browser       string
	OS            string
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

	http.Handle(allgroups, http.HandlerFunc(state.GetallgroupsHandler))
	http.Handle(allusers, http.HandlerFunc(state.GetallusersHandler))
	http.Handle(usergroups, http.HandlerFunc(state.GetgroupsofuserHandler))
	http.Handle(groupusers, http.HandlerFunc(state.GetusersingroupHandler))

	http.Handle(creategroupWebPage, http.HandlerFunc(state.creategroupWebpageHandler))
	http.Handle(deletegroupWebPage, http.HandlerFunc(state.deletegroupWebpageHandler))
	http.Handle(creategroup, http.HandlerFunc(state.createGrouphandler))
	http.Handle(deletegroup, http.HandlerFunc(state.deleteGrouphandler))

	http.Handle(requestaccess, http.HandlerFunc(state.requestAccessHandler))
	http.Handle(indexpath, http.HandlerFunc(state.IndexHandler))
	http.Handle(mygroups, http.HandlerFunc(state.MygroupsHandler))
	http.Handle(pendingactions, http.HandlerFunc(state.pendingActions))
	http.Handle(pendingrequests, http.HandlerFunc(state.pendingRequests))
	http.Handle(deleterequests, http.HandlerFunc(state.deleteRequests))
	http.Handle(exitgroup, http.HandlerFunc(state.exitfromGroup))

	http.Handle(loginpath, simpleOidcAuth.Handler(http.HandlerFunc(state.LoginHandler)))

	http.Handle(approverequest, http.HandlerFunc(state.approveHandler))
	http.Handle(rejectrequest, http.HandlerFunc(state.rejectHandler))

	http.Handle(addmembers, http.HandlerFunc(state.AddmemberstoGroup))

	fs := http.FileServer(http.Dir(templatesdirectory))
	http.Handle(csspath, fs)
	http.Handle(images, fs)
	log.Fatal(http.ListenAndServeTLS(state.Config.Base.HttpAddress, state.Config.Base.TLSCertFilename, state.Config.Base.TLSKeyFilename, nil))
}
