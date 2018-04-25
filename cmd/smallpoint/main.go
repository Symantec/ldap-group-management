package main

import (
	"database/sql"
	"errors"
	"flag"
	"github.com/cviecco/go-simple-oidc-auth/authhandler"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/ldap.v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	. "github.com/Symantec/ldap-group-management/lib/ldaputil"
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
	Base       baseConfig         `yaml:"base"`
	SourceLDAP UserInfoLDAPSource `yaml:"source_config"`
	TargetLDAP UserInfoLDAPSource `yaml:"target_config"`
}

type RuntimeState struct {
	Config     AppConfigFile
	targetLdap *ldap.Conn
	dbType     string
	db         *sql.DB
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


	http.Handle("/allgroups", simpleOidcAuth.Handler(http.HandlerFunc(state.GetallgroupsHandler)))
	http.Handle("/allusers", simpleOidcAuth.Handler(http.HandlerFunc(state.GetallusersHandler)))
	http.Handle("/user_groups/", simpleOidcAuth.Handler(http.HandlerFunc(state.GetgroupsofuserHandler)))
	http.Handle("/group_users/", simpleOidcAuth.Handler(http.HandlerFunc(state.GetusersingroupHandler)))

	http.Handle("/create_group", simpleOidcAuth.Handler(http.HandlerFunc(state.creategroupWebpageHandler)))
	http.Handle("/delete_group", simpleOidcAuth.Handler(http.HandlerFunc(state.deletegroupWebpageHandler)))
	http.Handle("/create_group/", simpleOidcAuth.Handler(http.HandlerFunc(state.createGrouphandler)))
	http.Handle("/delete_group/", simpleOidcAuth.Handler(http.HandlerFunc(state.deleteGrouphandler)))

	http.Handle("/requestaccess", simpleOidcAuth.Handler(http.HandlerFunc(state.requestAccessHandler)))
	http.Handle("/", simpleOidcAuth.Handler(http.HandlerFunc(state.IndexHandler)))
	http.Handle("/mygroups/", simpleOidcAuth.Handler(http.HandlerFunc(state.MygroupsHandler)))
	http.Handle("/pending-actions", simpleOidcAuth.Handler(http.HandlerFunc(state.pendingActions)))
	http.Handle("/pending-requests", simpleOidcAuth.Handler(http.HandlerFunc(state.pendingRequests)))
	http.Handle("/deleterequests", simpleOidcAuth.Handler(http.HandlerFunc(state.deleteRequests)))
	http.Handle("/exitgroup", simpleOidcAuth.Handler(http.HandlerFunc(state.exitfromGroup)))

	http.Handle("/approve-request", simpleOidcAuth.Handler(http.HandlerFunc(state.approveHandler)))
	http.Handle("/reject-request", simpleOidcAuth.Handler(http.HandlerFunc(state.rejectHandler)))

	http.Handle("/addmembers/", simpleOidcAuth.Handler(http.HandlerFunc(state.AddmemberstoGroup)))

	fs := http.FileServer(http.Dir("templates"))
	http.Handle("/css/", fs)
	http.Handle("/images/", fs)
	log.Fatal(http.ListenAndServeTLS(state.Config.Base.HttpAddress, state.Config.Base.TLSCertFilename, state.Config.Base.TLSKeyFilename, nil))
}
