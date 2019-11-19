package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"github.com/Symantec/keymaster/lib/instrumentedwriter"
	"github.com/Symantec/ldap-group-management/lib/userinfo"
	"github.com/Symantec/ldap-group-management/lib/userinfo/ldapuserinfo"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
	"html/template"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Symantec/ldap-group-management/lib/authn"
)

type baseConfig struct {
	HttpAddress                 string `yaml:"http_address"`
	TLSCertFilename             string `yaml:"tls_cert_filename"`
	TLSKeyFilename              string `yaml:"tls_key_filename"`
	StorageURL                  string `yaml:"storage_url"`
	TemplatesPath               string `yaml:"templates_path"`
	SMTPserver                  string `yaml:"smtp_server"`
	SmtpSenderAddress           string `yaml:"smtp_sender_address"`
	ClientCAFilename            string `yaml:"client_ca_filename"`
	LogDirectory                string `yaml:"log_directory"`
	ClusterSharedSecretFilename string `yaml:"cluster_shared_secret_filename"`
	SharedSecrets               []string
	Hostname                    string   `yaml:"hostname"`
	AutoGroups                  []string `yaml:"auto_add_to_groups"`
}

type AppConfigFile struct {
	Base       baseConfig                      `yaml:"base"`
	OpenID     authn.OpenIDConfig              `yaml:"openid"`
	SourceLDAP ldapuserinfo.UserInfoLDAPSource `yaml:"source_config"`
	TargetLDAP ldapuserinfo.UserInfoLDAPSource `yaml:"target_config"`
}

type pendingUserActionsCacheEntry struct {
	Expiration time.Time
	Groups     [][]string
}

type RuntimeState struct {
	Config         AppConfigFile
	dbType         string
	db             *sql.DB
	Userinfo       userinfo.UserInfo
	UserSourceinfo userinfo.UserInfo
	htmlTemplate   *template.Template
	sysLog         *syslog.Writer
	authenticator  *authn.Authenticator

	allUsersRWLock               sync.RWMutex
	allUsersCacheValue           map[string]time.Time
	pendingUserActionsCacheMutex sync.Mutex
	pendingUserActionsCache      map[string]pendingUserActionsCacheEntry
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
	UserName            string
	Groups              [][]string
	Users               []string
	PendingActions      [][]string
	GroupName           string
	GroupManagedbyValue string
	GroupUsers          []string
}

type httpLogger struct {
	AccessLogger *log.Logger
}

var (
	Version        = "No version provided"
	configFilename = flag.String("config", "/etc/smallpoint/config.yml", "The filename of the configuration")
)

const (
	metricsPath                 = "/metrics"
	cacheRefreshDuration        = 6 * time.Hour
	descriptionAttribute        = "self-managed"
	cookieExpirationHours       = 12
	cookieName                  = "smallpointauth"
	creategroupWebPagePath      = "/create_group"
	deletegroupWebPagePath      = "/delete_group"
	creategroupPath             = "/create_group/"
	deletegroupPath             = "/delete_group/"
	requestaccessPath           = "/requestaccess"
	allLDAPgroupsPath           = "/allGroups"
	pendingactionsPath          = "/pending-actions"
	pendingrequestsPath         = "/pending-requests"
	deleterequestsPath          = "/deleterequests"
	exitgroupPath               = "/exitgroup"
	loginPath                   = "/login"
	approverequestPath          = "/approve-request"
	rejectrequestPath           = "/reject-request"
	addmembersbuttonPath        = "/addmembers/"
	addmembersPath              = "/addmembers"
	deletemembersPath           = "/deletemembers"
	deletemembersbuttonPath     = "/deletemembers/"
	createServiceAccWebPagePath = "/create_serviceaccount"
	createServiceAccountPath    = "/create_serviceaccount/"
	groupinfoPath               = "/group_info/"
	changeownershipbuttonPath   = "/change_owner/"
	changeownershipPath         = "/change_owner"
	myManagedGroupsWebPagePath  = "/my_managed_groups"
	permissionmanageWebPagePath = "/permissionmanage"
	permissionmanagePath        = "/permissionmanage/"

	getGroupsJSPath = "/getGroups.js"
	getUsersJSPath  = "/getUsers.js"

	indexPath  = "/"
	authPath   = "/auth/oidcsimple/callback"
	cssPath    = "/css/"
	imagesPath = "/images/"
	jsPath     = "/js/"
)

func (l httpLogger) Log(record instrumentedwriter.LogRecord) {
	if l.AccessLogger != nil {
		l.AccessLogger.Printf("%s -  %s [%s] \"%s %s %s\" %d %d \"%s\"\n",
			record.Ip, record.Username, record.Time, record.Method,
			record.Uri, record.Protocol, record.Status, record.Size, record.UserAgent)
	}
}

func (state *RuntimeState) loadTemplates() (err error) {

	state.htmlTemplate = template.New("main")

	//Load extra templates
	templatesPath := state.Config.Base.TemplatesPath
	if _, err = os.Stat(templatesPath); err != nil {
		return err
	}

	//Eventally this will include the customization path
	templateFiles := []string{}
	for _, templateFilename := range templateFiles {
		templatePath := filepath.Join(templatesPath, templateFilename)
		_, err = state.htmlTemplate.ParseFiles(templatePath)
		if err != nil {
			return err
		}
	}

	/// Load the oter built in templates
	extraTemplates := []string{commonCSSText, commonJSText, headerHTMLText,
		footerHTMLText, sidebarHTMLText, myGroupsPageText, allGroupsPageText,
		pendingRequestsPageText, pendingActionsPageText,
		createGroupPageText, deleteGroupPageText,
		simpleMessagePageText, addMembersToGroupPageText, groupInfoPageText,
		createServiceAccountPageText, changeGroupOwnershipPageText,
		deleteMembersFromGroupPageText, commonHeadText, permManagePageText}
	for _, templateString := range extraTemplates {
		_, err = state.htmlTemplate.Parse(templateString)
		if err != nil {
			return err
		}
	}

	return nil
}

func getClusterSecretsFile(clusterSecretsFilename string) ([]string, error) {
	file, err := os.Open(clusterSecretsFilename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var rarray []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		rarray = append(rarray, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rarray) < 1 {
		return nil, errors.New("empty cluster secretFile")
	}
	return rarray, nil
}

//parses initializes from the config file
func loadConfig(configFilename string) (RuntimeState, error) {

	var state RuntimeState

	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = fmt.Errorf("mising config file failure. Filename=%s", configFilename)
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

	//Load extra templates
	err = state.loadTemplates()
	if err != nil {
		return state, err
	}

	err = initDB(&state)
	if err != nil {
		return state, err
	}

	state.Userinfo = &state.Config.TargetLDAP
	state.allUsersCacheValue = make(map[string]time.Time)
	state.pendingUserActionsCache = make(map[string]pendingUserActionsCacheEntry)
	state.UserSourceinfo = &state.Config.SourceLDAP

	if len(state.Config.Base.ClusterSharedSecretFilename) > 1 {
		state.Config.Base.SharedSecrets, err = getClusterSecretsFile(state.Config.Base.ClusterSharedSecretFilename)
		if err != nil {
			return state, err
		}
	}
	//
	state.authenticator = authn.NewAuthenticator(state.Config.OpenID, "smallpoint", nil,
		state.Config.Base.SharedSecrets, nil,
		nil)

	for _, group := range state.Config.Base.AutoGroups {
		GroupExistsornot, _, err := state.Userinfo.GroupnameExistsornot(group)
		if err != nil {
			return state, err
		}
		if !GroupExistsornot {
			err = errors.New("Group " + group + " doesn't exist in CPE LDAP")
			return state, err
		}
	}
	return state, err
}

type mailAttributes struct {
	RequestedUser string
	OtherUser     string
	Groupname     string
	Browser       string
	OS            string
	Hostname      string
}

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
	flag.PrintDefaults()
}

func main() {
	flag.Usage = Usage
	flag.Parse()

	state, err := loadConfig(*configFilename)
	if err != nil {
		panic(err)
	}

	//start to log
	state.sysLog, err = syslog.New(syslog.LOG_NOTICE|syslog.LOG_AUTHPRIV, "smallpoint")
	if err != nil {
		log.Fatalf("System log failed")
	}
	defer state.sysLog.Close()

	http.Handle(metricsPath, promhttp.Handler())

	http.HandleFunc(authn.Oauth2redirectPath, state.authenticator.Oauth2RedirectPathHandler)

	http.Handle(creategroupWebPagePath, http.HandlerFunc(state.creategroupWebpageHandler))
	http.Handle(deletegroupWebPagePath, http.HandlerFunc(state.deletegroupWebpageHandler))
	http.Handle(creategroupPath, http.HandlerFunc(state.createGrouphandler))
	http.Handle(deletegroupPath, http.HandlerFunc(state.deleteGrouphandler))

	http.Handle(requestaccessPath, http.HandlerFunc(state.requestAccessHandler))
	http.HandleFunc(indexPath, state.defaultPathHandler)
	http.Handle(allLDAPgroupsPath, http.HandlerFunc(state.allGroupsHandler))
	http.Handle(pendingactionsPath, http.HandlerFunc(state.pendingActions))
	http.Handle(pendingrequestsPath, http.HandlerFunc(state.pendingRequests))
	http.Handle(deleterequestsPath, http.HandlerFunc(state.deleteRequests))
	http.Handle(exitgroupPath, http.HandlerFunc(state.exitfromGroup))

	http.Handle(approverequestPath, http.HandlerFunc(state.approveHandler))
	http.Handle(rejectrequestPath, http.HandlerFunc(state.rejectHandler))

	http.Handle(addmembersPath, http.HandlerFunc(state.addmemberstoGroupWebpageHandler))
	http.Handle(addmembersbuttonPath, http.HandlerFunc(state.addmemberstoExistingGroup))

	http.Handle(changeownershipPath, http.HandlerFunc(state.changeownershipWebpageHandler))
	http.Handle(changeownershipbuttonPath, http.HandlerFunc(state.changeownership))

	http.Handle(deletemembersPath, http.HandlerFunc(state.deletemembersfromGroupWebpageHandler))
	http.Handle(deletemembersbuttonPath, http.HandlerFunc(state.deletemembersfromExistingGroup))

	http.Handle(createServiceAccWebPagePath, http.HandlerFunc(state.createserviceAccountPageHandler))
	http.Handle(createServiceAccountPath, http.HandlerFunc(state.createServiceAccounthandler))

	http.Handle(groupinfoPath, http.HandlerFunc(state.groupInfoWebpage))

	http.Handle(getGroupsJSPath, http.HandlerFunc(state.getGroupsJSHandler))
	http.Handle(getUsersJSPath, http.HandlerFunc(state.getUsersJSHandler))

	http.Handle(myManagedGroupsWebPagePath, http.HandlerFunc(state.myManagedGroupsHandler))
	http.Handle(permissionmanageWebPagePath, http.HandlerFunc(state.permissionmanageWebpageHandler))
	http.Handle(permissionmanagePath, http.HandlerFunc(state.permissionManagehandler))

	fs := http.FileServer(http.Dir(state.Config.Base.TemplatesPath))
	http.Handle(cssPath, fs)
	http.Handle(imagesPath, fs)
	http.Handle(jsPath, fs)

	var clientCACertPool *x509.CertPool
	if len(state.Config.Base.ClientCAFilename) > 0 {
		clientCACertPool = x509.NewCertPool()
		caCert, err := ioutil.ReadFile(state.Config.Base.ClientCAFilename)
		if err != nil {
			log.Fatalf("cannot read clientCA file err=%s", err)
		}
		clientCACertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  clientCACertPool,
	}

	l := &lumberjack.Logger{
		Filename:   filepath.Join(state.Config.Base.LogDirectory, "access"),
		MaxSize:    20, // megabytes
		MaxBackups: 3,
		MaxAge:     28,   //days
		Compress:   true, // disabled by default
	}
	accessLogger := httpLogger{AccessLogger: log.New(l, "", 0)}
	serviceServer := &http.Server{
		Addr:         state.Config.Base.HttpAddress,
		Handler:      instrumentedwriter.NewLoggingHandler(http.DefaultServeMux, accessLogger),
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	err = serviceServer.ListenAndServeTLS(state.Config.Base.TLSCertFilename, state.Config.Base.TLSKeyFilename)
	if err != nil {
		log.Fatalf("Failed to start service server, err=%s", err)
	}

}
