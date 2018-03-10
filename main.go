package ldap_group_management

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
	"github.com/Symantec/keymaster/lib/authutil"
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
	//htmlTemplate *template.Template
}

const ldapTimeoutSecs = 3


var Attributes = []string{"sAMAccountName"}


const pagingsize =2147483647


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
func getLDAPConnection1(u url.URL) (*ldap.Conn, string, error) {

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
func disabledaccounts(conn *ldap.Conn, UserSearchBaseDNs string, UserSearchFilter string, Attributes []string)([]string,error){
	var final []string

	searchrequest := ldap.NewSearchRequest(UserSearchBaseDNs,ldap.ScopeWholeSubtree,ldap.NeverDerefAliases, 0,0,false,UserSearchFilter,Attributes,nil)

	result, err:= conn.SearchWithPaging(searchrequest,pagingsize)
	if err !=nil{
		return nil,err
	}
	if len(result.Entries)==0{
		log.Println("No records found")
	}
	for _,entry := range result.Entries{
		cname := entry.GetAttributeValue("sAMAccountName")
		final=append(final,strings.ToLower(cname))
	}
	return final,nil
}



//function which compares the users disabled accounts in AD with CPE LDAP and adds the attribute nsaccountLock in CPE ldap for the disbaled USer.
func disableinCPELDAP(conn *ldap.Conn,userdn string,result []string)(error){
	for _,entry:=range result{
		entry=userDN(userdn,entry)

		modify := ldap.NewModifyRequest(entry)
		modify.Replace("nsaccountLock",[]string{"True"})
		err:=conn.Modify(modify)
		if err !=nil{
			return err
		}
	}
	return nil

}




//Get all ldap users and put that in map
func getallusers(conn *ldap.Conn, UserSearchBaseDNs string, UserSearchFilter string, hello []string) (map[string]string,error){
	final := make(map[string]string)

	searchrequest := ldap.NewSearchRequest(UserSearchBaseDNs,ldap.ScopeWholeSubtree,ldap.NeverDerefAliases, 0,0,false,UserSearchFilter,hello,nil)
	result, err := conn.Search(searchrequest)
	if err !=nil{
		return nil,err
	}
	fmt.Println(len(result.Entries))
	if len(result.Entries)==0{
		log.Println("No records found")
	}
	//fmt.Printf("%+v",result.Entries)
	//fmt.Println(result.Entries[0].GetAttributeValue("uid"))
	for _,entry := range result.Entries{
		//if entry.GetAttributeValue("uid")
		uid := entry.GetAttributeValue("uid")
		final[uid]=uid


	}
	fmt.Println(final)
	return final,nil
}


//find out which accounts need to be locked in cpe ldap(i.e. which accounts needs attribute nsaccountLock=True
func LockAccountsinCPELdap(finalLdap map[string]string,finalAD []string ) ([]string,error){
	var result []string
	for _,entry:=range finalAD{
		if entry, ok := finalLdap[entry]; ok{

			result=append(result,entry)
		}

	}
	return result,nil
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
func userinfo(conn *ldap.Conn,userdn string)([]string,error) {
	var final []string
	searchrequest := ldap.NewSearchRequest(userdn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "((objectClass=*))", nil, nil)
	result, err := conn.Search(searchrequest)
	if err != nil {
		return nil, err
	}
	for _, entry := range result.Entries {
		final = entry.GetAttributeValues("objectClass")
		//println(entry.GetAttributeValue(entry.Attributes[5].Name))
	}
	return final, nil
}

//function to get all the groups in cpe ldap and put it in array
func getallGroupsinCPELdap(conn *ldap.Conn,groupdn string)([]string,error){
	var final []string
	searchrequest := ldap.NewSearchRequest(groupdn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(&(objectClass=posixGroup)(objectClass=groupofNames)(objectClass=top))", nil, nil)
	result, err := conn.Search(searchrequest)
	if err !=nil{
		return nil,err
	}
	for _,entry:=range result.Entries{
		final=append(final,entry.GetAttributeValue("cn"))
	}
	return final,nil
}


// GetGroupsOfUser returns the all groups of a user.
func GetGroupsOfUser(conn *ldap.Conn,groupdn string,username string) ([]string, error) {
	//Base:=userDN(username)
	Base:=groupdn
	searchRequest := ldap.NewSearchRequest(
		Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(memberUid="+username+" ))",
		[]string{"cn"},//memberOf (if searching other way around using usersdn instead of groupdn)
		nil,
	)
	sr, err := conn.Search(searchRequest)
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
func GetUsersofaGroup(conn *ldap.Conn,groupdn string,groupname string) ([][]string, error) {
	Base:=GroupDN(groupdn,groupname)

	searchRequest := ldap.NewSearchRequest(
		Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"((objectClass=*))",
		[]string{"memberUid"},
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	users := [][]string{}
	for _, entry := range sr.Entries {
		users = append(users, entry.GetAttributeValues("memberUid"))
	}
	return users, nil
}





func main() {
	flag.Parse()

	state, err := loadConfig(*configFilename)
	if err != nil {
		panic(err)
	}

	//Parsing AD URL, establishing connection and binding user.
	ldapADurl,err:= authutil.ParseLDAPURL(state.Config.TargetLDAP.LDAPTargetURLs)

	//conn,_,err:= getLDAPConnection(*ldapurl,ldapTimeoutSecs,nil)
	conn,_,err:=getLDAPConnection1(*ldapADurl)
	if err != nil {
		panic(err)
	}

	err=conn.Bind(state.Config.TargetLDAP.BindUsername,state.Config.TargetLDAP.BindPassword)

	if err!=nil{
		panic(err)
	}


	//Parsing CPE LDAP, establishing connection and binding user.
	cpeldapurl,err:= authutil.ParseLDAPURL(state.Config.SourceLDAP.LDAPTargetURLs)


	//conn,_,err:= getLDAPConnection(*ldapurl,ldapTimeoutSecs,nil)
	cpeconn,_,err:=getLDAPConnection1(*cpeldapurl)
	if err != nil {
		panic(err)
	}

	err=cpeconn.Bind(state.Config.SourceLDAP.BindUsername,state.Config.SourceLDAP.BindPassword)
	if err!=nil{
		panic(err)
	}


	//result will have all the disabled accounts in AD
	result,err:=disabledaccounts(conn,state.Config.TargetLDAP.UserSearchBaseDNs,state.Config.TargetLDAP.UserSearchFilter,Attributes)

	if err != nil{
		panic(err)
	}

	//result1 will have all the users in cpe ldap
	result1,err:=getallusers(cpeconn,state.Config.SourceLDAP.UserSearchBaseDNs,state.Config.SourceLDAP.UserSearchFilter,[]string{"uid"})

	if err != nil{
		panic(err)
	}


	//finalresult will have all the accounts that needed to be locked in cpe ldap
	finalresult,err:=LockAccountsinCPELdap(result1,result)

	if err != nil{
		panic(err)
	}

	userinfo1:=userDN(state.Config.SourceLDAP.UserSearchBaseDNs,"username") //username as per in LDAP
	fmt.Println(userinfo1)
	userinfo2,err:=userinfo(cpeconn,userinfo1)

	usergroups,err:=GetGroupsOfUser(cpeconn,state.Config.SourceLDAP.GroupSearchBaseDNs,"username") //username as per in LDAP


	if err != nil{
		panic(err)
	}

	//fmt.Println(groupinfo)

	groupinfo,err:=GetUsersofaGroup(cpeconn,state.Config.SourceLDAP.GroupSearchBaseDNs,"groupname",)//groupname as per in ldap
	if err != nil{
		panic(err)
	}


	fmt.Println(groupinfo)
	fmt.Println(userinfo2)

	fmt.Println(usergroups)

	//fmt.Println(result1)
	//fmt.Println(len(result1))
	//for item := range finalresult{
	//	fmt.Println(finalresult[item])
	//}

	//disables all the users in finalresult(i.e, adds accountLock attritube to them)
	err=disableinCPELDAP(cpeconn,state.Config.SourceLDAP.UserSearchBaseDNs,finalresult)
	if err!=nil{
		panic(err)
	}
	fmt.Println(finalresult)
	fmt.Println(len(finalresult))

	str,err:=getallGroupsinCPELdap(cpeconn,state.Config.SourceLDAP.GroupSearchBaseDNs)

	if err!=nil{
		panic(err)
	}
	fmt.Println(str)
	fmt.Println(len(str))



	//fmt.Println(result[0])
	//fmt.Println(result[1])
	//fmt.Println(result)
}
