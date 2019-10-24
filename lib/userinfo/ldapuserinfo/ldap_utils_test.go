package ldapuserinfo

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/Symantec/ldap-group-management/lib/userinfo"

	"github.com/vjeantet/goldap/message"
	ldap "github.com/vjeantet/ldapserver"
)

const rootCAPem = `-----BEGIN CERTIFICATE-----
MIIE1jCCAr4CAQowDQYJKoZIhvcNAQELBQAwMTELMAkGA1UEBhMCVVMxEDAOBgNV
BAoMB1Rlc3RPcmcxEDAOBgNVBAsMB1Rlc3QgQ0EwHhcNMTcwMTA1MTc0NzQ1WhcN
MzYxMjMxMTc0NzQ1WjAxMQswCQYDVQQGEwJVUzEQMA4GA1UECgwHVGVzdE9yZzEQ
MA4GA1UECwwHVGVzdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AK178Hyl2iJ8l4k/iHWgACtkLLa4n6sJo6DB8s1t98ILgU5ykT30jslWPH/QJvfL
/OAvgDcq2+ScwZThGFMxotBKnoufy88wAV/8SAwdy6rbAatW6v6K8+dgPEcka2jf
aqOby27+vrglQePQjjUMZoqr4qAizCUwCGZQUPhfSorBUcyWupKVZe8kDmD395yT
yRf3z5rJAMFzJmNOv/6ZOA2Scv14xZWTezBlr3E2zBCr0iYpYsqh5dG2ube9DYyX
0fXfrfaa8jstlu9jrYltxRmlCBAdoFB1N7eN6V/CsKc9nKc4dFkNDJng1Z4dpPYW
v+HzYI4UBsnkYFtpt5VV3M+Ys/FE1ARE4ah4R69FK+eBKCkpRUszbm/fjnt/QvDX
pCBcpa8vddgAgFKz9kvpO3lfA+jBb2euzX1lOL3ETooE0sEtFPK81P2M62BxsoIa
ztAWOQlLQotDtY156YaUoREXCjLkpiitEhpn9+nlMAPlA9X2iVQWIgpkAepbu+rU
ouODruaOoxc67GyTXUT7NIj3IE3PxPn5LBta+SOJ1DsUcC7aBG/x10/ifYLq/H4J
JxnHhac+S5aKxeCBTzT84JKltbYiqhhoGVaXYp6AwbOkqUMYyhEKelcvtdKc7fKF
+0DRAymVdGzV+nhwxGqwgarlXzZwsWkSj/A0+J7l2Ty9AgMBAAEwDQYJKoZIhvcN
AQELBQADggIBAKsYxpXFY4dyarnvMjAmX6EXcwqDfOJXgQdnX7QMzYlygMb+m2h1
Nuk4HTMlmQtkLba6JQd5NQw42RBYl1ef0PwwJoVlznht7Hec9wEopa5pyzyerSPT
nblh1TRKVffLQ1SyTO6yPgdn8rct5n2M0tW+nW7SZuWkzsc6swVEfJyTykXbMYHg
aSap7oMUr0MaffQjihzwk585fY8GvPeqdrer/k7d6MD05NWkqeXaMitI4hNWTyTu
7yjppKcGRVaNHmhk4867Jz6RZzxWbZBQe7tqaqmdqKLvz8/7j/VFjBTO2NebE0FV
LxKcpv6QklH0UWqzWBn8LDZRYz6D1PglGjgh8ERHOTKJW0BRdIlzljZwND2f5lSx
0HBSJYqTU38iBCHkxf8hYdiPI8Jw2CCt4l+hCwQhtIWgCrENSIa1sT9j3TPy+zwq
2GHf9xTpjV1pVEyuFPf1bllPUeOFXprJiq2J4rnE/fqyabO0uSX35ucdG+YGVyMa
BkwaEPvqvwremmh+xLYye6scQ+A/Wn9fN/8VN0W22t37O2VQNgsTANyIZwKZlxJc
fSkkhF5M7t/rWTtO0MXnCuIDJu3QJneRvOSBlvIabkVGEt9tZQCzK9wiJqsBkLSy
FCdYqoFk7gKsLkv51iMd+oItlEBuSEJSs1N+F5knShYfJdpHYDY+84ul
-----END CERTIFICATE-----`

const localhostCertPem = `-----BEGIN CERTIFICATE-----
MIIDvTCCAaUCBQLd4CbMMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYTAlVTMRAw
DgYDVQQKDAdUZXN0T3JnMRAwDgYDVQQLDAdUZXN0IENBMB4XDTE3MDEwNTE3NTQw
NVoXDTM2MTIzMTE3NTQwNVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3w9PziLdiuYkq4sxVEQkq0HIq6Ad/51o
k98AG87DqbG4hcPcbP/ItEHv4NdYZOtagY5twzb+sjcDC4plubQ9ewMKsGeBlDG4
xxkaMYJeqx8usmiT+fisiI6B+tM38ahxtYqcyCp3ou+WrSEuRb+70UXnztR8RT4R
ISkpq0wuj1Qcmxp9GkyA6aH4gwlj7EocqhIUCF2LxS8U0u2xvbCxHVSQFf4VxrrW
ZwoHaI8GWAZb/IAe9gxoau5rtJ90gpesO5AVx1VPX+WhpSCmVGPnJdknMXC6mjDJ
rMUW0KX8/dX7OdXAtSdDLzm6Yd4cI2DTnGVfckGIzsIYlGhBwxIUGwIDAQABMA0G
CSqGSIb3DQEBCwUAA4ICAQAlendYr/Xrh2h9tWRNB7kCS8OSaJqsaLP7nDWlwbj/
93QRB51qg2BHUy+tCzXAChq9HnaVcOLrDa0V3Amx5J6LauIBTnRBlHQGaw9Tu4Bo
UqMusHKM9/brNTDRUq8eafJhdfsXWs+cwKj9+Zh1UX0gc8yzgJSLCfkJgeuf62vP
tLAiJAxanxwT2hqtHnuVLu/UUmfx4n0IOALE8tARcLwZkKfmbsXiIY0ZIb/kwCuF
APYy4bmjRXfA9CKnHcfwOxYNqsAPad/MLme9bSBtOuY75VY3UDeno6Uz5PZL4163
8q+MedT6yinEtGaEllnpWMHa4NC0w+Klpk28fONEIxfqjCvlugRkIlCS3T9qfS9R
vhqwn1V+13JRYxLwMtVpXPdfQbBy7PG9VaQAyRsMrIGsG8esHx+OUMKP3hvh07gs
Lhmjn8SWaFpazldaNRcbOKazxHcwY+yL21VEL5CdA8GcjXEls3YaCuw54QBPJaoB
Yg4ybiaio7h8od1Nydf3mbQ9gmMruLpGHw7RKAGxBD6Ukt0uPAMKOgaL9H2YOSzB
SsYyE/ONrTbxpHZPQG1SszKuKUzGsPEwlMTwt8NHVTixKy/ttMA7NhN8KAYJrJQw
Z65R0mZFpYSL31jrfV4Q4mhFj6/Cr8rgmH++82FWfg88gf4lPk6/iDZtHvMMBUXy
Pg==
-----END CERTIFICATE-----`

const localhostKeyPem = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDfD0/OIt2K5iSr
izFURCSrQciroB3/nWiT3wAbzsOpsbiFw9xs/8i0Qe/g11hk61qBjm3DNv6yNwML
imW5tD17AwqwZ4GUMbjHGRoxgl6rHy6yaJP5+KyIjoH60zfxqHG1ipzIKnei75at
IS5Fv7vRRefO1HxFPhEhKSmrTC6PVBybGn0aTIDpofiDCWPsShyqEhQIXYvFLxTS
7bG9sLEdVJAV/hXGutZnCgdojwZYBlv8gB72DGhq7mu0n3SCl6w7kBXHVU9f5aGl
IKZUY+cl2ScxcLqaMMmsxRbQpfz91fs51cC1J0MvObph3hwjYNOcZV9yQYjOwhiU
aEHDEhQbAgMBAAECggEBALK97lFclvLK4O+lpm3D/S5OlKMSt3cxh6+WrtuZoCjH
BPoLrQKbJRVtEO+3IFoeTnQq0cHwu7/LXWFOEZ3x1KJSGaqqBqfeABdrAhZSRdIS
NrU4H/vbTUZQC9AWmWnIdPXokSHFBgFGxBMP16iEr9hOkCapFrvVtJxCA+YEMfsf
CKK9azdS/6aA4LxFKFuf7EwZz3uD5BqQXM/1vrAjmmATzE5yoJUsUPwJNwTlwTLs
53tOoZAIhYiWMXL1USXcKm3z8IJq8SgfgOUsK9X6IEEIga/IMwimPl966RlJyIsR
U4RzqG+cP5D2bC9n1M3aBUmUGcvWV7E3nVg+bbuNYIECgYEA76lfyMCbnnBzqagx
UpNR6PXn53RQicQktt+wFFexknf01ZmX+Tn3slSVtsms2xJRtUeNmljPKa7CIMWi
CaBLA2fsUjkPB0EQk6v8MzJeEJOpfFPWC+miKZhnV17rNkuuCwUdPFIz7g66/HU5
/W4gzrUkttw597cpOkOoiUrd16sCgYEA7kQzBa0ille35TlicqSQqeLQrTSga7b2
U0NjSwu0szCGw2LNV87H6Fhxw+MqIQM5VDTPb3bp9T0Uv2n0moENbGO5dD4ZGuNC
mA+AmKNeUBx81Jx4DumGxaU3eATkg6KlNKNccHtXF64k8blM9Y6q6ncCtr4UVz3H
ekSGNXx/hVECgYBf+o7XkPtBmntXqHoIPeOBzmlPMi/G3HxvmGml2/DLXar5mAda
0jI2gtVqXJ4TJeT/GmbFN2fPo6MvCLb57+3asVXdH+i62P3QhgH8ZuFw9hHcLp78
Kla9HcHVJbhBCFHtK+EndSxC3DdaP4A31FDjN3w6lzvHztx97vah9Q+e/QKBgQCk
8Y+EuXO9MmJ7DDvL84K2KO+fSFRZ3SIvR/JgDG1+svRIJIjU5bBcd4XiPst2aR3x
3lFP77lM7YkEbdxIbViWlX7YKvkENRlv3SOAB3CN8vqz0NIIOL/06Ug6DOEJA7ps
cz7WG3ySRxsKP+Y4BBjsEZFOYs4ACyOhz/g85L/+0QKBgQCjjTLjcSNg+fBZRXHC
YwzyBA/WXBPve5qo17Bt91knZ4m+xOVmRcswNG2U0eFrm+nNlk84Kj3TMRAv8Stx
GuCdIOQpn0IWClccTMjwc0AhJStSckNdSUQcsRl6LRnRHa3oCIs3hxnkiEHYch6e
dcxWzhBDbzeIV9SvcTwLx/ghQg==
-----END PRIVATE KEY-----`

const (
	groupname = "aaa.test.yunchao"
	username  = "yunchao_liu"
)

var testBaseGroupData = map[string]map[string][]string{
	"group1": map[string][]string{
		"cn":        []string{"group1"},
		"gidNumber": []string{"10001"},
		"owner":     []string{"cn=group1,o=group, o=My Company, c=US"},
		"memberUid": []string{"yunchao_liu"},
	},
	"group2": map[string][]string{
		"cn":        []string{"group2"},
		"gidNumber": []string{"10002"},
		"owner":     []string{"cn=group1,o=group, o=My Company, c=US"},
		"memberUid": []string{"valere.jeantet"},
	},
	"group3": map[string][]string{
		"cn":        []string{"group3"},
		"gidNumber": []string{"10003"},
		"owner":     []string{"cn=group1,o=group, o=My Company, c=US"},
		"memberUid": []string{"valere.jeantet", "yunchao_liu"},
	},
}

var testGroupData = map[string]map[string][]string{}

// getTLSconfig returns a tls configuration used
// to build a TLSlistener for TLS or StartTLS
func getTLSconfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(localhostCertPem), []byte(localhostKeyPem))
	if err != nil {
		return &tls.Config{}, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionSSL30,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
	}, nil
}

// handleBind return Success if login == username
func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	if string(r.Name()) == "username" {
		w.Write(res)
		return
	}

	log.Printf("Bind failed User=%s, Pass=%s", string(r.Name()), string(r.AuthenticationSimple()))
	res.SetResultCode(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}

func handleSearchGroup(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())
	log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())

	hasGroupFilter := strings.Contains(r.FilterString(), "cn=") || strings.Contains(r.FilterString(), "memberUid=")
	for groupName, groupData := range testGroupData {
		searchPattern := "cn=" + groupName
		if !hasGroupFilter || strings.Contains(r.FilterString(), searchPattern) {
			e := ldap.NewSearchResultEntry("cn=" + groupName + "," + string(r.BaseObject()))
			for attributeName, attributeDataArray := range groupData {
				for _, attributeValue := range attributeDataArray {
					e.AddAttribute(message.AttributeDescription(attributeName), message.AttributeValue(attributeValue))
				}
			}
			w.Write(e)
		}
	}
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())
	log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		log.Print("Leaving handleSearch...")
		return
	default:
	}

	hasUserFilter := !strings.Contains(r.FilterString(), "uid=*")
	if !hasUserFilter || strings.Contains(r.FilterString(), "uid=valere.jeantet") {
		e := ldap.NewSearchResultEntry("cn=Valere JEANTET, " + string(r.BaseObject()))
		e.AddAttribute("mail", "valere.jeantet@gmail.com", "mail@vjeantet.fr")
		e.AddAttribute("company", "SODADI")
		e.AddAttribute("department", "DSI/SEC")
		e.AddAttribute("l", "Ferrieres en brie")
		e.AddAttribute("mobile", "0612324567")
		e.AddAttribute("telephoneNumber", "0612324567")
		e.AddAttribute("cn", "Valère JEANTET")
		e.AddAttribute("uid", "valere.jeantet")
		e.AddAttribute("uidNumber", "5000")
		e.AddAttribute("memberOf", "cn=group2, o=group, o=My Company, c=US", "cn=group3, o=group, o=My Company, c=US")
		e.AddAttribute("givenName", "valere")
		e.AddAttribute("sAMAccountName", "valere.jeantet")
		w.Write(e)
	}
	if !hasUserFilter || strings.Contains(r.FilterString(), "uid=yunchao_liu") {
		e := ldap.NewSearchResultEntry("cn=Yunchao Liu, " + string(r.BaseObject()))
		e.AddAttribute("mail", "yunchao_liu@example.com")
		e.AddAttribute("cn", "Yunchao Liu")
		e.AddAttribute("uid", "yunchao_liu")
		e.AddAttribute("uidNumber", "5001")
		e.AddAttribute("memberOf", "cn=group1, o=group, o=My Company, c=US", "cn=group3, o=group, o=My Company, c=US")
		e.AddAttribute("givenName", "yunchao")
		e.AddAttribute("sAMAccountName", "yunchao_liu")
		w.Write(e)
	}

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleModifyGroup(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyRequest()
	log.Printf("Modify entry: %s", r.Object())

	for _, change := range r.Changes() {
		modification := change.Modification()
		var operationString string
		switch change.Operation() {
		case ldap.ModifyRequestChangeOperationAdd:
			operationString = "Add"
		case ldap.ModifyRequestChangeOperationDelete:
			operationString = "Delete"
		case ldap.ModifyRequestChangeOperationReplace:
			operationString = "Replace"
		}

		log.Printf("%s attribute '%s'", operationString, modification.Type_())
		for _, attributeValue := range modification.Vals() {
			log.Printf("- value: %s", attributeValue)
		}

	}

	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleAddGroup(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetAddRequest()
	log.Printf("Adding entry: %s", r.Entry())
	//attributes values
	for _, attribute := range r.Attributes() {
		for _, attributeValue := range attribute.Vals() {
			log.Printf("- %s:%s", attribute.Type_(), attributeValue)
		}
	}
	res := ldap.NewAddResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleDeleteGroup(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetDeleteRequest()
	log.Printf("Deleting entry: %s", r)
	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func init() {

	//Create a new LDAP Server
	server := ldap.NewServer()

	//Set routes, here, we only serve bindRequest
	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)

	routes.Search(handleSearchGroup).
		BaseDn("o=group,o=My Company,c=US").
		Label("Search - Group Root")
	routes.Search(handleSearch).Label("Search - Generic")
	routes.Modify(handleModifyGroup).BaseDn("o=group,o=My Company,c=US")

	routes.Add(handleAddGroup).BaseDn("o=group,o=My Company,c=US")
	routes.Delete(handleDeleteGroup).BaseDn("o=group,o=My Company,c=US")

	//This should be modified for other
	routes.Add(handleAddGroup).BaseDn("ou=services,o=My Company,c=US")

	server.Handle(routes)

	//SSL
	secureConn := func(s *ldap.Server) {
		config, _ := getTLSconfig()
		s.Listener = tls.NewListener(s.Listener, config)
	}
	go server.ListenAndServe(":10636", secureConn)

	time.Sleep(20 * time.Millisecond)

}

////////////////////////////
func setupTestLDAPUserInfo(t *testing.T) *UserInfoLDAPSource {
	var u UserInfoLDAPSource
	u.RootCAs = x509.NewCertPool()
	ok := u.RootCAs.AppendCertsFromPEM([]byte(rootCAPem))
	if !ok {
		t.Fatal("cannot add certs to certpool")
	}
	u.LDAPTargetURLs = "ldaps://localhost:10636"
	u.BindUsername = "username"
	u.BindPassword = "password"
	u.UserSearchBaseDNs = "ou=people,o=My Company,c=US"
	u.UserSearchFilter = "(&(uid=*)(objectClass=person))"
	u.GroupSearchBaseDNs = "o=group,o=My Company,c=US"
	u.GroupSearchFilter = "(|(objectClass=posixGroup)(objectClass=groupofNames))"
	u.ServiceAccountBaseDNs = "ou=services,o=My Company,c=US"
	u.GroupManageAttribute = "owner"
	u.MainBaseDN = "o=My Company,c=US"
	u.SearchAttribute = "uid"
	u.AdminGroup = "group1"
	for k := range testGroupData {
		delete(testGroupData, k)
	}

	for k, v := range testBaseGroupData {
		testGroupData[k] = v
	}

	return &u
}

func Test_GetallUsers(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	userList, err := u.GetallUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(userList) < 1 {
		t.Errorf("Should have failed")
	}
	t.Logf("GetAllUsers =%+v", userList)

	//now make a second call to get the cached values
	userList2, err := u.GetallUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(userList2) != len(userList) {
		t.Fatalf("second call for users does not match in len")
	}
	// TODO: actually compare the contents

}

func Test_GetallGroups(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	allGroups, err := u.GetallGroups()
	if err != nil {
		log.Println(err)
	}
	if len(allGroups) != 3 {
		t.Fatalf("should have returned exactly 3 groups")
	}
	t.Logf("GetAllGroups =%+v", allGroups)
}

func Test_GetgroupsofUser(t *testing.T) {
	var groups []string
	u := setupTestLDAPUserInfo(t)
	groups, err := u.GetgroupsofUser("valere.jeantet")
	if err != nil {
		log.Println(err)
	}
	if len(groups) != 7 {
		log.Println(groups)
	}
}

func Test_GetusersofGroup(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	users, owner, err := u.GetusersofaGroup("group2")
	if err != nil {
		log.Fatal(err)
	}
	if owner != "group1" {
		log.Fatalf("bad returned owner")
	}
	if len(users) != 1 || users[0] != "valere.jeantet" {
		log.Fatalf("bad expected Users owner")
	}
}

func Test_isgroupmemberornot(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	expectedFalse, _, err := u.IsgroupmemberorNot("group1", "valere.jeantet")
	if err != nil {
		log.Fatal(err)
	}
	if expectedFalse {
		log.Fatalf("should not be a member")
	}
	expectedTrue, _, err := u.IsgroupmemberorNot("group2", "valere.jeantet")
	if err != nil {
		log.Fatal(err)
	}
	if !expectedTrue {
		log.Fatalf("should not be a member")
	}
}

func Test_GetDescriptionvalue(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	description, err := u.GetDescriptionvalue("group2")
	if err != nil {
		log.Println(err)
	}
	if description != "" {
		log.Println(description)
	}
}

func Test_UsernameExistsornot(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	result, err := u.UsernameExistsornot("valere.jeantet")
	if err != nil {
		log.Println(err)
	}
	if !result {
		log.Println(username)
	}
}

func Test_GroupnameExistsornot(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	result, description, err := u.GroupnameExistsornot("invalidGroup")
	if err != nil {
		log.Println(err)
	}
	if !result {
		log.Println(description)
	}
	if result {
		log.Fatalf("group should be invalid")
	}
	result, _, err = u.GroupnameExistsornot("group2")
	if !result {
		log.Fatalf("group should be valid")
	}
}

func Test_GetEmailofusersingroup(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	groupEmails, err := u.GetEmailofusersingroup("group2")
	if err != nil {
		log.Fatal(err)
	}
	//Todo actua;;y check
	t.Logf("groupEmails=%+v", groupEmails)
}

func Test_GetGroupsInfoOfUser(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	userGroups, err := u.GetGroupsInfoOfUser("o=group,o=My Company,c=US", "valere.jeantet")
	if err != nil {
		log.Fatal(err)
	}
	//Todo actua;;y check
	t.Logf("userGroups+Man=%+v", userGroups)
}

func Test_GetGroupUsersAndManagers(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	members, managers, managerGroupName, err := u.GetGroupUsersAndManagers("group2")
	if err != nil {
		log.Fatal(err)
	}
	//TODO: actually check the return values
	t.Logf("members=%+v managers=%+v, managerGroupName=%s", members, managers, managerGroupName)
}

func Test_GetAllGroupsManagedBy(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	groupsManagers, err := u.GetAllGroupsManagedBy()
	if err != nil {
		log.Fatal(err)
	}
	t.Logf("groupManagres=%+v", groupsManagers)
	groupsManagers2, err := u.GetAllGroupsManagedBy()
	if err != nil {
		log.Fatal(err)
	}
	t.Logf("groupManagres2=%+v", groupsManagers2)

}

//Now we test the ones that modify

func Test_AddmembersToExisting(t *testing.T) {
	u := setupTestLDAPUserInfo(t)

	groupInfo := userinfo.GroupInfo{
		Groupname: "group2",
		MemberUid: []string{"yunchao_liu"},
	}
	err := u.AddmemberstoExisting(groupInfo)
	if err != nil {
		log.Fatal(err)
	}
	// TODO: actually verify that the members where added
}

func Test_CreateGroup(t *testing.T) {
	u := setupTestLDAPUserInfo(t)

	groupInfo := userinfo.GroupInfo{
		Groupname:   "group4",
		Description: "self-managed",
		MemberUid:   []string{"yunchao_liu"},
	}
	err := u.CreateGroup(groupInfo)
	if err != nil {
		log.Fatal(err)
	}
	// TODO: actually verify that the members where added

}

func Test_DeleteGroup(t *testing.T) {
	u := setupTestLDAPUserInfo(t)

	err := u.DeleteGroup([]string{"group3"})
	if err != nil {
		log.Fatal(err)
	}
	// TODO: actually verify that the members where added

}

func Test_CreateServiceAccount(t *testing.T) {
	u := setupTestLDAPUserInfo(t)

	groupInfo := userinfo.GroupInfo{
		Groupname:   "serviceaccount-f00",
		Description: "self-managed",
	}

	err := u.CreateServiceAccount(groupInfo)
	if err != nil {
		log.Fatal(err)
	}
	// TODO: actually verify that the members where added
}

func Test_GetInfoFromAD(t *testing.T) {
	u := setupTestLDAPUserInfo(t)
	mail, givenName, err := u.GetUserAttributes("yunchao_liu")
	if err != nil {
		log.Fatal(err)
	}

	t.Logf("email=%+v givenName=%+v", mail, givenName)
}

func Test_UserisadminOrNot(t *testing.T) {
	u := setupTestLDAPUserInfo(t)

	adminOrNot := u.UserisadminOrNot("yunchao_liu")
	t.Logf("yunchao_liu is admin: %+v", adminOrNot)

	adminOrNotV := u.UserisadminOrNot("valere.jeantet")
	t.Logf("valere.jeantet is admin: %+v", adminOrNotV)
}
