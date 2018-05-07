package ldapuserinfo

import (
	"gopkg.in/ldap.v2"
	"log"
	"strings"
)

const maximumPagingsize = 2147483647

var nsaccountLock = []string{"True"}

//Function which returns the array of disabled accounts from Source LDAP.--required
func (u *UserInfoLDAPSource) getDisabledAccountsinLDAP() ([]string, error) {
	var disabledAccounts []string
	Attributes := []string{"sAMAccountName"}
	searchrequest := ldap.NewSearchRequest(u.UserSearchBaseDNs, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, u.UserSearchFilter, Attributes, nil)

	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer conn.Close()

	result, err := conn.SearchWithPaging(searchrequest, maximumPagingsize)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if len(result.Entries) == 0 {
		log.Println("No records found")
	}
	for _, entry := range result.Entries {
		cname := entry.GetAttributeValue("sAMAccountName")
		disabledAccounts = append(disabledAccounts, strings.ToLower(cname))
	}
	return disabledAccounts, nil
}

//function which compares the users disabled accounts in Source LDAP and Target LDAP and adds the attribute nsaccountLock in TARGET LDAP for the disbaled USer.
//---required
func (u *UserInfoLDAPSource) DisableaccountsinLdap(result []string) error {
	conn, err := u.getTargetLDAPConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

	for _, entry := range result {
		entry = u.CreateuserDn(entry)

		modify := ldap.NewModifyRequest(entry)
		modify.Replace("nsaccountLock", nsaccountLock)
		err := conn.Modify(modify)
		if err != nil {
			return err
		}
	}
	return nil

}

//find out which accounts need to be locked in Target ldaputil(i.e. which accounts needs attribute nsaccountLock=True) --required
func FindLockAccountsinTargetLdap(TargetLDAPUsers map[string]string, LockedAccountsSourceLDAP []string) ([]string, error) {

	var lockAccounts []string
	for _, entry := range LockedAccountsSourceLDAP {
		if entry, ok := TargetLDAPUsers[entry]; ok {

			lockAccounts = append(lockAccounts, entry)
		}

	}
	return lockAccounts, nil
}
