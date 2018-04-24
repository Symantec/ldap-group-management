package main

import (
	"gopkg.in/ldap.v2"
	"log"
	"strings"
)

//Function which returns the array of disabled accounts from Source LDAP.--required
func (state *RuntimeState) DisabledAccountsinSourceLDAP(UserSearchBaseDNs string,
	UserSearchFilter string, Attributes []string) ([]string, error) {
	var disabledAccounts []string

	searchrequest := ldap.NewSearchRequest(UserSearchBaseDNs, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, UserSearchFilter, Attributes, nil)

	result, err := state.sourceLdap.SearchWithPaging(searchrequest, maximumPagingsize)
	if err != nil {
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
func (state *RuntimeState) CompareDisabledaccounts(result []string) error {
	for _, entry := range result {
		entry = state.Config.TargetLDAP.CreateuserDn(entry)

		modify := ldap.NewModifyRequest(entry)
		modify.Replace("nsaccountLock", nsaccountLock)
		err := state.targetLdap.Modify(modify)
		if err != nil {
			return err
		}
	}
	return nil

}

//find out which accounts need to be locked in Target ldap(i.e. which accounts needs attribute nsaccountLock=True) --required
func FindLockAccountsinTargetLdap(TargetLDAPUsers map[string]string,
	LockedAccountsSourceLDAP []string) ([]string, error) {

	var lockAccounts []string
	for _, entry := range LockedAccountsSourceLDAP {
		if entry, ok := TargetLDAPUsers[entry]; ok {

			lockAccounts = append(lockAccounts, entry)
		}

	}
	return lockAccounts, nil
}
