package main

import (
	"log"
	"strings"
	"gopkg.in/ldap.v2"
)

//Function which returns the array of disabled accounts from Source LDAP.--required
func (state *RuntimeState) DisabledAccountsinSourceLDAP(UserSearchBaseDNs string, UserSearchFilter string, Attributes []string) ([]string, error) {
	var disabled_accounts []string

	searchrequest := ldap.NewSearchRequest(UserSearchBaseDNs, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, UserSearchFilter, Attributes, nil)

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
//---required
func (state *RuntimeState) CompareDisabledaccounts(result []string) error {
	for _, entry := range result {
		entry = state.Create_UserDN(entry)

		modify := ldap.NewModifyRequest(entry)
		modify.Replace("nsaccountLock", nsaccount_lock)
		err := state.target_ldap.Modify(modify)
		if err != nil {
			return err
		}
	}
	return nil

}



//find out which accounts need to be locked in Target ldap(i.e. which accounts needs attribute nsaccountLock=True) --required
func FindLockAccountsinTargetLdap(TargetLDAP_Users map[string]string, LockedAccounts_SourceLDAP []string) ([]string, error) {
	var lock_accounts []string
	for _, entry := range LockedAccounts_SourceLDAP {
		if entry, ok := TargetLDAP_Users[entry]; ok {

			lock_accounts = append(lock_accounts, entry)
		}

	}
	return lock_accounts, nil
}


