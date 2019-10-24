package main

import (
	"log"
	"sort"
)

var checkPermissionStmt = "select groupname from permissions where (resource=$1 or resource='*') and resource_type=$2 and permission=$3;"

func checkPermission(resources, resource_type string, permission int, state *RuntimeState) []string {
	stmt, err := state.db.Prepare(checkPermissionStmt)
	if err != nil {
		log.Println("Error prepare statement " + checkPermissionStmt)
	}
	defer stmt.Close()

	var groupnames []string
	rows, err := stmt.Query(resources, resource_type, permission)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			log.Println("No rows found")
			return nil
		} else {
			log.Println(err)
			return nil

		}
	}
	defer rows.Close()

	for rows.Next() {
		var groupName string
		err = rows.Scan(&groupName)
		groupnames = append(groupnames, groupName)
	}
	return groupnames
}

func (state *RuntimeState) canPerformAction(username, resources, resource_type string, permission int) (bool, error) {
	groups := checkPermission(resources, resource_type, permission, state)
	log.Println(groups)
	groupsOfUser, err := state.Userinfo.GetgroupsofUser(username)
	if err != nil {
		return false, err
	}
	sort.Strings(groupsOfUser)

	adminGroup := state.Config.TargetLDAP.AdminGroup
	adminIndex := sort.SearchStrings(groupsOfUser, adminGroup)
	if adminIndex < len(groupsOfUser) {
		return true, nil
	}

	for _, group := range groups {
		var index int
		index = sort.SearchStrings(groupsOfUser, group)
		if index < len(groupsOfUser) && groupsOfUser[index] == group {
			return true, nil
		}
		continue
	}

	return false, nil
}
