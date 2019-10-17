package main

import (
	"log"
	"sort"
)

var checkPermissionStmt = "select groupname from permissions where resources=$1 and permission=$2;"

func checkPermission(resources string, permission int, state *RuntimeState) []string {
	stmt, err := state.db.Prepare(checkPermissionStmt)
	if err != nil {
		log.Println("Error prepare statement " + checkPermissionStmt)
	}
	defer stmt.Close()

	var groupnames []string
	rows, err := stmt.Query(resources, permission)
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

func (state *RuntimeState) canPerformAction(username, resources string, permission int) (bool, error) {
	groups := checkPermission(resources, permission, state)
	log.Println(groups)
	groupsOfUser, err := state.Userinfo.GetgroupsofUser(username)
	if err != nil {
		return false, err
	}
	sort.Strings(groupsOfUser)

	for _, group := range groups {
		var index int
		index = sort.SearchStrings(groupsOfUser, group)
		if index < len(groupsOfUser) {
			return true, nil
		}
		continue
	}

	return false, nil
}
