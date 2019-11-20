package main

import (
	"log"
	"sort"
	"strings"
)

var checkPermissionStmt = map[string]string{
	"sqlite":   "select groupname, resource from permissions where (resource=? or resource='*' or resource LIKE ?) and resource_type=? and (permission&?=?);",
	"postgres": "select groupname, resource from permissions where (resource=$1 or resource='*' or resource LIKE $2) and resource_type=$3 and (permission&$4=$5);",
}

const (
	permCreate = 1 << iota
	permUpdate
	permDelete
)

const (
	resourceGroup = iota + 1
	resourceSVC
)

func checkResourceMatch(resource, input string) (bool, error) {
	if strings.HasSuffix(resource, "*") {
		if len(resource) == 1 {
			return true, nil
		}
		resource = resource[:len(resource)-1]
		if strings.HasPrefix(input, resource) {
			return true, nil
		}
	}
	if resource == input {
		return true, nil
	}
	return false, nil
}

func getPermittedGroups(resources string, resource_type, permission int, state *RuntimeState) ([]string, error) {
	stmtText := checkPermissionStmt[state.dbType]
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Println("Error prepare statement " + stmtText)
		return nil, err
	}
	defer stmt.Close()

	var groupnames []string

	firstLetter := resources[:1]
	rows, err := stmt.Query(resources, firstLetter+"%", resource_type, permission, permission)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			log.Println("No rows found")
			return nil, err
		} else {
			log.Println(err)
			return nil, err

		}
	}
	defer rows.Close()

	for rows.Next() {
		var groupName string
		var resourceName string
		err = rows.Scan(&groupName, &resourceName)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		match, err := checkResourceMatch(resourceName, resources)
		if err != nil {
			log.Println(err)
			return nil, err
		}

		if match {
			groupnames = append(groupnames, groupName)
		}
	}
	return groupnames, nil
}

func (state *RuntimeState) canPerformAction(username, resources string, resource_type, permission int) (bool, error) {
	groups, err := getPermittedGroups(resources, resource_type, permission, state)
	if err != nil {
		return false, err
	}

	if len(groups) < 1 {
		return false, nil
	}
	groupsOfUser, err := state.Userinfo.GetgroupsofUser(username)
	if err != nil {
		return false, err
	}
	sort.Strings(groupsOfUser)

	if state.Userinfo.UserisadminOrNot(username) {
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
