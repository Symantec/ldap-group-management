package main

import (
	"log"
	"sort"
	"strings"
)

var checkPermissionStmt = map[string]string{
	"sqlite":   "select groupname from permissions where (resource=? or resource='*' or resource LIKE ?) and resource_type=? and (permission&?=?);",
	"postgres": "select groupname from permissions where (resource=$1 or resource='*' or resource LIKE $2) and resource_type=$3 and (permission&$4=$5);",
}

var checkResourceStmt = map[string]string{
	"sqlite":   "select resource from permissions where groupname=? and resource_type=? and (permission&?=?);",
	"postgres": "select resource from permissions where groupname=$1 and resource_type=$2 and (permission&$3=$4);",
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

func checkResourceMatch(groupname, input string, resource_type, permission int, state *RuntimeState) (bool, error) {
	stmtText := checkResourceStmt[state.dbType]
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Println("Error prepare statement " + stmtText)
		return false, err
	}
	defer stmt.Close()

	rows, err := stmt.Query(groupname, resource_type, permission, permission)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			log.Println("No rows found")
			return false, err
		} else {
			log.Println(err)
			return false, err

		}
	}
	defer rows.Close()

	for rows.Next() {
		var target string
		err = rows.Scan(&target)
		if err != nil {
			log.Println(err)
			return false, err
		}
		if strings.HasSuffix(target, "*") {
			if len(target) == 1 {
				return true, nil
			}
			target = target[:len(target)-1]
			if strings.HasPrefix(input, target) {
				return true, nil
			}
		}
		if target == input {
			return true, nil
		}
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
		err = rows.Scan(&groupName)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		match, err := checkResourceMatch(groupName, resources, resource_type, permission, state)
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
