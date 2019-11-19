package main

import (
	"log"
	"sort"
)

var checkPermissionStmt = map[string]string{
	"sqlite":   "select groupname from permissions where (resource=? or resource='*') and resource_type=? and (permission&?=?);",
	"postgres": "select groupname from permissions where (resource=$1 or resource='*') and resource_type=$2 and (permission&$3=$4);",
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

func getPermittedGroups(resources string, resource_type, permission int, state *RuntimeState) ([]string, error) {
	stmtText := checkPermissionStmt[state.dbType]
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Println("Error prepare statement " + stmtText)
		return nil, err
	}
	defer stmt.Close()

	var groupnames []string
	rows, err := stmt.Query(resources, resource_type, permission, permission)
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
		groupnames = append(groupnames, groupName)
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

var insertPermissionStmt = map[string]string{
	"sqlite":   "insert into permissions(groupname, resource_type, resource, permission) values (?,?,?,?);",
	"postgres": "insert into permissions(groupname, resource_type, resource, permission) values ($1, $2, $3, $4);",
}

func insertPermissionEntry(groupname, resource string, resource_type, permission int, state *RuntimeState) error {
	stmtText := insertPermissionStmt[state.dbType]
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement" + stmtText)
		log.Fatal(err)
		return err
	}
	defer stmt.Close()
	exists, oldPerm := permExistsorNot(groupname, resource, resource_type, state)
	if exists {
		if oldPerm == permission {
			return nil
		}
		return updatePermissionEntry(groupname, resource, oldPerm+permission, resource_type, state)
	}
	_, err = stmt.Exec(groupname, resource_type, resource, permission)
	if err != nil {
		return err
	}
	return nil
}

var permExistsorNotStmt = map[string]string{
	"sqlite":   "select * from permissions where groupname=? and resource_type=? and resource=?;",
	"postgres": "select * from permissions where groupname=$1 and resource_type=$2 and resource=$3;",
}

func permExistsorNot(groupname, resource string, resource_type int, state *RuntimeState) (bool, int) {
	stmtText := permExistsorNotStmt[state.dbType]
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement" + stmtText)
		log.Fatal(err)
		return false, 0
	}
	defer stmt.Close()
	rows, err := stmt.Query(groupname, resource_type, resource)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			log.Printf("err='%s'", err)
			return false, 0
		} else {
			log.Printf("Problem with db ='%s'", err)
			return false, 0
		}
	}

	defer rows.Close()
	if rows.Next() {
		var oldPerm int
		err = rows.Scan(&oldPerm)
		if err != nil {
			return true, 0
		}
		return true, oldPerm
	}
	return false, 0
}

var updatePermissionStmt = map[string]string{
	"sqlite":   "update permissions set permission=? where groupname=? and resource_type=? and resource=?;",
	"postgres": "update permissions set permission=$1 where groupname=$2 and resource_type=$3 and resource=$4;",
}

func updatePermissionEntry(groupname, resource string, permission, resource_type int, state *RuntimeState) error {
	stmtText := updatePermissionStmt[state.dbType]
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement" + stmtText)
		log.Fatal(err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(permission, groupname, resource_type, resource)
	if err != nil {
		return err
	}
	return nil
}
