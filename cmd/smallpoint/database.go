package main

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"time"
)

//Initialsing database
func initDB(state *RuntimeState) (err error) {

	state.dbType = "sqlite3"
	state.db, err = sql.Open("sqlite3", state.Config.Base.StorageURL)
	if err != nil {
		return err
	}
	if true {
		sqlStmt := `create table if not exists pending_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, username text not null, groupname text not null, time_stamp int not null);`
		_, err = state.db.Exec(sqlStmt)
		if err != nil {
			log.Printf("init sqlite3 err: %s: %q\n", err, sqlStmt)
			return err
		}
	}

	return nil
}

//insert a request into DB
func insertRequestInDB(username string, groupnames []string, state *RuntimeState) error {

	stmtText := "insert into pending_requests(username, groupname, time_stamp) values (?,?,?);"
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement")
		log.Fatal(err)
	}
	defer stmt.Close()
	for _, entry := range groupnames {
		if entryExistsorNot(username, entry, state) || state.Config.TargetLDAP.IsgroupmemberorNot(entry, username) {
			continue
		} else {

			_, err = stmt.Exec(username, entry, time.Now().Unix())
			if err != nil {
				return err
			}
		}
	}
	return nil
}

//delete the request after approved or declined
func deleteEntryInDB(username string, groupname string, state *RuntimeState) error {

	stmtText := "delete from pending_requests where username= ? and groupname= ?;"
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement")
		log.Fatal(err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(username, groupname)
	if err != nil {
		return err
	}
	return nil

}

//deleting all groups in DB which are deleted from Target LDAP
func deleteEntryofGroupsInDB(groupnames []string, state *RuntimeState) error {

	stmtText := "delete from pending_requests where groupname= ?;"
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement")
		return err
	}
	defer stmt.Close()
	for _, entry := range groupnames {
		_, err = stmt.Exec(entry)
		if err != nil {
			return err
		}
	}
	return nil

}

//Search for a particular request made by a user (or) a group. (for my_pending_actions)
func findrequestsofUserinDB(username string, state *RuntimeState) ([]string, bool, error) {
	stmtText := "select groupname from pending_requests where username=?;"
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement")
		log.Fatal(err)
	}
	defer stmt.Close()
	var groupname []string
	rows, err := stmt.Query(username)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			log.Printf("err='%s'", err)
			return nil, false, nil
		} else {
			log.Printf("Problem with db ='%s'", err)
			return nil, false, err
		}
	}
	defer rows.Close()

	for rows.Next() {
		var groupName string
		err = rows.Scan(&groupName)
		groupname = append(groupname, groupName)
	}

	return groupname, true, nil

}

//looks in the DB if the entry already exists or not
func entryExistsorNot(username string, groupname string, state *RuntimeState) bool {
	stmtText := "select * from pending_requests where username=? and groupname=?;"
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement")
		log.Fatal(err)
	}
	defer stmt.Close()
	rows, err := stmt.Query(username, groupname)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			log.Printf("err='%s'", err)
			return false
		} else {
			log.Printf("Problem with db ='%s'", err)
			return false
		}
	}
	defer rows.Close()
	if rows.Next() {
		return true
	}
	return false
}

//(username,groupname) get whole db entries.
func getDBentries(state *RuntimeState) ([][]string, error) {
	stmtText := "select username,groupname from pending_requests;"
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement")
		log.Fatal(err)
	}
	defer stmt.Close()
	var entry [][]string
	rows, err := stmt.Query()
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			log.Printf("err='%s'", err)
			return nil, err
		} else {
			log.Printf("Problem with db ='%s'", err)
			return nil, err
		}
	}
	defer rows.Close()
	var eachEntry1 string
	var eachEntry2 string
	for rows.Next() {
		err = rows.Scan(&eachEntry1, &eachEntry2)
		var eachentry = []string{eachEntry1, eachEntry2}
		entry = append(entry, eachentry)
	}
	return entry, nil
}
