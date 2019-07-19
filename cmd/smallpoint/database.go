package main

import (
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"strings"
	"time"
)

const (
	profileDBFilename = "requests.sqlite3"
	DB_Port           = "5432"
)

//Initialsing database -- There are two cases for the database, one is sqlite and the other one is postgrep
func initDB(state *RuntimeState) (err error) {

	storageURL := state.Config.Base.StorageURL
	if storageURL == "" {
		storageURL = "sqlite:"
	}
	splitString := strings.SplitN(storageURL, ":", 2)
	if len(splitString) < 1 {
		log.Print("invalid string")
		err := errors.New("Bad storage url string")
		return err
	}
	//state.remoteDBQueryTimeout = time.Second * 2
	//initialSleep := time.Second * 3
	switch splitString[0] {
	case "sqlite":
		log.Print("doing sqlite")
		return initDBSQlite(state, splitString[1])
	case "postgresql":
		log.Print("doing postgres")
		return initDBPostgres(state, splitString[1])
	default:
		log.Print("invalid storage url string")
		err := errors.New("Bad storage url string")
		return err
	}

	err = errors.New("invalid state")
	return err
}

func initDBSQlite(state *RuntimeState, db string) (err error) {
	state.dbType = "sqlite"
	state.db, err = sql.Open("sqlite3", db)
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

func initDBPostgres(state *RuntimeState, db string) (err error) {
	state.dbType = "postgres"
	dnsStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		state.Config.Base.DB_Username, state.Config.Base.DB_Password, db, DB_Port, state.Config.Base.DB_Name,
	)

	// Use db to perform SQL operations on database
	state.db, err = sql.Open("postgres", dnsStr)
	if err != nil {
		fmt.Println("Cannot open db")
		log.Println(err)
	}

	// This should be changed to take care of DB schema
	if true {
		sqlStmt := `create table if not exists pending_requests (id SERIAL PRIMARY KEY, username text not null, groupname text not null, time_stamp int not null);`
		_, err = state.db.Exec(sqlStmt)
		if err != nil {
			log.Printf("init postgres err: %s: %q\n", err, sqlStmt)
			return err
		}
	}

	return nil
}

//insert a request into DB
var insertRequestStmt = map[string]string{
	"sqlite":   "insert into pending_requests(username, groupname, time_stamp) values (?,?,?);",
	"postgres": "insert into pending_requests(username, groupname, time_stamp) values ($1,$2,$3);",
}

func insertRequestInDB(username string, groupnames []string, state *RuntimeState) error {

	stmtText := insertRequestStmt[state.dbType]
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement")
		log.Fatal(err)
	}
	defer stmt.Close()
	for _, entry := range groupnames {
		IsgroupMember, _, err := state.Userinfo.IsgroupmemberorNot(entry, username)
		if err != nil {
			log.Println(err)
			return err
		}
		if entryExistsorNot(username, entry, state) || IsgroupMember {
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
var deleteEntryStmt = map[string]string{
	"sqlite":   "delete from pending_requests where username= ? and groupname= ?;",
	"postgres": "delete from pending_requests where username=$1 and groupname= $2;",
}

func deleteEntryInDB(username string, groupname string, state *RuntimeState) error {

	stmtText := deleteEntryStmt[state.dbType]
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
var deleteEntryofGroupsStmt = map[string]string{
	"sqlite":   "delete from pending_requests where groupname= ?;",
	"postgres": "delete from pending_requests where groupname= $1;",
}

func deleteEntryofGroupsInDB(groupnames []string, state *RuntimeState) error {

	stmtText := deleteEntryofGroupsStmt[state.dbType]
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
var findrequestsofUserStmt = map[string]string{
	"sqlite":   "select groupname from pending_requests where username=?;",
	"postgres": "select groupname from pending_requests where username=$1;",
}

func findrequestsofUserinDB(username string, state *RuntimeState) ([]string, bool, error) {
	stmtText := findrequestsofUserStmt[state.dbType]
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
var entryExistsorNotStmt = map[string]string{
	"sqlite":   "select * from pending_requests where username=? and groupname=?;",
	"postgres": "select * from pending_requests where username=$1 and groupname=$2;",
}

func entryExistsorNot(username string, groupname string, state *RuntimeState) bool {
	stmtText := entryExistsorNotStmt[state.dbType]
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
var getDBentriesStmt = map[string]string{
	"sqlite":   "select username,groupname from pending_requests;",
	"postgres": "select username,groupname from pending_requests;",
}

func getDBentries(state *RuntimeState) ([][]string, error) {
	stmtText := getDBentriesStmt[state.dbType]
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
