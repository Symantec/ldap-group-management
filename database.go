package main

import (
	"database/sql"
	"log"
	"time"
	_"github.com/mattn/go-sqlite3"

)

//Initialsing database
func initDB(state *RuntimeState) (err error) {

	state.dbType = "sqlite3"
	state.db, err = sql.Open("sqlite3", "./ldap-group-management1.db")
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
func (state *RuntimeState) insertRequestInDB(username string,groupname []string) error {

	stmtText := "insert into pending_requests(username, groupname, time_stamp) values (?,?,?)"
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement")
		log.Fatal(err)
	}
	defer stmt.Close()
	for _, entry := range groupname {
		if state.entryExistsorNot(username, entry) || state.isGroupMemberorNot(entry,username){
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
func (state *RuntimeState) deleteEntryInDB(username string,groupname string) error{

	stmtText :="delete from pending_requests where username= ? and groupname= ?;"
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement")
		log.Fatal(err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(username,groupname)
	if err != nil {
		return err
	}
	return nil

}

//deleting all groups in DB which are deleted from Target LDAP
func (state *RuntimeState) deleteEntryofGroupsInDB(groupnames []string) error {

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
func (state *RuntimeState) findrequestsofUserinDB(username string) ([]string,bool,error) {
	stmtText:="select groupname from pending_requests where username=?;"
	stmt,err:=state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement")
		log.Fatal(err)
	}
	defer stmt.Close()
	var groupname []string
	rows,err := stmt.Query(username)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			log.Printf("err='%s'", err)
			defer rows.Close()
			return nil,false,nil
		} else {
			log.Printf("Problem with db ='%s'", err)
			defer rows.Close()
			return nil,false, err
		}
	}
	for rows.Next(){
		var group_Name string
		err=rows.Scan(&group_Name)
		groupname=append(groupname,group_Name)
	}
	defer rows.Close()

	return groupname,true, nil

}

//looks in the DB if the entry already exists or not
func (state *RuntimeState) entryExistsorNot(username string,groupname string)bool{
	stmt_Text:="select * from pending_requests where username=? and groupname=?;"
	stmt,err:=state.db.Prepare(stmt_Text)
	if err != nil {
		log.Print("Error Preparing statement")
		log.Fatal(err)
	}
	defer stmt.Close()
	rows,err:=stmt.Query(username,groupname)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			log.Printf("err='%s'", err)
			return false
		} else {
			log.Printf("Problem with db ='%s'", err)
			return false
		}
	}
	if rows.Next() {
		defer rows.Close()
		return true
	}
	defer rows.Close()
	return false
}


//(username,groupname) get whole db entries.
func (state *RuntimeState) getDB_entries()([][]string,error){
	stmtText:="select username,groupname from pending_requests;"
	stmt,err:=state.db.Prepare(stmtText)
	if err != nil {
		log.Print("Error Preparing statement")
		log.Fatal(err)
	}
	defer stmt.Close()
	var entry [][]string
	rows,err:=stmt.Query()
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			log.Printf("err='%s'", err)
			defer rows.Close()
			return nil,err
		} else {
			log.Printf("Problem with db ='%s'", err)
			defer rows.Close()
			return nil,err
		}
	}
	var each_entry1 string
	var each_entry2 string
	for rows.Next(){
		err=rows.Scan(&each_entry1,&each_entry2)
		var each_entry =[]string{each_entry1,each_entry2}
		entry=append(entry,each_entry)
	}
	defer rows.Close()
	return entry,nil
}


