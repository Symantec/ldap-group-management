package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"github.com/Symantec/keymaster/lib/authutil"
	"time"
	"gopkg.in/ldap.v2"
	"errors"
	"log"
)

// parse HTML templates and pass in a list of file names, and get a template

func generateHTML(w http.ResponseWriter, data interface{}, filenames ...string) {
	var files []string
	for _, file := range filenames {
		files = append(files, fmt.Sprintf("templates/%s.html", file))
	}

	templates := template.Must(template.ParseFiles(files...))
	templates.ExecuteTemplate(w, "index", data)
}

func (state *RuntimeState) GetTargetLDAPConnection()(*ldap.Conn,error) {
	var ldapURL []*url.URL
	for _, ldapURLString := range strings.Split(state.Config.TargetLDAP.LDAPTargetURLs, ",") {
		newURL, err := authutil.ParseLDAPURL(ldapURLString)
		if err != nil {
			log.Println(err)
			continue
		}
		ldapURL = append(ldapURL, newURL)
	}

	for _, TargetLdapUrl := range ldapURL {
		conn, _, err := GetLDAPConnection(*TargetLdapUrl, ldapTimeoutSecs, nil)

		if err != nil {
			log.Println(err)
			continue
		}
		timeout := time.Duration(time.Duration(ldapTimeoutSecs) * time.Second)
		conn.SetTimeout(timeout)
		conn.Start()

		err = conn.Bind(state.Config.TargetLDAP.BindUsername, state.Config.TargetLDAP.BindPassword)
		if err != nil {
			log.Println(err)
			continue
		}
		return conn, nil
	}
	return nil,errors.New("cannot connect to LDAP server")
}
