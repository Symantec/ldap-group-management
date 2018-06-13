package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

// parse HTML templates and pass in a list of file names, and get a template

func generateHTML(w http.ResponseWriter, data interface{}, templatespath string, filenames ...string) {
	var files []string
	for _, file := range filenames {
		files = append(files, fmt.Sprintf("%s/%s.html", templatespath, file))
	}
	templates := template.Must(template.ParseFiles(files...))
	templates.ExecuteTemplate(w, "index", data)
}
