package main

import (
	"fmt"
	"net/http"
	"html/template"
)

// parse HTML templates and pass in a list of file names, and get a template

func parseTemplateFiles(filenames ...string) (t *template.Template) {
	var files []string
	t = template.New("index")
	for _, file := range filenames {
		files = append(files, fmt.Sprintf("templates/%s.html", file))
	}
	t = template.Must(t.ParseFiles(files...))
	return
}



func generateHTML(w http.ResponseWriter, data interface{}, filenames ...string) {
	var files []string
	for _, file := range filenames {
		files = append(files, fmt.Sprintf("templates/%s.html", file))
	}

	templates := template.Must(template.ParseFiles(files...))
	templates.ExecuteTemplate(w, "index", data)
}

