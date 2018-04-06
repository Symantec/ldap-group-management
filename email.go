package main

import (
	"net/smtp"
	"log"
	"github.com/mssola/user_agent"
	texttemplate "text/template"

)

////Request Access email  start.....//////

//for request access button
func (state *RuntimeState) send_request_email(username string,groupnames []string,remoteAddr string,userAgent string)error{
	for _,entry:=range groupnames{
		description,err:=state.getDescription_value(entry)
		if err!=nil{
			log.Println(err)
			return err
		}
		if description=="self-managed"{
			users_email,err:=state.getEmailofUsersinGroup(entry)
			if err!=nil{
				log.Println(err)
				return err

			}
			state.success_request_email(username,users_email,entry,remoteAddr,userAgent)
		}else{
			users_email,err:=state.getEmailofUsersinGroup(entry)
			if err!=nil{
				log.Println(err)
				return err

			}
			state.success_request_email(username,users_email,entry,remoteAddr,userAgent)
		}
	}
	return nil
}


const requestaccess_mailTemplateText = `Subject: Requesting access for group {{.Groupname}}

User {{.RequestedUser}} has requested access for group {{.Groupname}} (from {{.RemoteAddr}} ({{.Browser}} {{.OS}} ))`

//send email for requesting access to a group
func (state *RuntimeState) success_request_email(requesteduser string,users_email []string,groupname string,remoteAddr string,userAgent string) error{
	// Connect to the remote SMTP server.
	c, err := smtp.Dial("smtp.example.net:25")
	if err != nil {
		return err
	}
	defer c.Close()
	// Set the sender and recipient.
	c.Mail("ldap-group-manager-noreply@example.net")
	for _, recipient := range users_email {
		//c.Rcpt("recipient@example.net")
		c.Rcpt(recipient)
	}
	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		log.Fatal(err)
	}
	defer wc.Close()
	//get browser details
	ua := user_agent.New(userAgent)
	uaName, _ := ua.Browser()

	mailData := mailAttributes{
		RequestedUser:    requesteduser,
		Groupname:groupname,
		RemoteAddr:     remoteAddr,
		Browser:        uaName,
		OS:             ua.OS(),
		OtherUser:""}

	templ, err := texttemplate.New("mailbody").Parse(requestaccess_mailTemplateText)
	if err != nil {
		log.Fatal(err)
	}
	err = templ.Execute(wc, mailData)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}
////Request Access email  end.....//////

////Approve email  start.....//////

const requestapprove_mailTemplateText = `Subject: Regarding access for group {{.Groupname}}

User {{.OtherUser}} has Approved access to user {{.RequestedUser}} for group {{.Groupname}} (from {{.RemoteAddr}} ({{.Browser}} {{.OS}} ))`

//send approve email
func (state *RuntimeState) send_approve_email(username string,user_pair [][]string,remoteAddr string,userAgent string) error{
	user_email,err:=state.getEmailofaUser(username)
	if err!=nil{
		log.Println(err)
		return err
	}
	for _,entry:=range user_pair{
		var target_address []string
		target_address=append(target_address,user_email[0])
		requesteduser:=entry[0]
		otheruser_email,err:=state.getEmailofaUser(requesteduser)
		if err!=nil{
			log.Println(err)
			return err
		}
		target_address=append(target_address,otheruser_email[0])
		err=state.approve_request_email(requesteduser,username,target_address,entry[1],remoteAddr,userAgent)
		if err!=nil{
			log.Println(err)
			return err
		}
		target_address=nil
	}
	return nil
}

//for approving requests in pending actions main email function
func (state *RuntimeState) approve_request_email(requesteduser string,otheruser string,users_email []string,groupname string,remoteAddr string,userAgent string) error{
	// Connect to the remote SMTP server.
	c, err := smtp.Dial("smtp.example.net:25")
	if err != nil {
		return err
	}
	defer c.Close()
	// Set the sender and recipient.
	c.Mail("ldap-group-manager-noreply@example.net")
	for _, recipient := range users_email {
		//c.Rcpt("recipient@example.net")
		c.Rcpt(recipient)
	}
	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		log.Fatal(err)
	}
	defer wc.Close()
	//get browser details
	ua := user_agent.New(userAgent)
	uaName, _ := ua.Browser()

	mailData := mailAttributes{
		RequestedUser:    requesteduser,
		Groupname:groupname,
		RemoteAddr:     remoteAddr,
		Browser:        uaName,
		OS:             ua.OS(),
		OtherUser:otheruser}

	templ, err := texttemplate.New("mailbody").Parse(requestapprove_mailTemplateText)
	if err != nil {
		log.Fatal(err)
	}
	err = templ.Execute(wc, mailData)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}
////Approve email  end.....//////



////Reject email  start.....//////
const requestreject_mailTemplateText = `Subject: Regarding access for group {{.Groupname}}

User {{.OtherUser}} has Rejected access to user {{.RequestedUser}} for group {{.Groupname}} (from {{.RemoteAddr}} ({{.Browser}} {{.OS}} ))`

//send reject email
func (state *RuntimeState) send_reject_email(username string,user_pair [][]string,remoteAddr string,userAgent string) error{
	user_email,err:=state.getEmailofaUser(username)
	if err!=nil{
		log.Println(err)
		return err
	}
	for _,entry:=range user_pair{
		var target_address []string
		target_address=append(target_address,user_email[0])
		requesteduser:=entry[0]
		otheruser_email,err:=state.getEmailofaUser(requesteduser)
		if err!=nil{
			log.Println(err)
			return err
		}
		target_address=append(target_address,otheruser_email[0])
		err=state.reject_request_email(requesteduser,username,target_address,entry[1],remoteAddr,userAgent)
		if err!=nil{
			log.Println(err)
			return err
		}
		target_address=nil
	}
	return nil
}


func (state *RuntimeState) reject_request_email(requesteduser string,otheruser string,users_email []string,groupname string,remoteAddr string,userAgent string) error{
	// Connect to the remote SMTP server.
	c, err := smtp.Dial("smtp.example.net:25")
	if err != nil {
		return err
	}
	defer c.Close()
	// Set the sender and recipient.
	c.Mail("ldap-group-manager-noreply@example.net")
	for _, recipient := range users_email {
		//c.Rcpt("recipient@example.net")
		c.Rcpt(recipient)
	}
	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		log.Fatal(err)
	}
	defer wc.Close()
	//get browser details
	ua := user_agent.New(userAgent)
	uaName, _ := ua.Browser()

	mailData := mailAttributes{
		RequestedUser:    requesteduser,
		Groupname:groupname,
		RemoteAddr:     remoteAddr,
		Browser:        uaName,
		OS:             ua.OS(),
		OtherUser:otheruser}

	templ, err := texttemplate.New("mailbody").Parse(requestreject_mailTemplateText)
	if err != nil {
		log.Fatal(err)
	}
	err = templ.Execute(wc, mailData)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

///// reject email end/////

/// Email function end////

