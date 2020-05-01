package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/smtp"
	"strings"
	texttemplate "text/template"

	"github.com/mssola/user_agent"
)

// From: https://blog.andreiavram.ro/golang-unit-testing-interfaces/
type smtpDialer interface {
	Close() error
	Data() (io.WriteCloser, error)
	//Hello(localName string) error
	Mail(from string) error
	Rcpt(to string) error
}

var (
	smtpClient = func(addr string) (smtpDialer, error) {
		// Dial the tcp connection
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}

		// Connect to the SMTP server
		c, err := smtp.NewClient(conn, addr)
		if err != nil {
			return nil, err
		}

		return c, nil
	}
)

////Request Access email  start.....//////

//for request access button
func (state *RuntimeState) SendRequestemail(username string, groupnames []string,
	remoteAddr, userAgent string) error {
	for _, entry := range groupnames {
		managerEntry, err := state.Userinfo.GetDescriptionvalue(entry)
		if err != nil {
			log.Println(err)
			return err
		}
		log.Printf("managerEntry:%s", managerEntry)
		if managerEntry == "" {
			log.Printf("no manager for group %s.", entry)
			return fmt.Errorf("no manager for group %s", entry)

		}
		var usersEmail []string
		if managerEntry == "self-managed" {
			managerEntry = entry
		}
		usersEmail, err = state.Userinfo.GetEmailofusersingroup(managerEntry)
		if err != nil {
			log.Printf("SendRequestemail: GetEmailofusersingroup err:%s", err)
			return err

		}
		state.SuccessRequestemail(username, usersEmail, entry, remoteAddr, userAgent)
	}
	return nil
}

// TODO: @SLR9511: The Hostname should be a param, please servisit
// const requestAccessMailTemplateText = `Subject: Request access to group {{.Groupname}}
// User {{.RequestedUser}} requested access to group {{.Groupname}}.
// Please take a review at {{.Hostname}}/pending-actions`

const requestAccessMailTemplateText = "From: {{.RemoteAddr}}\r\n" + "Subject: Request access to group {{.Groupname}}\r\n" + "\r\n" + "User {{.RequestedUser}} requested access to group {{.Groupname}}.\r\n" + "Please take a review at {{.Hostname}}/pending-actions\r\n"

func (state *RuntimeState) SendMail(requesteduser string, otheruser string, usersEmail []string,
	groupname, remoteAddr, userAgent string, tmmplateText string) error {
	auth := smtp.PlainAuth("", state.Config.Base.SMTPUsername, state.Config.Base.SMTPPassword, strings.Split(state.Config.Base.SMTPserver, ":")[0])
	//get browser details
	ua := user_agent.New(userAgent)
	uaName, _ := ua.Browser()

	mailData := mailAttributes{
		RequestedUser: requesteduser,
		RemoteAddr:    remoteAddr,
		Groupname:     groupname,
		Hostname:      state.Config.Base.Hostname,
		Browser:       uaName,
		OS:            ua.OS(),
		OtherUser:     otheruser}

	templ, err := texttemplate.New("mailbody").Parse(tmmplateText)
	if err != nil {
		return err
	}
	var tpl bytes.Buffer
	err = templ.Execute(&tpl, mailData)
	if err != nil {
		return err
	}
	err = smtp.SendMail(state.Config.Base.SMTPserver, auth, state.Config.Base.SmtpSenderAddress, usersEmail, tpl.Bytes())
	return err

}

//send email for requesting access to a group
func (state *RuntimeState) SuccessRequestemail(requesteduser string, usersEmail []string,
	groupname, remoteAddr, userAgent string) error {
	// Connect to the remote SMTP server.
	if len(state.Config.Base.SMTPPassword) > 0 {
		return state.SendMail(requesteduser, "", usersEmail, groupname, remoteAddr, userAgent, requestAccessMailTemplateText)
	}

	c, err := smtpClient(state.Config.Base.SMTPserver)
	if err != nil {
		log.Println(err)
		return err
	}
	defer c.Close()
	// Set the sender and recipient.
	c.Mail(state.Config.Base.SmtpSenderAddress)
	for _, recipient := range usersEmail {
		//c.Rcpt("recipient@example.net")
		c.Rcpt(recipient)
	}
	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		log.Println(err)
		return err
	}
	defer wc.Close()
	//get browser details
	ua := user_agent.New(userAgent)
	uaName, _ := ua.Browser()

	mailData := mailAttributes{
		RequestedUser: requesteduser,
		RemoteAddr:    remoteAddr,
		Groupname:     groupname,
		Hostname:      state.Config.Base.Hostname,
		Browser:       uaName,
		OS:            ua.OS(),
		OtherUser:     ""}

	templ, err := texttemplate.New("mailbody").Parse(requestAccessMailTemplateText)
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

// const requestApproveMailTemplateText = `Subject: Approve access to group {{.Groupname}}
// User {{.OtherUser}} approved user {{.RequestedUser}}'s access request to group {{.Groupname}}`
const requestApproveMailTemplateText = "From: {{.RemoteAddr}}\r\n" + "Subject: Approve access to group {{.Groupname}}\r\n" + "\r\n" + "User {{.OtherUser}} approved user {{.RequestedUser}}'s access request to group {{.Groupname}.\r\n"

//send approve email
func (state *RuntimeState) sendApproveemail(username string,
	userPair [][]string, remoteAddr string, userAgent string) error {
	userEmail, err := state.Userinfo.GetEmailofauser(username)
	if err != nil {
		log.Println(err)
		return err
	}
	for _, entry := range userPair {
		var targetAddress []string
		targetAddress = append(targetAddress, userEmail[0])
		requesteduser := entry[0]
		otheruserEmail, err := state.Userinfo.GetEmailofauser(requesteduser)
		if err != nil {
			log.Println(err)
			return err
		}
		targetAddress = append(targetAddress, otheruserEmail[0])
		err = state.approveRequestemail(requesteduser, username, targetAddress, entry[1], remoteAddr, userAgent)
		if err != nil {
			log.Println(err)
			return err
		}
		managerGroupName, err := state.Userinfo.GetDescriptionvalue(entry[1])
		if err != nil {
			log.Println(err)
			return err
		}
		if managerGroupName == "self-managed" {
			managerGroupName = entry[1]
		}
		otherUsersMail, err := state.Userinfo.GetEmailofusersingroup(managerGroupName)
		if err != nil {
			log.Println(err)
			return err
		}
		err = state.approveRequestemail(requesteduser, username, otherUsersMail, entry[1], remoteAddr, userAgent)
		if err != nil {
			log.Println(err)
			return err
		}
		targetAddress = nil
	}
	return nil
}

//for approving requests in pending actions main email function
func (state *RuntimeState) approveRequestemail(requesteduser string, otheruser string, usersEmail []string,
	groupname string, remoteAddr string, userAgent string) error {
	if len(state.Config.Base.SMTPPassword) > 0 {
		return state.SendMail(requesteduser, otheruser, usersEmail, groupname, remoteAddr, userAgent, requestApproveMailTemplateText)
	}
	// Connect to the remote SMTP server.
	c, err := smtpClient(state.Config.Base.SMTPserver)
	if err != nil {
		log.Println(err)
		return err
	}
	defer c.Close()
	// Set the sender and recipient.
	c.Mail(state.Config.Base.SmtpSenderAddress)
	for _, recipient := range usersEmail {
		//c.Rcpt("recipient@example.net")
		c.Rcpt(recipient)
	}
	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		log.Println(err)
		return err
	}
	defer wc.Close()
	//get browser details
	ua := user_agent.New(userAgent)
	uaName, _ := ua.Browser()

	mailData := mailAttributes{
		RequestedUser: requesteduser,
		RemoteAddr:    remoteAddr,
		Groupname:     groupname,
		Browser:       uaName,
		OS:            ua.OS(),
		OtherUser:     otheruser,
		Hostname:      state.Config.Base.Hostname}

	templ, err := texttemplate.New("mailbody").Parse(requestApproveMailTemplateText)
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
// const requestRejectMailTemplateText = `Subject: Rejected access to group {{.Groupname}}
// User {{.OtherUser}} rejected user {{.RequestedUser}}'s access request to group {{.Groupname}}`

const requestRejectMailTemplateText = "From: {{.RemoteAddr}}\r\n" + "Subject: Rejected access to group {{.Groupname}}\r\n" + "\r\n" + "User {{.OtherUser}} rejected user {{.RequestedUser}}'s access request to group {{.Groupname}}.\r\n"

//send reject email
func (state *RuntimeState) sendRejectemail(username string, userPair [][]string,
	remoteAddr string, userAgent string) error {
	userEmail, err := state.Userinfo.GetEmailofauser(username)
	if err != nil {
		log.Println(err)
		return err
	}
	for _, entry := range userPair {
		var targetAddress []string
		targetAddress = append(targetAddress, userEmail[0])
		requesteduser := entry[0]
		otheruserEmail, err := state.Userinfo.GetEmailofauser(requesteduser)
		if err != nil {
			log.Println(err)
			return err
		}
		targetAddress = append(targetAddress, otheruserEmail[0])
		err = state.RejectRequestemail(requesteduser, username, targetAddress, entry[1], remoteAddr, userAgent)
		if err != nil {
			log.Println(err)
			return err
		}
		description, err := state.Userinfo.GetDescriptionvalue(entry[1])
		if err != nil {
			log.Println(err)
			return err
		}
		if description == "self-managed" {
			other_users_email, err := state.Userinfo.GetEmailofusersingroup(entry[1])
			if err != nil {
				log.Println(err)
				return err
			}
			err = state.RejectRequestemail(requesteduser, username, other_users_email, entry[1], remoteAddr, userAgent)
			if err != nil {
				log.Println(err)
				return err
			}
		} else {
			other_users_email, err := state.Userinfo.GetEmailofusersingroup(description)
			if err != nil {
				log.Println(err)
				return err
			}
			err = state.RejectRequestemail(requesteduser, username, other_users_email, entry[1], remoteAddr, userAgent)
			if err != nil {
				log.Println(err)
				return err
			}
		}
		targetAddress = nil
	}
	return nil
}

func (state *RuntimeState) RejectRequestemail(requesteduser string, otheruser string, usersEmail []string,
	groupname string, remoteAddr string, userAgent string) error {
	// Connect to the remote SMTP server.
	if len(state.Config.Base.SMTPPassword) > 0 {
		return state.SendMail(requesteduser, otheruser, usersEmail, groupname, remoteAddr, userAgent, requestRejectMailTemplateText)
	}

	c, err := smtpClient(state.Config.Base.SMTPserver)
	if err != nil {
		log.Println(err)
		return err
	}
	defer c.Close()
	// Set the sender and recipient.
	c.Mail(state.Config.Base.SmtpSenderAddress)
	for _, recipient := range usersEmail {
		//c.Rcpt("recipient@example.net")
		c.Rcpt(recipient)
	}
	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		log.Println(err)
		return err
	}
	defer wc.Close()
	//get browser details
	ua := user_agent.New(userAgent)
	uaName, _ := ua.Browser()

	mailData := mailAttributes{
		RequestedUser: requesteduser,
		RemoteAddr:    remoteAddr,
		Groupname:     groupname,
		Browser:       uaName,
		OS:            ua.OS(),
		OtherUser:     otheruser,
		Hostname:      state.Config.Base.Hostname}

	templ, err := texttemplate.New("mailbody").Parse(requestRejectMailTemplateText)
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
