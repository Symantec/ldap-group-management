package main

import (
	"github.com/mssola/user_agent"
	"log"
	"net/smtp"
	texttemplate "text/template"
)

////Request Access email  start.....//////

//for request access button
func (state *RuntimeState) SendRequestemail(username string, groupnames []string,
	remoteAddr string, userAgent string) error {
	for _, entry := range groupnames {
		description, err := state.Config.TargetLDAP.GetDescriptionvalue(entry)
		if err != nil {
			log.Println(err)
			return err
		}
		if description == "self-managed" {
			usersEmail, err := state.Config.TargetLDAP.GetEmailofusersingroup(entry)
			if err != nil {
				log.Println(err)
				return err

			}
			state.SuccessRequestemail(username, usersEmail, entry, remoteAddr, userAgent)
		} else {
			usersEmail, err := state.Config.TargetLDAP.GetEmailofusersingroup(entry)
			if err != nil {
				log.Println(err)
				return err

			}
			state.SuccessRequestemail(username, usersEmail, entry, remoteAddr, userAgent)
		}
	}
	return nil
}

const requestAccessMailTemplateText = `Subject: Requesting access for group {{.Groupname}}
User {{.RequestedUser}} has requested access for group {{.Groupname}} (from {{.RemoteAddr}} ({{.Browser}} {{.OS}} ))`

//send email for requesting access to a group
func (state *RuntimeState) SuccessRequestemail(requesteduser string, usersEmail []string,
	groupname string, remoteAddr string, userAgent string) error {
	// Connect to the remote SMTP server.
	c, err := smtp.Dial(state.Config.Base.SMTPserver)
	if err != nil {
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
		return err
	}
	defer wc.Close()
	//get browser details
	ua := user_agent.New(userAgent)
	uaName, _ := ua.Browser()

	mailData := mailAttributes{
		RequestedUser: requesteduser,
		Groupname:     groupname,
		RemoteAddr:    remoteAddr,
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

const requestApproveMailTemplateText = `Subject: Regarding access for group {{.Groupname}}
User {{.OtherUser}} has Approved access to user {{.RequestedUser}} for group {{.Groupname}} (from {{.RemoteAddr}} ({{.Browser}} {{.OS}} ))`

//send approve email
func (state *RuntimeState) sendApproveemail(username string,
	userPair [][]string, remoteAddr string, userAgent string) error {
	userEmail, err := state.Config.TargetLDAP.GetEmailofauser(username)
	if err != nil {
		log.Println(err)
		return err
	}
	for _, entry := range userPair {
		var targetAddress []string
		targetAddress = append(targetAddress, userEmail[0])
		requesteduser := entry[0]
		otheruserEmail, err := state.Config.TargetLDAP.GetEmailofauser(requesteduser)
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
		targetAddress = nil
	}
	return nil
}

//for approving requests in pending actions main email function
func (state *RuntimeState) approveRequestemail(requesteduser string, otheruser string, usersEmail []string,
	groupname string, remoteAddr string, userAgent string) error {
	// Connect to the remote SMTP server.
	c, err := smtp.Dial(state.Config.Base.SMTPserver)
	if err != nil {
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
		return err
	}
	defer wc.Close()
	//get browser details
	ua := user_agent.New(userAgent)
	uaName, _ := ua.Browser()

	mailData := mailAttributes{
		RequestedUser: requesteduser,
		Groupname:     groupname,
		RemoteAddr:    remoteAddr,
		Browser:       uaName,
		OS:            ua.OS(),
		OtherUser:     otheruser}

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
const requestRejectMailTemplateText = `Subject: Regarding access for group {{.Groupname}}
User {{.OtherUser}} has Rejected access to user {{.RequestedUser}} for group {{.Groupname}} (from {{.RemoteAddr}} ({{.Browser}} {{.OS}} ))`

//send reject email
func (state *RuntimeState) sendRejectemail(username string, userPair [][]string,
	remoteAddr string, userAgent string) error {
	userEmail, err := state.Config.TargetLDAP.GetEmailofauser(username)
	if err != nil {
		log.Println(err)
		return err
	}
	for _, entry := range userPair {
		var targetAddress []string
		targetAddress = append(targetAddress, userEmail[0])
		requesteduser := entry[0]
		otheruserEmail, err := state.Config.TargetLDAP.GetEmailofauser(requesteduser)
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
		targetAddress = nil
	}
	return nil
}

func (state *RuntimeState) RejectRequestemail(requesteduser string, otheruser string, usersEmail []string,
	groupname string, remoteAddr string, userAgent string) error {
	// Connect to the remote SMTP server.
	c, err := smtp.Dial(state.Config.Base.SMTPserver)
	if err != nil {
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
		return err
	}
	defer wc.Close()
	//get browser details
	ua := user_agent.New(userAgent)
	uaName, _ := ua.Browser()

	mailData := mailAttributes{
		RequestedUser: requesteduser,
		Groupname:     groupname,
		RemoteAddr:    remoteAddr,
		Browser:       uaName,
		OS:            ua.OS(),
		OtherUser:     otheruser}

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