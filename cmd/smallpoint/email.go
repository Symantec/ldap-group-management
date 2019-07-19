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
		description, err := state.Userinfo.GetDescriptionvalue(entry)
		if err != nil {
			log.Println(err)
			return err
		}
		if description == "self-managed" {
			usersEmail, err := state.Userinfo.GetEmailofusersingroup(entry)
			if err != nil {
				log.Println(err)
				return err

			}
			state.SuccessRequestemail(username, usersEmail, entry, remoteAddr, userAgent)
		} else {
			usersEmail, err := state.Userinfo.GetEmailofusersingroup(description)
			if err != nil {
				log.Println(err)
				return err

			}
			state.SuccessRequestemail(username, usersEmail, entry, remoteAddr, userAgent)
		}
	}
	return nil
}

const requestAccessMailTemplateText = `Subject: Request access to group {{.Groupname}}
User {{.RequestedUser}} requested access to group {{.Groupname}} (from {{.RemoteAddr}})
Please take a review at https://ae15-smallpoint.phx2.symcpe.net/pending-actions`

//send email for requesting access to a group
func (state *RuntimeState) SuccessRequestemail(requesteduser string, usersEmail []string,
	groupname string, remoteAddr string, userAgent string) error {
	// Connect to the remote SMTP server.
	c, err := smtp.Dial(state.Config.Base.SMTPserver)
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

const requestApproveMailTemplateText = `Subject: Approve access to group {{.Groupname}}
User {{.OtherUser}} approved user {{.RequestedUser}}'s access request to group {{.Groupname}} (from {{.RemoteAddr}})`

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
			err = state.approveRequestemail(requesteduser, username, other_users_email, entry[1], remoteAddr, userAgent)
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
			err = state.approveRequestemail(requesteduser, username, other_users_email, entry[1], remoteAddr, userAgent)
			if err != nil {
				log.Println(err)
				return err
			}
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
const requestRejectMailTemplateText = `Subject: Rejected access to group {{.Groupname}}
User {{.OtherUser}} rejected user {{.RequestedUser}}'s access request to group {{.Groupname}} (from {{.RemoteAddr}})`

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
	c, err := smtp.Dial(state.Config.Base.SMTPserver)
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
