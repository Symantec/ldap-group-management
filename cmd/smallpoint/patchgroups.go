package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Symantec/ldap-group-management/lib/userinfo"
)

type UserMembers struct {
	Members   []string
	ManagedBy string
	Mail      string
}

type ServiceAccounts struct {
	Mail string
}

func (state *RuntimeState) initPatchGroups(dlPath string, accountPath string) error {
	if state.Config.Base.AutoPatchGroup == nil {
		mlist := make(map[string]map[string]bool)
		f, err := os.Open(dlPath)
		if err != nil {
			return fmt.Errorf("Error[%s]: Unable to read file %s\n", dlPath, err.Error())
		}
		userScanner := bufio.NewScanner(f)
		dlMembers := make(map[string]*UserMembers)
		dlName := ""
		for userScanner.Scan() {
			if strings.Contains(userScanner.Text(), "#") {
				continue
			} else if len(userScanner.Text()) > 1 {
				if strings.Contains(userScanner.Text(), "cn:") {
					dlName = strings.TrimPrefix(userScanner.Text(), "cn: ")
					if _, ok := dlMembers[dlName]; !ok {
						dlMembers[dlName] = &UserMembers{}
					}
				} else if dlName != "" {
					if strings.Contains(userScanner.Text(), "member:") {
						dlMembers[dlName].Members = append(dlMembers[dlName].Members, strings.Split(strings.TrimPrefix(userScanner.Text(), "member: CN="), ",")[0])
					} else if strings.Contains(userScanner.Text(), "managedBy:") {
						dlMembers[dlName].ManagedBy = strings.Split(strings.TrimPrefix(userScanner.Text(), "managedBy: CN="), ",")[0]
					} else if strings.Contains(userScanner.Text(), "mail:") {
						dlMembers[dlName].Mail = strings.TrimPrefix(userScanner.Text(), "mail: ")
					}
				}
			} else {
				dlName = ""
			}
		}
		if err = userScanner.Err(); err != nil {
			return fmt.Errorf("Error[%s]: Scan file %s\n", dlPath, err.Error())
		}
		af, err := os.Open(accountPath)
		if err != nil {
			return fmt.Errorf("Error[%s]: Unable to read file %s\n", accountPath, err.Error())
		}
		accScanner := bufio.NewScanner(af)
		svcAccounts := make(map[string]*ServiceAccounts)
		cnName := ""
		for accScanner.Scan() {
			if strings.Contains(accScanner.Text(), "#") {
				continue
			} else if len(accScanner.Text()) > 1 {
				if strings.Contains(accScanner.Text(), "cn:") {
					cnName = strings.TrimPrefix(accScanner.Text(), "cn: ")
					svcAccounts[cnName] = &ServiceAccounts{}
				} else if cnName != "" {
					if strings.Contains(accScanner.Text(), "mail:") {
						svcAccounts[cnName].Mail = strings.TrimPrefix(accScanner.Text(), "mail: ")
					}
				}
			} else {
				cnName = ""
			}
		}
		if err = accScanner.Err(); err != nil {
			return fmt.Errorf("Error[%s]: Scan file %s\n", accountPath, err.Error())
		}
		for _, v := range svcAccounts {
			dlname := strings.Split(v.Mail, "@")[0]
			if dlm, ok := dlMembers[dlname]; ok {
				for _, name := range dlm.Members {
					name = strings.Join(strings.Split(strings.ToLower(name), " "), "_")
					if mlist[name] == nil {
						mlist[name] = make(map[string]bool)
					}
					mlist[name][dlname] = true
				}
			}
		}
		state.Config.Base.AutoPatchGroup = mlist
	}
	return nil
}

func (state *RuntimeState) autoPatchGroups(username string) error {
	var err error
	if state.Config.Base.AutoPatchGroup != nil {
		if groups, ok := state.Config.Base.AutoPatchGroup[username]; ok {
			for group, _ := range groups {
				var groupinfo userinfo.GroupInfo
				groupinfo.Groupname = group
				groupinfo.MemberUid = append(groupinfo.MemberUid, username)
				err = state.Userinfo.AddmemberstoExisting(groupinfo)
				if err != nil {
					log.Println(err)
					return err
				}
			}
		}
	}
	return err
}
