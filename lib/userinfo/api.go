package userinfo

import (
	"errors"
)

var GroupDoesNotExist = errors.New("Group does not exist")
var UserDoesNotExist = errors.New("User does not exist")
var UserDoesNotHaveEmail = errors.New("User does not have mail")
var UserDoesNotHaveGivenName = errors.New("User does not have givenName")

type AccountType int

type GroupInfo struct {
	Groupname   string
	Description string
	MemberUid   []string
	Member      []string
	Cn          string
	Mail        string
	LoginShell  string
}

type UserInfo interface {
	GetallUsers() ([]string, error)

	CreateGroup(groupinfo GroupInfo) error

	DeleteGroup(groupnames []string) error

	ChangeDescription(groupname string, managegroup string) error

	GetallGroups() ([]string, error)

	GetgroupsofUser(username string) ([]string, error)

	GetusersofaGroup(groupname string) ([]string, string, error)

	GetGroupUsersAndManagers(groupname string) ([]string, []string, string, error)

	ParseSuperadmins() []string

	UserisadminOrNot(username string) bool

	AddmemberstoExisting(groupinfo GroupInfo) error

	DeletemembersfromGroup(groupinfo GroupInfo) error

	IsgroupmemberorNot(groupname string, username string) (bool, string, error)

	GetDescriptionvalue(groupname string) (string, error)

	GetEmailofauser(username string) ([]string, error)

	GetEmailofusersingroup(groupname string) ([]string, error)

	CreateServiceAccount(groupinfo GroupInfo) error

	IsgroupAdminorNot(username string, groupname string) (bool, error)

	UsernameExistsornot(username string) (bool, error)

	GroupnameExistsornot(groupname string) (bool, string, error)

	ServiceAccountExistsornot(groupname string) (bool, string, error)

	GetAllGroupsManagedBy() ([][]string, error)

	GetGroupsInfoOfUser(groupdn string, username string) ([][]string, error)

	GetGroupandManagedbyAttributeValue(groupnames []string) ([][]string, error)

	CreateUser(username string, givenName, email []string) error

	GetUserAttributes(username string) ([]string, []string, error)
}
