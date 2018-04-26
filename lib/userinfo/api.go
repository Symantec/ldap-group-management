package userinfo


import "ldap-group-management/lib/userinfo/ldapuserinfo"

type Operations interface {

	GetallUsers() (map[string]string, error)

	CreateuserDn(username string) string

	CreategroupDn(groupname string) string

	CreateserviceDn(groupname string) string

	CreateGroup(groupinfo ldapuserinfo.GroupInfo) error

	DeleteGroup(groupnames []string) error

	AddAtributedescription(groupname string) error

	DeleteDescription(groupnames []string) error

	UserInfo(Userdn string) ([]string, error)

	GetallGroups() ([]string, error)

	GetgroupsofUser(username string) ([]string, error)

	GetusersofaGroup(groupname string) ([][]string, error)

	ParseSuperadmins() []string

	UserisadminOrNot(username string) bool

	GetmaximumGidnumber() (string, error)

	AddmemberstoExisting(groupinfo ldapuserinfo.GroupInfo) error

	DeletemembersfromGroup(groupinfo ldapuserinfo.GroupInfo) error

	IsgroupmemberorNot(groupname string, username string) bool

	GetDescriptionvalue(groupname string) (string, error)

	GetEmailofauser(username string) ([]string, error)

	GetEmailofusersingroup(groupname string) ([]string, error)

	CreateServiceAccount(groupinfo ldapuserinfo.GroupInfo) error
}
