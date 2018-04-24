package main

type Operations interface {
	GetallUsers() (map[string]string, error)

	CreateuserDn(username string) string

	CreategroupDn(groupname string) string

	CreateserviceDn(groupname string) string

	CreateGroup(groupinfo groupInfo) error

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

	AddmemberstoExisting(groupinfo groupInfo) error

	DeletemembersfromGroup(groupinfo groupInfo) error

	IsgroupmemberorNot(groupname string, username string) bool

	GetDescriptionvalue(groupname string) (string, error)

	GetEmailofauser(username string) ([]string, error)

	GetEmailofusersingroup(groupname string) ([]string, error)

	CreateServiceAccount(groupinfo groupInfo) error
}
