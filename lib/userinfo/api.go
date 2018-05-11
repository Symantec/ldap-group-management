package userinfo

type GroupInfo struct {
	Groupname   string
	Description string
	MemberUid   []string
	Member      []string
	Cn          string
}

type UserInfo interface {
	GetallUsers() (map[string]string, error)

	CreateuserDn(username string) string

	CreategroupDn(groupname string) string

	CreateserviceDn(groupname string) string

	CreateGroup(groupinfo GroupInfo) error

	DeleteGroup(groupnames []string) error

	AddAtributedescription(groupname string) error

	DeleteDescription(groupnames []string) error

	GetallGroups() ([]string, error)

	GetgroupsofUser(username string) ([]string, error)

	GetusersofaGroup(groupname string) ([]string, string, error)

	ParseSuperadmins() []string

	UserisadminOrNot(username string) bool

	GetmaximumGidnumber() (string, error)

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

	ServiceAccountExistsornot(groupname string) (bool, error)

	GetGroupDN(groupname string) (string, error)
}
