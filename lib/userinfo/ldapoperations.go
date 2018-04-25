package userinfo


type UserInfoLDAPSource struct {
	BindUsername          string `yaml:"bind_username"`
	BindPassword          string `yaml:"bind_password"`
	LDAPTargetURLs        string `yaml:"ldap_target_urls"`
	UserSearchBaseDNs     string `yaml:"user_search_base_dns"`
	UserSearchFilter      string `yaml:"user_search_filter"`
	GroupSearchBaseDNs    string `yaml:"group_search_base_dns"`
	GroupSearchFilter     string `yaml:"group_search_filter"`
	Admins                string `yaml:"super_admins"`
	ServiceAccountBaseDNs string `yaml:"service_search_base_dns"`
}

type GroupInfo struct {
	Groupname   string
	Description string
	MemberUid   []string
	Member      []string
	Cn          string
}


type Operations interface {

	GetallUsers() (map[string]string, error)

	CreateuserDn(username string) string

	CreategroupDn(groupname string) string

	CreateserviceDn(groupname string) string

	CreateGroup(groupinfo GroupInfo) error

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

	AddmemberstoExisting(groupinfo GroupInfo) error

	DeletemembersfromGroup(groupinfo GroupInfo) error

	IsgroupmemberorNot(groupname string, username string) bool

	GetDescriptionvalue(groupname string) (string, error)

	GetEmailofauser(username string) ([]string, error)

	GetEmailofusersingroup(groupname string) ([]string, error)

	CreateServiceAccount(groupinfo GroupInfo) error
}
