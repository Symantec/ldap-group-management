package main

const commonCSSText = `
{{define "commonCSS"}}
    <style>
        html,body,h1,h2,h3,h4,h5 {font-family: "Raleway", sans-serif}

    </style>
    <style type="text/css" media="screen">
        @import url("/css/new.css");
        @import url("https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css");
        @import url("https://cdn.datatables.net/1.10.16/css/jquery.dataTables.min.css");
        @import url("https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css");
        @import url("https://cdn.datatables.net/fixedcolumns/3.2.4/css/fixedColumns.dataTables.min.css");
        @import url("https://cdn.datatables.net/select/1.2.5/css/select.dataTables.min.css");
    </style>{{end}}`

const commonJSText = `
{{define "commonJS"}}
    <script src="https://code.jquery.com/jquery-3.3.1.js"
            integrity="sha256-2Kok7MbOyxpgUVvAk/HJ2jigOSYS2auK4Pfzbm7uH60="
            crossorigin="anonymous"></script>
    <script src="https://cdn.datatables.net/1.10.16/js/jquery.dataTables.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
    <script src="https://cdn.datatables.net/select/1.2.5/js/dataTables.select.min.js"></script>
    <script type="text/javascript" src="/js/newtable.js"></script>
    <script type="text/javascript" src="/js/sidebar.js"></script>
{{end}}
`

const commonHeadText = `
{{define "commonHead"}}
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>{{.Title}}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    {{template "commonCSS"}}
    {{template "commonJS"}}
    {{if .JSSources -}}
    {{- range .JSSources }}
    <script type="text/javascript" src="{{.}}"></script>
    {{- end}}
    {{- end}}
{{end}}
`

const headerHTMLText = `
{{define "header"}}
<!-- Top container -->
<div class="w3-bar w3-top w3-new-blue w3-large" style="z-index: 4">
<button class="w3-bar-item w3-button w3-hide-large w3-hover-none w3-hover-text-light-grey" id="hamburger_menu_button"><i class="fa fa-bars"></i> &nbsp;Menu</button>
    <div>
        <img src="/images/darkBG.svg" alt="CPE Logo" style="height: 28px">
        <span class="w3-bar-item w3-right w3-text-new-white"><strong><b>LDAP GROUP MANAGEMENT</b></strong></span>
    </div>
</div>
<div id="side">
{{template "sidebar" .}}
</div>

<!-- Overlay effect when opening sidebar on small screens -->
<div class="w3-overlay w3-hide-large w3-animate-opacity"  style="cursor:pointer" title="close side menu" id="myOverlay"></div>
{{end}}`

const footerHTMLText = `
{{define "footer"}}
        <footer class="w3-container w3-padding-16 w3-light-grey w3-bottom">
            <hr>
            <p>Copyright 2018-2019 Symantec Corporation. | <a href="https://confluence.ges.symantec.com" target="_blank">Documentation</a></p>
        </footer>
        <!-- End page content -->
{{end}}`

const sidebarHTMLText = `
{{define "sidebar"}}

<nav class="w3-sidebar w3-collapse w3-white w3-animate-left" style="z-index:3;width:300px;" id="mySidebar"><br>
    <div class="w3-container w3-row">
        <div class="w3-col s4">
            <img src="/images/avatar2.png" class="w3-circle w3-margin-right" style="width:46px">
        </div>
        <div class="w3-col s8 w3-bar">
            <span>Welcome, <strong>{{.UserName}}</strong></span><br>
        </div>
    </div>
    <hr>
    <div class="w3-container">
        <h5>Dashboard</h5>
    </div>
    <div class="w3-bar-block">
        <a href="/" class="w3-bar-item w3-button w3-padding"><i class="fa fa-users fa-fw"></i>&nbsp; My Groups</a>
        <a href="/allGroups" class="w3-bar-item w3-button w3-padding"><i class="fa fa-users fa-fw"></i>&nbsp; All LDAP Groups</a>
        <a href="/my_managed_groups" class="w3-bar-item w3-button w3-padding"><i class="fa fa-users fa-fw"></i>&nbsp; My Managed Groups</a>
	<a href="/pending-actions" class="w3-bar-item w3-button w3-padding"><i class="fa fa-cog fa-fw"></i>&nbsp; My Pending Actions</a>
        <a href="/pending-requests" class="w3-bar-item w3-button w3-padding"><i class="fa fa-cog fa-fw"></i>&nbsp; My Pending Requests</a>
        {{if .IsAdmin}}
        <a href="/create_group" class="w3-bar-item w3-button w3-padding"><i class="fa fa-users fa-fw"></i>&nbsp; Create Group</a>
        <a href="/delete_group" class="w3-bar-item w3-button w3-padding"><i class="fa fa-users fa-fw"></i>&nbsp; Delete Group</a>
        <a href="/create_serviceaccount" class="w3-bar-item w3-button w3-padding"><i class="fa fa-users fa-fw"></i>&nbsp; Create Service Account</a>
        <a href="/change_owner" class="w3-bar-item w3-button w3-padding"><i class="fa fa-users fa-fw"></i>&nbsp; Change Group Ownership(RegExp)</a>
        {{end}}
        <a href="/addmembers" class="w3-bar-item w3-button w3-padding"><i class="fa fa-users fa-fw"></i>&nbsp; Add Members to Group</a>
        <a href="/deletemembers" class="w3-bar-item w3-button w3-padding"><i class="fa fa-users fa-fw"></i>&nbsp; Remove Members from Group</a>

        <br><br>
    </div>
</nav>
{{end}}
`

type myGroupsPageData struct {
	Title   string
	IsAdmin bool

	UserName string
	/*  // These is the old template data
	Groups              [][]string
	Users               []string
	PendingActions      [][]string
	GroupName           string
	GroupManagedbyValue string
	GroupUsers          []string
	*/
	JSSources []string
}

const myGroupsPageText = `
{{define "myGroupsPage"}}
<html>

<head>
    {{template "commonHead" . }}
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">
  <header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>{{.Title}}</b>
        <button class="w3-button w3-right w3-text-new-white w3-red" id="length_btn" data-toggle="modal" data-target="#myModal">Exit Group</button>
        <div class="modal fade" id="myModal" role="dialog">
            <div class="modal-dialog">

                <!-- Modal content-->
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal">&times;</button>
                        <h4 class="modal-title">Action Required</h4>
                    </div>
                    <div class="modal-body">
                        <p>Are you sure you want to exit <span id="add_here"></span> selected groups?</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" id="btn_exitgroup" data-dismiss="modal">Confirm</button>
                        <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    </div>
                </div>

            </div>
        </div>

    </h5>
  </header>
  <div class="w3-panel">
    <table class="w3-table w3-striped w3-white" id="display">
    </table>
  </div>
</div>
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`

type allGroupsPageData struct {
	Title   string
	IsAdmin bool

	UserName  string
	JSSources []string
}

const allGroupsPageText = `
{{define "allGroupsPage"}}
<html>

<head>
    {{template "commonHead" . }}
    <script type="text/javascript" src="/getGroups.js?type=all"></script>
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">

  <header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>All Ldap Groups</b>
    </h5>
  </header>

  <div class="w3-panel">
    <button class="w3-button w3-right w3-text-new-white w3-new-blue" id="length_btn" data-toggle="modal" data-target="#myModal">Request Access</button>
    <div class="modal fade" id="myModal" role="dialog">
        <div class="modal-dialog">

            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal"></button>
                    <h4 class="modal-title">Action Required</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to request access for these <span id="add_here"></span> selected groups?</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" id="btn_requestaccess" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>

        </div>
    </div>

    <table class="w3-table w3-striped w3-white" id="display">

    </table>

  </div>

  </div>
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`

type pendingRequestsPageData struct {
	Title   string
	IsAdmin bool

	UserName           string
	HasPendingRequests bool
	JSSources          []string
}

const pendingRequestsPageText = `
{{define "pendingRequestsPage"}}
<html>

<head>
    {{template "commonHead" . }}
    {{if .HasPendingRequests}}<script type="text/javascript" src="/getGroups.js?type=pendingRequests"></script>{{end}}
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">


{{if .HasPendingRequests}}
<header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>My Pending Group Requests</b>
    </h5>
</header>

<div class="w3-panel">
    <button class="w3-button w3-right w3-text-new-white w3-red" id="length_btn" data-toggle="modal" data-target="#myModal">Delete Requests</button>
    <div class="modal fade" id="myModal" role="dialog">
        <div class="modal-dialog">

            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Action Required</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete <span id="add_here"></span> selected requests?</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" id="btn_deleterequest" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>

        </div>
    </div>


    <table class="w3-table w3-striped w3-white" id="display">

    </table>

</div>
{{else}}

<header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>My Pending Group Requests</b>
    </h5>
</header>

<div class="w3-panel">
    <p>You don't have any pending requests at the moment.</p>
</div>

{{end}}


  </div><!-- end of content div -->
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`

type pendingActionsPageData struct {
	Title   string
	IsAdmin bool

	UserName          string
	HasPendingActions bool
	JSSources         []string
}

const pendingActionsPageText = `
{{define "pendingActionsPage"}}
<html>

<head>
    {{template "commonHead" . }}
    {{if .HasPendingActions}}<script type="text/javascript" src="/getGroups.js?type=pendingActions"></script>{{end}}
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">

{{if .HasPendingActions}}

<header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>My Pending Actions</b>
    </h5>
</header>

<div class="w3-panel">
    <button class="w3-button w3-right w3-text-new-white w3-red"  id="length_btn1" data-toggle="modal" data-target="#myModal">Reject Requests</button>
    <button class="w3-button w3-right w3-text-new-white w3-new-blue" id="length_btn2" data-toggle="modal" data-target="#myModal1">Approve Requests</button>
    <div class="modal fade" id="myModal" role="dialog">
        <div class="modal-dialog">

            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Action Required</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to reject <span id="add_here1"></span> selected requests?</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" id="btn_reject" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>

        </div>
    </div>
    <div class="modal fade" id="myModal1" role="dialog">
        <div class="modal-dialog">

            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Action Required</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to approve the <span id="add_here2"></span> selected requests?</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" id="btn_approve" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>

        </div>
    </div>


    <table class="w3-table w3-striped w3-white" id="pending_actions">

    </table>

</div>

{{else}}

<header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>My Pending Actions</b>
    </h5>
</header>

<div class="w3-panel">
    <p>You don't have any pending actions at the moment.</p>
</div>

{{end}}


  </div><!-- end of content div -->
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`

type createGroupPageData struct {
	Title   string
	IsAdmin bool

	UserName  string
	JSSources []string
}

const createGroupPageText = `
{{define "createGroupPage"}}
<html>

<head>
    {{template "commonHead" . }}
    <script type="text/javascript" src="/js/createGroup.js"></script>
    <script type="text/javascript" src="/getGroups.js?type=allNoManager"></script>
    <script type="text/javascript" src="/getUsers.js"></script>
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">


<!-- Header -->
<header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>Create a Group</b></h5>
</header>

<div class="w3-panel">
        <table class="w3-table w3-striped w3-white" id="creategroup">
            <tr>
                <td>Group Name</td>
                <td><input autocomplete="off" id="cg_groupname" name="groupname"  required="required" type="text"/><br/></td>
            </tr>
            <tr>
                <td>description</td>
                <td><select  id="select_groups" required="required" name="description" type="text">
                    <option value="self-managed">self-managed</option>
                </select><br/></td>
            </tr>
            <tr>
                <td>Members</td>
                <td>
                    <div class='suggestion'>
                    </div>
                    <input autocomplete="off" class="members" id='cg_members'  list="select_members" name="members" type="text"/>
                    <datalist class="select_memberslist" id="select_members">
                    </datalist>
                </td>
            </tr>
            <button class="w3-button w3-right w3-text-new-white w3-new-blue" data-toggle="modal" data-target="#myModalCreateGroup">Create Group</button>
        </table>

    <div class="modal fade" id="myModalCreateGroup" role="dialog">
        <div class="modal-dialog">
            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Action Required</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to create this group?</p>
                    <form id="form_create_group" method="POST" action="/create_group/?username={{.UserName}}" autocomplete="off">
                        GroupName: <input autocomplete="off" id='group_groupname' name="groupname" required type="text" readonly/><br/>
                        Managedby: <input autocomplete="off" id="group_managedby" name="description" required type="text" readonly><br/>
                        Members  : <input autocomplete="off" class='group_members' id='group_members' name="members" required="required" type="text" readonly/><br/>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default"  id="btn_creategroup" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>
        </div>
    </div>
</div>


  </div><!-- end of content div -->
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`

type deleteGroupPageData struct {
	Title   string
	IsAdmin bool

	UserName  string
	JSSources []string
}

const deleteGroupPageText = `
{{define "deleteGroupPage"}}
<html>

<head>
    {{template "commonHead" . }}
    <script type="text/javascript" src="/js/deleteGroup.js"></script>
    <script type="text/javascript" src="/getGroups.js?type=allNoManager"></script>
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">


<header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>Delete Group</b></h5>
</header>

<div class="w3-panel">
        <table class="w3-table w3-striped w3-white" id="deletegroup">
            <tr>
                <td>Group Names</td>
                <td>
                    <div class='suggestion'>
                    </div>
                    <input autocomplete="off" class="groupnames" id='cg_groupnames'  list="select_groups" name="groupnames" type="text"/>
                    <datalist class="select_groupslist" id="select_groups">
                    </datalist>
                </td>
            </tr>
            <button class="w3-button w3-right w3-text-new-white w3-new-blue" data-toggle="modal" data-target="#myModalDeleteGroups">Delete Groups</button>
        </table>
    <div class="modal fade" id="myModalDeleteGroups" role="dialog">
        <div class="modal-dialog">
            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Action Required</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete groups?</p>
                    <form autocomplete="off" id="form_delete_group" method="POST" action="/delete_group/?username={{.UserName}}">
                        GroupNames: <input autocomplete="off" class='group_names' id='group_names' name="groupnames" required="required" type="text" readonly/><br/>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" id="btn_deletegroup" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>
        </div>
    </div>
</div>

  </div><!-- end of content div -->
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`

type simpleMessagePageData struct {
	Title   string `json:",omitempty"`
	IsAdmin bool   `json:",omitempty"`

	UserName       string
	JSSources      []string `json:",omitempty"`
	SuccessMessage string   `json:",omitempty"`
	ContinueURL    string   `json:",omitempty"`
	ErrorMessage   string   `json:",omitempty"`
}

const simpleMessagePageText = `
{{define "simpleMessagePage"}}
<html>

<head>
    {{template "commonHead" . }}
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">
     <p>
     {{.SuccessMessage}}
     </p>
     {{if .ContinueURL}}<p>Click <a href="{{.ContinueURL}}">Here </a> to continue</p>{{end}}
  </div><!-- end of content div -->
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`

type addMembersToGroupPagData struct {
	Title   string
	IsAdmin bool

	UserName  string
	JSSources []string
}

const addMembersToGroupPageText = `
{{define "addMembersToGroupPage"}}
<html>

<head>
    {{template "commonHead" . }}
    <script type="text/javascript" src="/js/addMemberToGroup.js"></script>
    <script type="text/javascript" src="/getGroups.js?type=allNoManager"></script>
    <script type="text/javascript" src="/getUsers.js"></script>
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">

<!-- Header -->
<header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>Add members to Group</b></h5>
</header>

<div class="w3-panel">
        <table class="w3-table w3-striped w3-white">
            <tr>
                <td>Group Name</td>
                <td>
                    <input autocomplete="off" list="select_groups" id="cg_groupname" required name="groupname" type="text">
                    <datalist id="select_groups">
                    </datalist><br/>
                </td>
            </tr>
            <tr>
                <td>Members</td>
                <td>
                    <div class='suggestion'>
                    </div>
                    <input autocomplete="off" class="members" id='cg_members' list="select_members" name="members" type="text"/>
                    <datalist class="select_memberslist" id="select_members">
                    </datalist>
                </td>
            </tr>
            <button class="w3-button w3-right w3-text-new-white w3-new-blue" data-toggle="modal" data-target="#myModalAddpeopletoGroup">Add Members</button>
        </table>
    <div class="modal fade" id="myModalAddpeopletoGroup" role="dialog">
        <div class="modal-dialog">
            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Action Required</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to add members to the group?</p>
                    <form id="form_addpeople_togroup" method="POST" action="/addmembers/?username={{.UserName}}" autocomplete="off">
                        GroupName: <input autocomplete="off" id='group_groupname' name="groupname" required type="text" readonly/><br/>
                        Members  : <input autocomplete="off" class='group_members' id='group_members' name="members" required="required" type="text" readonly/><br/>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default"  id="btn_addpeopletogroup" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>
        </div>
    </div>
</div>


  </div><!-- end of content div -->
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`

type groupInfoPageData struct {
	Title    string
	IsAdmin  bool
	UserName string

	IsMember            bool
	IsGroupAdmin        bool
	GroupName           string
	GroupManagedbyValue string
	JSSources           []string
}

const groupInfoPageText = `
{{define "groupInfoPage"}}
<html>

<head>
    {{template "commonHead" . }}
    <script type="text/javascript" src="/js/groupInfo.js"></script>
    <script type="text/javascript" src="/getUsers.js?type=group&groupName={{.GroupName}}"></script>
    <script type="text/javascript" src="/getUsers.js"></script>
    </head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">


<!-- Header -->
<header class="w3-container" style="padding-top:12px">
    <h4><b><i class="fa fa-group"></i>Group Name:<strong id="groupname_member">{{.GroupName}}</strong></b></h4>
    <br>
    <br>
    <h4><b>Group Managed Attribute:<strong id="group_managedby">{{.GroupManagedbyValue}}</strong></b></h4>
</header>

<div class="w3-panel">
    {{if .IsGroupAdmin}}
    <button class="w3-button w3-right w3-text-new-white w3-new-blue" id="length_btn" data-toggle="modal" data-target="#myModalAddMember">Add Members</button>
    <button class="w3-button w3-right w3-text-new-white w3-new-blue" id="length_btn" data-toggle="modal" data-target="#myModalRemoveMembers">Remove Members</button>    
    {{end}}
    {{if .IsMember}}
    <button class="w3-button w3-right w3-text-new-white w3-new-blue" id="length_btn" data-toggle="modal" data-target="#myModalExitGroup">Exit group</button>
    {{else}}
    <button class="w3-button w3-right w3-text-new-white w3-new-blue" id="length_btn" data-toggle="modal" data-target="#myModal_joingroup">Join Group</button>
    {{end}}


    {{if .IsGroupAdmin}}
    <div class="modal fade" id="myModalAddMember" role="dialog">
        <div class="modal-dialog">

            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal"></button>
                    <h4 class="modal-title"><p>Please enter the names of those whom you want to add to this  group?</p></h4>
                </div>
                <div class="modal-body">
                    <form id="form_modal_addmember" action="/addmembers/?username={{.UserName}}" method="POST">
                        GroupName: <input name="groupname" required type="text" value="{{.GroupName}}" readonly><br/>
                        <input class='group_members' id='group_members' name="members" required="required" type="hidden" readonly/><br/>
                    </form>
                    <div class='suggestion'>
                    </div>
                    Members  : <input autocomplete="off" class="members" id='cg_members' list="select_members" name="members" type="text"/>
                    <datalist class="select_memberslist" id="select_members">
                    </datalist>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default"  id="btn_form_modal_addmember" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="myModalRemoveMembers" role="dialog">
        <div class="modal-dialog">

            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal"></button>
                    <h4 class="modal-title"><p>Please enter the names of those whom you want to remove from group?</p></h4>
                </div>
                <div class="modal-body">
                    <form id="form_modal_removemember" action="/deletemembers/?username={{.UserName}}" method="POST">
                        GroupName: <input autocomplete="off" name="groupname" required type="text" value="{{.GroupName}}" readonly><br/>
                        <input autocomplete="off" class="group_removemembers" id='group_removemembers' name="members" required="required" type="hidden" readonly/><br/>
                    </form>
                    <div class='suggestion_removemembers'>
                    </div>
                    Members  : <input autocomplete="off" class="remove_members" id='cg_members_remove' list="select_members_remove" name="members" type="text"/>
                    <datalist class="select_memberslist" id="select_members_remove">
                    </datalist>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default"  id="btn_form_modal_removemember" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>
        </div>
    </div>
    {{end}}
    {{if .IsMember}}
    <div class="modal fade" id="myModalExitGroup" role="dialog">
        <div class="modal-dialog">

            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal"></button>
                    <h4 class="modal-title">Action Required</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to exit this group?</p>
                    GroupName: <input name="groupname" id="groupinfo_exit" type="text" value="{{.GroupName}}" readonly><br/>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" id="groupinfo_btn_exitgroup" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>

        </div>
    </div>    
    {{else}}
    <div class="modal fade" id="myModal_joingroup" role="dialog">
        <div class="modal-dialog">

            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal"></button>
                    <h4 class="modal-title">Action Required</h4>
                </div>
                {{if .IsGroupAdmin}}
                <div class="modal-body">
                    <p>Are you sure you want to join this group?</p>
                    <form id="form_modal_joingroup" action="/addmembers/?username={{.UserName}}" method="POST">
                        GroupName: <input autocomplete="off" name="groupname" id="join_admin" type="text" value="{{.GroupName}}" required readonly><br/>
                        Username : <input autocomplete="off" name="members" required="required" value="{{.UserName}}" type="text" readonly><br/>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" id="btn_joingroup_admin"  data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
                {{else}}
                <div class="modal-body">
                    <p>Are you sure you want to request access for this group?</p>
                    GroupName: <input name="groupname" id="groupinfo_join_nonmember" type="text" value="{{.GroupName}}" readonly><br/>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" id="btn_joingroup" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
                {{end}}
            </div>
        </div>
    </div>
  
    {{end}}

    <table class="w3-table w3-striped w3-white" id="table_groupinfo">

    </table>


</div>


  </div><!-- end of content div -->
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`

type createServiceAccountPageData struct {
	Title   string
	IsAdmin bool

	UserName  string
	JSSources []string
}

const createServiceAccountPageText = `
{{define "createServiceAccountPage"}}
<html>

<head>
    {{template "commonHead" . }}
    <script type="text/javascript" src="/getGroups.js?type=allNoManager"></script>
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">



<!-- Header -->
<header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>Create a Service Account</b></h5>
</header>

<div class="w3-panel">
    <form method="POST" action="/create_serviceaccount/?username={{.UserName}}">
        <table class="w3-table w3-striped w3-white" id="creategroup">
            <tr>
                <td><label for="AccountName">Service Account Name</label></td>
                <td><input autocomplete="off" id="AccountName" name="AccountName" required type="text"/><br/></td>
            </tr>
            <tr>
                <td><label id="labelEmailAddress" for="EmailAddress">DL Email Address Only</label></td>
                <td><input autocomplete="off" id="EmailAddress" name="mail" required type="text"/><br/></td>
            </tr>
            <tr>
                <td><label id="labelloginShell" for="loginShell" >login Shell</label></td>
                <td><select id="loginShell" required name="loginShell" type="text">
                    <option value="/bin/false">/bin/false</option>
                    <option value="/bin/bash">/bin/bash</option>
                </select></td>
            </tr>
            <button class="w3-button w3-right w3-text-new-white w3-new-blue" type="submit" >Create Service Account</button>
        </table>
    </form>
</div>


  </div><!-- end of content div -->
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`

type changeGroupOwnershipPageData struct {
	Title   string
	IsAdmin bool

	UserName  string
	JSSources []string
}

const changeGroupOwnershipPageText = `
{{define "changeGroupOwnershipPage"}}
<html>

<head>
    {{template "commonHead" . }}
    <script type="text/javascript" src="/js/changeGroupOwnership.js"></script>
    <script type="text/javascript" src="/getGroups.js?type=allNoManager"></script>
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">

<header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>Change Group Ownership(RegExp)</b></h5>
</header>

<div class="w3-panel">
    <table class="w3-table w3-striped w3-white">
        <tr>
            <td>Regexp Group Name</td>
            <td>
                <input autocomplete="off" type="text" id="group_regexp"u>
            </td>
        </tr>
        <tr>
            <td>Manager Group</td>
            <td>
                <input autocomplete="off" list="select_groups" id="cg_groupname" required name="groupname" type="text">
                <datalist id="select_groups">
                </datalist><br/>
            </td>
        </tr>
        <tr>
            <td></td>
            <td>
            <textarea id="listgroups_output" cols="40" rows="10" data-role="none" style="resize: none;margin-left: auto; margin-right:auto;" readonly></textarea>
            </td>
        </tr>
        <button class="w3-button w3-right w3-text-new-white w3-new-blue" data-toggle="modal" data-target="#myModalAddpeopletoGroup_regexp" style="margin-left:10px">Change Ownership</button>
        <button class="w3-button w3-right w3-text-new-white w3-new-blue" id="list_group">Test List Groups</button>
    </table>
    <div class="modal fade" id="myModalAddpeopletoGroup_regexp" role="dialog">
        <div class="modal-dialog">
            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Action Required</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to change ownership of these groups?</p>
                    <form id="form_addpeople_togroup" method="POST" action="/change_owner/?username={{.UserName}}" autocomplete="off">
                        Groups: <input autocomplete="off" id='group_members' name="groupnames" required type="text" readonly/><br/>
                        ManagerGroup  : <input autocomplete="off" id='group_groupname' name="managegroup" required="required" type="text" readonly/><br/>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" id="btn_addpeopletogroup" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>
        </div>
    </div>
</div>


  </div><!-- end of content div -->
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`

type deleteMembersFromGroupPageData struct {
	Title   string
	IsAdmin bool

	UserName  string
	JSSources []string
	GroupName string
}

const deleteMembersFromGroupPageText = `
{{define "deleteMembersFromGroupPage"}}
<html>

<head>
    {{template "commonHead" . }}
    <script type="text/javascript" src="/js/deleteMembersFromGroup.js"></script>
    <script type="text/javascript" src="/getGroups.js?type=allNoManager"></script>
    <script type="text/javascript" src="/getUsers.js"></script>
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">


<!-- Header -->
<header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>Remove Members from a Group</b></h5>
</header>

<div class="w3-panel">
        <table class="w3-table w3-striped w3-white">
            <tr>
                <td>Group Name</td>
                <td>
                    <input list="select_groups" id="cg_groupname"  required name="groupname" type="text">
                    <datalist id="select_groups">
                    </datalist><br/>
                </td>
            </tr>
            <tr>
                <td>Members</td>
                <td>
                    <div class='suggestion'>
                    </div>
                    <input class="members" id='cg_members' list="select_members" name="members" type="text"/>
                    <datalist class="select_memberslist" id="select_members">
                    </datalist>
                </td>
            </tr>
            <button class="w3-button w3-right w3-text-new-white w3-new-blue" data-toggle="modal" data-target="#myModalDeletemembersfromGroup">Remove Members</button>
        </table>

    <div class="modal fade" id="myModalDeletemembersfromGroup" role="dialog">
        <div class="modal-dialog">
            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Action Required</h4>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to remove members from the group?</p>
                    <form id="form_deletemembers_fromgroup" method="POST" action="/deletemembers/?username={{.UserName}}">
                        GroupName: <input id='group_groupname' name="groupname" required type="text" readonly/><br/>
                        Members  : <input class='group_members' id='group_members' name="members" required="required" type="text" readonly/><br/>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default"  id="btn_deletemembersfromgroup" data-dismiss="modal">Confirm</button>
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                </div>
            </div>
        </div>
    </div>
</div>


  </div><!-- end of content div -->
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`
