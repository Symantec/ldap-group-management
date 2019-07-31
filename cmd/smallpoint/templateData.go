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

	Groups              [][]string
	Users               []string
	PendingActions      [][]string
	GroupName           string
	GroupManagedbyValue string
	GroupUsers          []string

	JSSources []string
}

const myGroupsPageText = `
{{define "myGroupsPage"}}
<html>

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>{{.Title}}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    {{template "commonCSS"}}
    {{template "commonJS"}}
    <script type="text/javascript" src="/getGroups.js"></script>
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">
  <header class="w3-container" style="padding-top:12px">
    <h5><b><i class="fa fa-group"></i>My Groups</b>
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
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>{{.Title}}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    {{template "commonCSS"}}
    {{template "commonJS"}}
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
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>{{.Title}}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    {{template "commonCSS"}}
    {{template "commonJS"}}
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
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>{{.Title}}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    {{template "commonCSS"}}
    {{template "commonJS"}}
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
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>{{.Title}}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    {{template "commonCSS"}}
    {{template "commonJS"}}
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
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>{{.Title}}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    {{template "commonCSS"}}
    {{template "commonJS"}}
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
	Title   string
	IsAdmin bool

	UserName       string
	JSSources      []string
	SuccessMessage string
	ErrorMessage   string
}

const simpleMessagePageText = `
{{define "simpleMessagePage"}}
<html>

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>{{.Title}}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    {{template "commonCSS"}}
    {{template "commonJS"}}
    <script type="text/javascript" src="/js/deleteGroup.js"></script>
    <script type="text/javascript" src="/getGroups.js?type=allNoManager"></script>
</head>
<body class="w3-light-grey" >
{{template "header" .}}

<!-- !PAGE CONTENT! -->
<div class="w3-main" style="margin-left:300px;margin-top:43px;">
  <div id="content">
     <p>
     {{.SuccessMessage}}
     </p>
  </div><!-- end of content div -->
{{template "footer"}}
</div>

</body>
</html>
{{end}}
`
