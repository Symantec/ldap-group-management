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
    i{{if .HasPendingRequests}}<script type="text/javascript" src="/getGroups.js?type=pendingRequests"></script>{{end}}
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
