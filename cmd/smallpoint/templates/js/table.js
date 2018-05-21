function Run_OnLoad(groupnames,PendingActions,Users) {
    if (groupnames!=null){

        var final_groupnames=array(groupnames);
        RequestAccess(final_groupnames);
        datalist(groupnames[0]);
        return;
    }
    if(PendingActions!=null){
        var pending_actions=arrayPendingActions(PendingActions);
        pendingActionsTable(pending_actions);
    }
    if(Users!=null){
        var usernames=arrayUsers(Users);
        Group_Info(usernames);
    }

}

function arrayUsers(Users) {
    var username=[];
    var user_names=[];
    for(i=0;i<Users.length;i++){
        username[0]=Users[i];
        user_names[i]=username;
        username=[];
    }
    return user_names;//=[[][][][]]
}
function array(groupnames) {//[["1","2"]]
    var groupname=[];
    var group_description=[];
    for(i=0;i<groupnames.length;i++){
        groupname[1]='<a title="click for groupinfo" href=/group_info/?groupname='+groupnames[i][0]+'>'+groupnames[i][0]+'</a>';
        //groupname[0]=groupnames[i][0];
        if(groupnames[i][1]==="self-managed") {
            groupname[2] ='<a title="click for groupinfo" href=/group_info/?groupname='+groupnames[i][0]+'>'+groupnames[i][1]+'</a>';
        }else{
            groupname[2] ='<a title="click for groupinfo" href=/group_info/?groupname='+groupnames[i][0]+'>'+groupnames[i][1]+'</a>';
        }
        groupname[0]='';
        group_description[i]=groupname;
        groupname=[];
    }
    return group_description;//=[[][][][]]
}

function arrayPendingActions(PendingActions) {
    var groupname=[];
    var group_description=[];
    for(i=0;i<PendingActions.length;i++){
        groupname[1]='<a title="click for userinfo" href=/user_groups/?username='+PendingActions[i][0]+'>'+PendingActions[i][0]+'</a>';
        //groupname[0]=groupnames[i][0];
        groupname[2] ='<a title="click for groupinfo" href=/group_info/?groupname='+PendingActions[i][1]+'>'+PendingActions[i][1]+'</a>';
        groupname[0]='';
        group_description[i]=groupname;
        groupname=[];
    }
    return group_description;//=[[][][][]]
}

function parsestring(str){
    var pos2,pos1,res;
    pos2 = str.lastIndexOf("<");
    pos1 = str.indexOf(">");
    res = str.substring(pos1 + 1, pos2);
    return res;
}

function Parsearray(array) {
    //console.log(array);
    var result=[];
    var pos2,pos1,res;
    for(i=0;i<length;i++){
        if(array[i]===""){
            result[i]="";
            continue;
        }
        pos2 = array[i].lastIndexOf("<");
        pos1 = array[i].indexOf(">");
        res = array[i].substring(pos1 + 1, pos2);
        result[i]=res;
    }
    return result;
}

function RequestAccess(final_groupnames) {

    $(document).ready(function() {
        $('#display').DataTable( {
            data: final_groupnames,
            columns: [
                {title:"select"},
                {title:"groups"},
                {title:"managed by"}
            ],
            columnDefs: [ {
                orderable: false,
                className: 'select-checkbox',
                targets:   0
            } ],
            select: {
                style: 'multi',
                selector: 'td:first-child'
            },
            order:[[1,'asc']]
        } );
    } );

    $(document).ready(function() {
        var table = $('#display').DataTable();

        $('#length_btn').click( function () {
            var length=table.rows('.selected').data().length;
            $('#add_here').html(length);
        });

        //Request access confirm button
        $('#btn_requestaccess').click( function () {
            //alert( table.rows('.selected').data().length +' row(s) selected' );
            var data_selected=table.rows('.selected').data();
            var xhttp = new XMLHttpRequest();   // new HttpRequest instance
            xhttp.open("POST", "/requestaccess");
            xhttp.setRequestHeader("Content-Type", "application/json");
            var request_groups={};
            request_groups.groups=[];
            for(i=0;i<table.rows('.selected').data().length;i++){
                //data_selected[i]=Parsearray(data_selected[i]);
                result=parsestring(data_selected[i][1]);
                //console.log(result);
                request_groups.groups.push(result);
            }
            //console.log(request_groups.groups);
            xhttp.onreadystatechange = function(){ReloadOnSuccessOrAlert(xhttp);};
            xhttp.send(JSON.stringify({groups:request_groups.groups}));
        } );

        //delete requests confirm button
        $('#btn_deleterequest').click( function () {
            //alert( table.rows('.selected').data().length +' row(s) selected' );
            var data_selected=table.rows('.selected').data();
            var xhttp = new XMLHttpRequest();   // new HttpRequest instance
            xhttp.open("POST", "/deleterequests");
            xhttp.setRequestHeader("Content-Type", "application/json");
            var request_groups={};
            request_groups.groups=[];
            for(i=0;i<table.rows('.selected').data().length;i++){
                result=parsestring(data_selected[i][1]);
                //console.log(result);
                request_groups.groups.push(result);
            }
            //console.log(request_groups.groups);
            xhttp.onreadystatechange = function(){ReloadOnSuccessOrAlert(xhttp);};
            xhttp.send(JSON.stringify({groups:request_groups.groups}));
        } );

        //exitgroup button
        $('#btn_exitgroup').click( function () {
            //alert( table.rows('.selected').data().length +' row(s) selected' );
            var data_selected=table.rows('.selected').data();
            var xhttp = new XMLHttpRequest();   // new HttpRequest instance
            xhttp.open("POST", "/exitgroup");
            xhttp.setRequestHeader("Content-Type", "application/json");
            var request_groups={};
            request_groups.groups=[];
            for(i=0;i<table.rows('.selected').data().length;i++){
                result=parsestring(data_selected[i][1]);
                //console.log(result);
                request_groups.groups.push(result);
            }
            //console.log(request_groups.groups);
            xhttp.onreadystatechange = function(){ReloadOnSuccessOrAlert(xhttp);};
            xhttp.send(JSON.stringify({groups:request_groups.groups}));
        } );
    } );


}

function pendingActionsTable(PendingActions) {
    $(document).ready(function() {
        $('#pending_actions').DataTable( {
            data: PendingActions,
            columns: [
                {title:"select"},
                {title:"username"},
                {title:"groupname"}
            ],
            columnDefs: [ {
                orderable: false,
                className: 'select-checkbox',
                targets:   0
            } ],
            select: {
                style: 'multi',
                selector: 'td:first-child'
            },
            order:[[1,'asc']]
        } );
    } );

    $(document).ready(function() {
        var table2 = $('#pending_actions').DataTable();

        $('#length_btn1').click( function () {
            var length=table2.rows('.selected').data().length;
            $('#add_here1').html(length);
        });

        $('#btn_reject').click( function () {
            //alert( table.rows('.selected').data().length +' row(s) selected' );
            var data_selected=table2.rows('.selected').data();
            var xhttp = new XMLHttpRequest();   // new HttpRequest instance
            xhttp.open("POST", "/reject-request");
            xhttp.setRequestHeader("Content-Type", "application/json");
            var request_groups={};
            request_groups.groups=[];
            var result=[];
            for(i=0;i<table2.rows('.selected').data().length;i++){
                user=parsestring(data_selected[i][1]);
                group=parsestring(data_selected[i][2]);
                result=[user,group];
                request_groups.groups.push(result);
                result=[];
            }
            //console.log(request_groups.groups);
            xhttp.onreadystatechange = function(){ReloadOnSuccessOrAlert(xhttp);};
            xhttp.send(JSON.stringify({groups:request_groups.groups}));
        } );
        $('#length_btn2').click( function () {
            var length=table2.rows('.selected').data().length;
            $('#add_here2').html(length);
        });

        $('#btn_approve').click( function () {
            //alert( table.rows('.selected').data().length +' row(s) selected' );
            var data_selected=table2.rows('.selected').data();
            var xhttp = new XMLHttpRequest();   // new HttpRequest instance
            xhttp.open("POST", "/approve-request");
            xhttp.setRequestHeader("Content-Type", "application/json");
            var request_groups={};
            request_groups.groups=[];
            var result=[];
            for(i=0;i<table2.rows('.selected').data().length;i++){
                user=parsestring(data_selected[i][1]);
                group=parsestring(data_selected[i][2]);
                result=[user,group];
                request_groups.groups.push(result);
                result=[];
            }
            console.log(request_groups.groups);
            xhttp.onreadystatechange = function(){ReloadOnSuccessOrAlert(xhttp);};
            xhttp.send(JSON.stringify({groups:request_groups.groups}));
        } );
    } );

}

// Toggle between showing and hiding the sidebar, and add overlay effect
function sidebar_open() {
    // Get the Sidebar
    var mySidebar = document.getElementById("mySidebar");

    // Get the DIV with overlay effect
    var overlayBg = document.getElementById("myOverlay");

    if (mySidebar.style.display === 'block') {
        mySidebar.style.display = 'none';
        overlayBg.style.display = "none";
    } else {
        mySidebar.style.display = 'block';
        overlayBg.style.display = "block";
    }
}

// Close the sidebar with the close button
function sidebar_close() {
    // Get the Sidebar
    var mySidebar = document.getElementById("mySidebar");

    // Get the DIV with overlay effect
    var overlayBg = document.getElementById("myOverlay");

    mySidebar.style.display = "block";
    overlayBg.style.display = "none";
}

function datalist(groupnames) {
    for(i=0;i<groupnames.length;i++){
        $('#select_groups').append("<option value='" + groupnames[i] + "'>"+groupnames[i]+"</option>");
    }
}

function ReloadOnSuccessOrAlert(xhttp) {
    if (xhttp.readyState === 4) {
        if (xhttp.status === 200) {
            location.reload();
        } else {
            alert("error occured!");
        }
    }
}



function Group_Info(users) {
    $(document).ready(function() {
        $('#table_groupinfo').DataTable( {
            data: users,
            columns: [
                {title:"Members of the group"}
            ]
        } );
    } );

    //exitgroup button
    $('#groupinfo_btn_exitgroup').click( function () {
        var groupname=document.getElementById('groupinfo_exit').value;
        var xhttp = new XMLHttpRequest();   // new HttpRequest instance
        xhttp.open("POST", "/exitgroup");
        xhttp.setRequestHeader("Content-Type", "application/json");
        var request_groups={};
        request_groups.groups=[];
        request_groups.groups.push(groupname);
        //console.log(request_groups.groups);
        xhttp.onreadystatechange = function(){ReloadOnSuccessOrAlert(xhttp);};
        xhttp.send(JSON.stringify({groups:request_groups.groups}));
    } );


    $('#btn_joingroup').click( function () {
        var data_selected=document.getElementById('groupinfo_join_nonmember').value;
        var xhttp = new XMLHttpRequest();   // new HttpRequest instance
        xhttp.open("POST", "/requestaccess");
        xhttp.setRequestHeader("Content-Type", "application/json");
        var request_groups={};
        request_groups.groups=[];
        request_groups.groups.push(data_selected);
        //console.log(request_groups.groups);
        xhttp.onreadystatechange = function(){ReloadOnSuccessOrAlert(xhttp);};
        xhttp.send(JSON.stringify({groups:request_groups.groups}));
    } );


    $('#btn_joingroup_admin').click( function () {
        var data_selected=document.getElementById('join_admin').value;
        var xhttp = new XMLHttpRequest();   // new HttpRequest instance
        xhttp.open("POST", "/join_group");
        xhttp.setRequestHeader("Content-Type", "application/json");
        var request_groups={};
        request_groups.groups=[];
        request_groups.groups.push(data_selected);
        //console.log(request_groups.groups);
        xhttp.onreadystatechange = function(){ReloadOnSuccessOrAlert(xhttp);};
        xhttp.send(JSON.stringify({groups:request_groups.groups}));
    } );
}

function addmember_form_submit() {

    document.getElementById("form_modal_addmember").submit();

}

function removemember_form_submit() {

    document.getElementById("form_modal_removemember").submit();

}
