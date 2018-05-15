function Run_OnLoad(groupnames,PendingActions) {
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

}
function array(groupnames) {//[["1","2"]]
    var groupname=[];
    var group_description=[];
    for(i=0;i<groupnames.length;i++){
        groupname[0]='<a title="click for groupinfo" href=/group_users/?groupname='+groupnames[i][0]+'>'+groupnames[i][0]+'</a>';
        //groupname[0]=groupnames[i][0];
        if(groupnames[i][1]==="self-managed") {
            groupname[1] ='<a title="click for groupinfo" href=/group_users/?groupname='+groupnames[i][0]+'>'+groupnames[i][1]+'</a>';
        }else{
            groupname[1] ='<a title="click for groupinfo" href=/group_users/?groupname='+groupnames[i][0]+'>'+groupnames[i][1]+'</a>';
        }
        group_description[i]=groupname;
        groupname=[];
    }
    return group_description;//=[[][][][]]
}

function arrayPendingActions(PendingActions) {
    var groupname=[];
    var group_description=[];
    for(i=0;i<PendingActions.length;i++){
        groupname[0]='<a title="click for userinfo" href=/user_groups/?username='+PendingActions[i][0]+'>'+PendingActions[i][0]+'</a>';
        //groupname[0]=groupnames[i][0];
        groupname[1] ='<a title="click for groupinfo" href=/group_users/?groupname='+PendingActions[i][1]+'>'+PendingActions[i][1]+'</a>';
        group_description[i]=groupname;
        groupname=[];
    }
    return group_description;//=[[][][][]]
}

function parsestring(str){
    var pos2,pos1,res;
    var nextindex=1;
    pos2 = str.lastIndexOf("<");
    pos1 = str.indexOf(">");
    res = str.substring(pos1 + index, pos2);
    return res;
}

function Parsearray(array) {
    //console.log(array);
    var nextindex=1;
    var result=[];
    var pos2,pos1,res;
    for(i=0;i<length;i++){
        if(array[i]===""){
            result[i]="";
            continue;
        }
        pos2 = array[i].lastIndexOf("<");
        pos1 = array[i].indexOf(">");
        res = array[i].substring(pos1 + nextindex, pos2);
        result[i]=res;
    }
    return result;
}

function RequestAccess(final_groupnames) {

    $(document).ready(function() {
        $('#display').DataTable( {
            data: final_groupnames,
            columns: [
                {title:"groups"},
                {title:"managed by"}
            ]
        } );
    } );

    $(document).ready(function() {
        var table = $('#display').DataTable();

        $('#display tbody').on( 'click', 'tr', function () {
            $(this).toggleClass('selected');
        } );
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
                result=parsestring(data_selected[i][0]);
                //console.log(result);
                request_groups.groups.push(result);
            }
            //console.log(request_groups.groups);
            xhttp.onreadystatechange = ActionTakenOnResponse(xhttp);
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
                result=parsestring(data_selected[i][0]);
                //console.log(result);
                request_groups.groups.push(result);
            }
            //console.log(request_groups.groups);
            xhttp.onreadystatechange = ActionTakenOnResponse(xhttp);
            xhttp.send(JSON.stringify({groups:request_groups.groups}));
        } );

        //exitgroup button
        $('#btn_exitgroup').click( function () {
            //alert( table.rows('.selected').data().length +' row(s) selected' );
            var data_selected=table.rows('.selected').data();
            var xhttp = new XMLHttpRequest();   // new HttpRequest instance
            xhttp.open("POST", "/exitgroup");
            xhttp.setRequestHeader("Content-Type", "application/json");
            //xhttp.setRequestHeader("X-CSRF-Token",Csrf_Token);
            var request_groups={};
            request_groups.groups=[];
            for(i=0;i<table.rows('.selected').data().length;i++){
                result=parsestring(data_selected[i][0]);
                //console.log(result);
                request_groups.groups.push(result);
            }
            //console.log(request_groups.groups);
            xhttp.onreadystatechange = ActionTakenOnResponse(xhttp);
            xhttp.send(JSON.stringify({groups:request_groups.groups}));
        } );
    } );


}

function pendingActionsTable(PendingActions) {
    $(document).ready(function() {
        $('#pending_actions').DataTable( {
            data: PendingActions,
            columns: [
                {title:"username"},
                {title:"groupname"}
            ]
        } );
    } );

    $(document).ready(function() {
        var table2 = $('#pending_actions').DataTable();

        $('#pending_actions tbody').on( 'click', 'tr', function () {
            $(this).toggleClass('selected');
        } );
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
            for(i=0;i<table2.rows('.selected').data().length;i++){
                data_selected[i]=Parsearray(data_selected[i]);
                request_groups.groups.push(data_selected[i]);
            }
            //console.log(request_groups.groups);
            xhttp.onreadystatechange = ActionTakenOnResponse(xhttp);
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
            // xhttp.setRequestHeader("X-CSRF-Token",Csrf_Token);
            var request_groups={};
            request_groups.groups=[];
            for(i=0;i<table2.rows('.selected').data().length;i++){
                request_groups.groups.push(data_selected[i]);
            }
            console.log(request_groups.groups);
            xhttp.onreadystatechange = ActionTakenOnResponse(xhttp);
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

function ActionTakenOnResponse(xhttp) {
    if (xhttp.readyState === 4 && xhttp.status === 200) {
        location.reload();
    }
    if(xhttp.status!==200){
        alert("error occured!");
    }
}