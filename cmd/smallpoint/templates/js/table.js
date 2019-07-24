function Run_OnLoad(groupnames,PendingActions,Users,Allusers,onegroup) {
    if (groupnames!=null){

        var final_groupnames=array(groupnames);
        RequestAccess(final_groupnames);
        datalist(groupnames[0]);
    }
    if(PendingActions!=null){
        var pending_actions=arrayPendingActions(PendingActions);
        pendingActionsTable(pending_actions);
    }
    if(Users!=null){
        var usernames=arrayUsers(Users);
        Group_Info(usernames);
    }
    if(Allusers!=null){
        list_members(Allusers);
    }
    if(onegroup!=null && Users != null){
    	show_groupname(onegroup, Users);
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
                result=parsestring(data_selected[i][1]);
                request_groups.groups.push(result);
            }
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
                request_groups.groups.push(result);
            }
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
                request_groups.groups.push(result);
            }
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
            xhttp.onreadystatechange = function(){ReloadOnSuccessOrAlert(xhttp);};
            xhttp.send(JSON.stringify({groups:request_groups.groups}));
        } );
        $('#length_btn2').click( function () {
            var length=table2.rows('.selected').data().length;
            $('#add_here2').html(length);
        });

        $('#btn_approve').click( function () {
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
    groupnames.sort();
    for(i=0;i<groupnames.length;i++){
        $('#select_groups').append("<option id='option-"+groupnames[i]+"' value='" + groupnames[i] + "'>"+groupnames[i]+"</option>");
    }
}

function list_members(users){
    users.sort();
    for(i=0;i<users.length;i++){
        $('#select_members').append("<option id='option-"+users[i]+"' value='" + users[i] + "'>"+users[i]+"</option>");
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
	for (i=0;i<users.length;i++){
	    $('#select_members_remove').append("<option id='option-"+users[i]+"' value='" + users[i] + "'>"+users[i]+"</option>");
	}
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
        xhttp.onreadystatechange = function(){ReloadOnSuccessOrAlert(xhttp);};
        xhttp.send(JSON.stringify({groups:request_groups.groups}));
    } );
}

function addmember_form_submit() {
    var val=refractor_members();
    if (val===1) {
        document.getElementById("form_modal_addmember").submit();
    }else {
        alert("error occured!");
    }

}

function removemember_form_submit() {
    var val=refractor_removemembers();
    if (val===1) {
        document.getElementById("form_modal_removemember").submit();
    }else {
        alert("error occured!");
    }
}

function joingroup_admin(){

    document.getElementById("form_modal_joingroup").submit();

}

function creategroup_form_submit() {
    var val=refractor_members();
    if (val===1) {
        document.getElementById("form_create_group").submit();
    }else {
        alert("error occured!");
    }
}

function deletegroup_form_submit() {

    var val=refractor_groupnames();
    if (val===1){
        document.getElementById("form_delete_group").submit();
    }else {
        alert("error occured!");
    }
}

function addpeopletogroup_form_submit() {
    var val=refractor_members();
    if (val===1) {
        document.getElementById("form_addpeople_togroup").submit();
    }else {
        alert("error occured!");
    }
}

function deletemembers_fromgroup_form_submit() {
    var val=refractor_members();
    if (val===1) {
        document.getElementById("form_deletemembers_fromgroup").submit();
    }else {
        alert("error occured!");
    }
}

function group_groupname(){

    var val = document.getElementById("cg_groupname").value;
    var select=document.getElementById('select_groups').value;

    $('#group_groupname').val(val);
    $('#group_managedby').val(select);

}

function groupadd_members() {
    var val = document.getElementById("cg_members").value;
    var opts = document.getElementById('select_members').childNodes;
    for (var i = 0; i < opts.length; i++) {
        if (opts[i].value === val) {
            members_func(opts[i].value);
            break;
        }
    }
}



function members_func(value) {
    $(document).ready(function() {
        $('input.members').val('');

        var optionid="option-"+value;
        var name=value;

        $('option.'+optionid).remove();
        $("div.suggestion").append($('<div class="borderbox" id='+value+'><b>' + value +
            '</b><button type="button" onclick="closebox('+"'"+name+"'"+')" class="close" aria-label="Close">\n' +
            '  <span  aria-hidden="true">&times;</span>\n' +
            '</button></div>'));
        var str='';
        $("div.suggestion div b").each(function () {
            str += $(this).text() + ",";
        });

        $('#group_members').val(str);
    });
}

function closebox(id) {


    $('datalist.select_memberslist').append("<option id='option-"+name+"' value='" +name+ "'>"+name+"</option>");

    $('datalist.select_groupslist').append("<option id='option-"+name+"' value='" +name+ "'>"+name+"</option>");

    document.getElementById(id).remove();
}

function refractor_members() {
    var val=document.getElementById("group_members").value;
    var length=val.length;
    if (val[length-1]===","){
        var res = val.substring(0, length-1);
        $('input.group_members').val(res);
        return 1;
    }
    return 0;
}

function refractor_groupnames() {
    var val=document.getElementById("group_names").value;
    var length=val.length;
    if (val[length-1]===","){
        var res = val.substring(0, length-1);
        $('input.group_names').val(res);
        return 1;
    }
    return 0;
}
function delete_groups() {
    var val = document.getElementById("cg_groupnames").value;
    var opts = document.getElementById('select_groups').childNodes;
    for (var i = 0; i < opts.length; i++) {
        if (opts[i].value === val) {
            deletegroups_func(opts[i].value);
            break;
        }
    }
}

function deletegroups_func(value) {
    $(document).ready(function() {
        $('input.groupnames').val('');

        var optionid="option-"+value;
        var name=value;

        document.getElementById(optionid).remove();

        $("div.suggestion").append($('<div class="borderbox" id='+value+'><b>' + value +
            '</b><button type="button" onclick="closebox('+"'"+name+"'"+')" class="close" aria-label="Close">\n' +
            '  <span  aria-hidden="true">&times;</span>\n' +
            '</button></div>'));
        var str='';
        $("div.suggestion div b").each(function () {
            str += $(this).text() + ",";
        });

        $('#group_names').val(str);
    });
}

//for remove members modal
function groupremove_members() {
    var val = document.getElementById("cg_members_remove").value;
    var opts = document.getElementById('select_members').childNodes;
    for (var i = 0; i < opts.length; i++) {
        if (opts[i].value === val) {
            members_removemodal(opts[i].value);
            break;
        }
    }
}

function members_removemodal(value) {
    $(document).ready(function() {
        $('input.remove_members').val('');

        var optionid="option-"+value;
        var name=value;

        document.getElementById(optionid).remove();

        $("div.suggestion_removemembers").append($('<div class="borderbox" id='+value+'><b>' + value +
            '</b><button type="button" onclick="closebox_remove('+"'"+name+"'"+')" class="close" aria-label="Close">\n' +
            '  <span  aria-hidden="true">&times;</span>\n' +
            '</button></div>'));
        var str='';
        $("div.suggestion_removemembers div b").each(function () {
            str += $(this).text() + ",";
        });

        $('#group_removemembers').val(str);
    });
}

function closebox_remove(id) {

    $('datalist.select_memberslist').append("<option id='option-"+id+"' value='" +id+ "'>"+id+"</option>");

    document.getElementById(id).remove();
}

function refractor_removemembers() {
    var val=document.getElementById("group_removemembers").value;
    var length=val.length;
    if (val[length-1]===","){
        var res = val.substring(0, length-1);
        $('input.group_removemembers').val(res);
        return 1;
    }
    return 0;
}

function listgroup_regexp() {
    $(document).ready(function() {
        var select = document.getElementById('select_groups').childNodes;
        var regexp = new RegExp(document.getElementById("group_regexp").value);
        var output = '';
        for (var i = 1; i < select.length; i++) {
            if (select[i].value.match(regexp)) {
                output += select[i].value + '\n';
            }
        }
        if (output.length < 1) {
            document.getElementById('listgroups_output').value = "No matched groups";
        } else {
            document.getElementById('listgroups_output').value = output;
        }
        $('#group_members').val(output.replace(/\n/g,','));
    });
}

function dm_groupname() {
    var val = document.getElementById('dm_group_name').value;
    var select = document.getElementById('select_groups').childNodes;
    for (var i = 1; i < select.length; i++) {
    	if(val === select[i].value) {
	    document.getElementById("group_name_delete_members").submit();
	} else {
	    continue;
	}
    }
}

function show_groupname(Groupname, Users) {
    Users.sort();
    for(var i=0;i<Users.length;i++) {
    	$('#select_dm_members').append("<option id='option-"+Users[i]+"' value='" + Users[i] + "'>"+Users[i]+"</option>");
    }
    $('#dm_group_name').val(Groupname);
    $('#group_groupname').val(Groupname);
}

function dm_members() {
    var val = document.getElementById("cg_members").value;
    var opts = document.getElementById("select_dm_members").childNodes;
    for (var i = 1; i < opts.length; i++) {
    	if (opts[i].value === val) {
	    members_func(opts[i].value);
	    break;
	}
    }
}
