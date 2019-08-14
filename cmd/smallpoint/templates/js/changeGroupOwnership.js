document.addEventListener('DOMContentLoaded', function () {
          document.getElementById('cg_groupname').addEventListener('input', group_groupname);
	  document.getElementById('list_group').addEventListener('click', listgroup_regexp);
          document.getElementById('btn_addpeopletogroup').addEventListener('click', addpeopletogroup_form_submit);
          //alert("done");
});
