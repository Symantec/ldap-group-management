document.addEventListener('DOMContentLoaded', function () {
          document.getElementById('cg_groupname').addEventListener('input', group_groupname);
	  document.getElementById('select_groups').addEventListener('change', group_groupname);
          document.getElementById('cg_members').addEventListener('input', groupadd_members);
          document.getElementById('btn_creategroup').addEventListener('click', creategroup_form_submit);
});
