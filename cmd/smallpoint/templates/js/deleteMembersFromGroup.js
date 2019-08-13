document.addEventListener('DOMContentLoaded', function () {
          document.getElementById('cg_groupname').addEventListener('input', group_groupname);
          document.getElementById('cg_members').addEventListener('input', groupadd_members);
	  document.getElementById('btn_deletemembersfromgroup').addEventListener('click', deletemembers_fromgroup_form_submit);
})
