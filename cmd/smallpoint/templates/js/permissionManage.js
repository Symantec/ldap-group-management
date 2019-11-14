document.addEventListener('DOMContentLoaded', function() {
	document.getElementById('cg_groupname').addEventListener('input', group_groupname);
	document.getElementById('create_permissions').addEventListener('click', resource_type);
	document.getElementById('input_permissions').addEventListener('input', permission_manage);
})
