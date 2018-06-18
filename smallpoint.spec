Name:		smallpoint
Version:	0.1.1
Release:	1%{?dist}
Summary:	LDAP group management tool

#Group:		
License:	ASL 2.0
URL:		https://github.com/Symantec/ldap-group-management
Source0:	smallpoint-%{version}.tar.gz

#BuildRequires:	Golang
#Requires:	

%description
Simple utilites for checking state of ldap infrastructure

%prep
%setup -n %{name}-%{version}


%build
make


%install
#%make_install
%{__install} -Dp -m0755 ~/go/bin/smallpoint %{buildroot}%{_sbindir}/smallpoint

install -d %{buildroot}/usr/lib/systemd/system
install -p -m 0644 misc/startup/smallpoint.service %{buildroot}/usr/lib/systemd/system/smallpoint.service
install -d %{buildroot}/%{_datarootdir}/smallpoint/templates/
install -p -m 0644 cmd/smallpoint/templates/Accessrequestsent.html %{buildroot}/%{_datarootdir}/smallpoint/templates/Accessrequestsent.html
install -p -m 0644 cmd/smallpoint/templates/deletemembersfromgroup.html %{buildroot}/%{_datarootdir}/smallpoint/templates/deletemembersfromgroup.html
install -p -m 0644 cmd/smallpoint/templates/my_groups.html %{buildroot}/%{_datarootdir}/smallpoint/templates/my_groups.html
install -p -m 0644 cmd/smallpoint/templates/addpeopletogroups.html %{buildroot}/%{_datarootdir}/smallpoint/templates/addpeopletogroups.html
install -p -m 0644 cmd/smallpoint/templates/deletemembersfromgroup_success.html %{buildroot}/%{_datarootdir}/smallpoint/templates/deletemembersfromgroup_success.html
install -p -m 0644 cmd/smallpoint/templates/groupinfo_nonmember_admin.html %{buildroot}/%{_datarootdir}/smallpoint/templates/groupinfo_nonmember_admin.html
install -p -m 0644 cmd/smallpoint/templates/no_pending_actions.html %{buildroot}/%{_datarootdir}/smallpoint/templates/no_pending_actions.html
install -p -m 0644 cmd/smallpoint/templates/addpeopletogroup_success.html %{buildroot}/%{_datarootdir}/smallpoint/templates/addpeopletogroup_success.html
install -p -m 0644 cmd/smallpoint/templates/groupcreation_success.html %{buildroot}/%{_datarootdir}/smallpoint/templates/groupcreation_success.html
install -p -m 0644 cmd/smallpoint/templates/groupinfo_nonmember.html %{buildroot}/%{_datarootdir}/smallpoint/templates/groupinfo_nonmember.html
install -p -m 0644 cmd/smallpoint/templates/no_pending_requests.html %{buildroot}/%{_datarootdir}/smallpoint/templates/no_pending_requests.html
install -p -m 0644 cmd/smallpoint/templates/admins_sidebar.html %{buildroot}/%{_datarootdir}/smallpoint/templates/admins_sidebar.html
install -p -m 0644 cmd/smallpoint/templates/groupdeletion_success.html %{buildroot}/%{_datarootdir}/smallpoint/templates/groupdeletion_success.html
install -p -m 0644 cmd/smallpoint/templates/groups.html %{buildroot}/%{_datarootdir}/smallpoint/templates/groups.html
install -p -m 0644 cmd/smallpoint/templates/pending_actions.html %{buildroot}/%{_datarootdir}/smallpoint/templates/pending_actions.html
install -p -m 0644 cmd/smallpoint/templates/create_group.html %{buildroot}/%{_datarootdir}/smallpoint/templates/create_group.html
install -p -m 0644 cmd/smallpoint/templates/groupinfo_member_admin.html %{buildroot}/%{_datarootdir}/smallpoint/templates/groupinfo_member_admin.html
install -p -m 0644 cmd/smallpoint/templates/pending_requests.html %{buildroot}/%{_datarootdir}/smallpoint/templates/pending_requests.html
install -p -m 0644 cmd/smallpoint/templates/create_service_account.html %{buildroot}/%{_datarootdir}/smallpoint/templates/create_service_account.html
install -p -m 0644 cmd/smallpoint/templates/groupinfo_member.html %{buildroot}/%{_datarootdir}/smallpoint/templates/groupinfo_member.html
install -p -m 0644 cmd/smallpoint/templates/index.html %{buildroot}/%{_datarootdir}/smallpoint/templates/index.html
install -p -m 0644 cmd/smallpoint/templates/serviceacc_creation_success.html %{buildroot}/%{_datarootdir}/smallpoint/templates/serviceacc_creation_success.html
install -p -m 0644 cmd/smallpoint/templates/sidebar.html %{buildroot}/%{_datarootdir}/smallpoint/templates/sidebar.html
install -p -m 0644 cmd/smallpoint/templates/delete_group.html %{buildroot}/%{_datarootdir}/smallpoint/templates/delete_group.html
install -p -m 0644 cmd/smallpoint/templates/groupinfo_no_managedby_member_nomem.html %{buildroot}/%{_datarootdir}/smallpoint/templates/groupinfo_no_managedby_member_nomem.html
install -p -m 0644 cmd/smallpoint/templates/modal.html %{buildroot}/%{_datarootdir}/smallpoint/templates/modal.html

install -d %{buildroot}/%{_datarootdir}/smallpoint/templates/css/
install -p -m 0644 cmd/smallpoint/templates/css/new.css %{buildroot}/%{_datarootdir}/smallpoint/templates/css/new.css

install -d %{buildroot}/%{_datarootdir}/smallpoint/templates/js/
install -p -m 0644 cmd/smallpoint/templates/js/table.js %{buildroot}/%{_datarootdir}/smallpoint/templates/js/table.js

install -d %{buildroot}/%{_datarootdir}/smallpoint/templates/images/
install -p -m 0644 cmd/smallpoint/templates/images/avatar2.png %{buildroot}/%{_datarootdir}/smallpoint/templates/images/avatar2.png

%post
systemctl daemon-reload

%postun
systemctl daemon-reload



%files
#%doc
%{_sbindir}/smallpoint
/usr/lib/systemd/system/smallpoint.service
%{_datarootdir}/smallpoint/templates/*
%changelog

