Name:		smallpoint
Version:	0.2.3
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

install -d %{buildroot}/%{_datarootdir}/smallpoint/templates/css/
install -p -m 0644 cmd/smallpoint/templates/css/new.css %{buildroot}/%{_datarootdir}/smallpoint/templates/css/new.css

install -d %{buildroot}/%{_datarootdir}/smallpoint/templates/js/
install -p -m 0644 cmd/smallpoint/templates/js/addMemberToGroup.js %{buildroot}/%{_datarootdir}/smallpoint/templates/js/addMemberToGroup.js
install -p -m 0644 cmd/smallpoint/templates/js/changeGroupOwnership.js %{buildroot}/%{_datarootdir}/smallpoint/templates/js/changeGroupOwnership.js
install -p -m 0644 cmd/smallpoint/templates/js/createGroup.js %{buildroot}/%{_datarootdir}/smallpoint/templates/js/createGroup.js
install -p -m 0644 cmd/smallpoint/templates/js/deleteGroup.js %{buildroot}/%{_datarootdir}/smallpoint/templates/js/deleteGroup.js
install -p -m 0644 cmd/smallpoint/templates/js/deleteMembersFromGroup.js %{buildroot}/%{_datarootdir}/smallpoint/templates/js/deleteMembersFromGroup.js
install -p -m 0644 cmd/smallpoint/templates/js/groupInfo.js %{buildroot}/%{_datarootdir}/smallpoint/templates/js/groupInfo.js
install -p -m 0644 cmd/smallpoint/templates/js/newtable.js %{buildroot}/%{_datarootdir}/smallpoint/templates/js/newtable.js
install -p -m 0644 cmd/smallpoint/templates/js/sidebar.js %{buildroot}/%{_datarootdir}/smallpoint/templates/js/sidebar.js
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

