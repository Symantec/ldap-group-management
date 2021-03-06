# Smallpoint
[![Build Status](https://api.travis-ci.org/Symantec/ldap-group-management.svg?branch=master)](https://travis-ci.org/Symantec/ldap-group-management)


Smallpoint is a LDAP group management system, it is developed to help with different operations based on LDAP database. First, super administrators can create and delete LDAP groups, then all users can ask for access to any LDAP group, and managers of the requested group can approve or decline such request. What's more, users can list all groups they belong to as well as all groups in the LDAP database. And this system is easy to use, configure and administer.


## Getting Start
You can build it from source. The rpm package contain the binary.

### Prerequisites
* go >= 1.10.1

### Building
1. make deps
2. make

This will leave you with a binary: smallpoint.

### Running
You will need to create a new valid config file. And run the binary file yourself.


## Contributions
Prior to receiving information from any contributor, Symantec requires
that all contributors complete, sign, and submit Symantec Personal
Contributor Agreement (SPCA).  The purpose of the SPCA is to clearly
define the terms under which intellectual property has been
contributed to the project and thereby allow Symantec to defend the
project should there be a legal dispute regarding the software at some
future time. A signed SPCA is required to be on file before an
individual is given commit privileges to the Symantec open source
project.  Please note that the privilege to commit to the project is
conditional and may be revoked by Symantec.

If you are employed by a corporation, a Symantec Corporate Contributor
Agreement (SCCA) is also required before you may contribute to the
project.  If you are employed by a company, you may have signed an
employment agreement that assigns intellectual property ownership in
certain of your ideas or code to your company.  We require a SCCA to
make sure that the intellectual property in your contribution is
clearly contributed to the Symantec open source project, even if that
intellectual property had previously been assigned by you.

Please complete the SPCA and, if required, the SCCA and return to
Symantec at:

Symantec Corporation
Legal Department
Attention:  Product Legal Support Team
350 Ellis Street
Mountain View, CA 94043

Please be sure to keep a signed copy for your records.


## LICENSE

Copyright 2016 Symantec Corporation.

Licensed under the Apache License, Version 2.0 (the “License”); you
may not use this file except in compliance with the License.

You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0 Unless required by
applicable law or agreed to in writing, software distributed under the
License is distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for
the specific language governing permissions and limitations under the
License.

