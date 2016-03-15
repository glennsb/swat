# SWAT
Swift Auth Token Tool

# About
A quick tool to help with getting swift OS_AUTH_TOKEN. Our environment
is one that uses SwiftStack and Active Directory based authentication using
standard user accounts. It is not prudent then to leave OS_PASSWORD or ST_KEY
values sitting around.

# Usage
Basic usage is to call ```swat login```, enter the password, then sh style
environment variable setting strings will be returned for OS_AUTH_TOKEN and
OS_STORAGE_URL. By default these will also be saved to a dot file that can be
sourced in future shells while the token is still valid

# Tenants
```swat tenants``` can be used to list possible additional accounts/tenant ids
to which you have access. This is specially designed for our use case of having
a primary Active Directory group for the account with a semi standard naming scheme
with an additional group of readers given RO access via an ACL

# Eval
The best way to really use ```eval``` via a shell function to automatically set the
enviroment in the calling shell

```
login (){
  eval $(swat --auth-url https://some.swift.endpoint/auth/v2.0/tokens login $*)
}
```

# Installation

```
go install github.com/glennsb/swat
```

# License
3-Clause BSD
