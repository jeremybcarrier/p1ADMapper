# PingOne AD Mapping Tool
### Author: Jeremy Carrier

## Notice
This tool is not written by Ping Identity, and is supported via best-effort

## Use Cases
For users within PingOne to utilize an AD source as the source of truth for attributes (and optinally password checks),
users must be mapped to a specific LDAP gateway.  Users created just-in-time via the gateway are automatically mapped, but
there are scenarios where an out-of-band mapping may be required:
- Users were created in PingOne prior to the LDAP gateway being used
- Bulk mapping of users from an AD source is needed
- Users are mapped to an LDAP gateway in PingOne, but need to be adjusted because:
    * The correllation attributes of users need to be changed
    * The gateway user type configuration needs to be changed
    * The gateway configuration itself needs to be changed

# Prerequisites
- An AD source of truth
- A user in the AD source of truth that can read from the AD source
- A PingOne environment
- A PingOne LDAP gateway configuration: https://docs.pingidentity.com/r/en-us/pingone/p1_c_ldap_gateways
- A PingOne LDAP gateway user type: https://docs.pingidentity.com/r/en-us/pingone/p1_c_add_a_user_type
- A PingOne client credentials worker application: https://docs.pingidentity.com/r/en-us/pingone/p1_add_app_worker

# Configuration
The **ldapgateway.cfg** file has a number of parameters that need to be filled in:
- *adHostname* - The hostname (or IP address) of the AD server (ex: dc.mydomain.com or 1.2.3.4)
- *adPort* - Port that should be used for the connection (ex: 389 (unsecure) or 636 (secure))
- *adSsl* - Is the provided port SSL or not? (y or n)
- *adUsername* - DN of a user with the rights to be able to read from AD (ex: cn=myuser,cn=user,dc=mydomain,dc=com)
- *adPassword* - password of the administrative user which will read from AD
- *adPath* - LDAP search path where users will be found (ex: ou=users,dc=mydomain,dc=com) - note, special characters should escaped
- *p1Region* - TLD for the PingOne instance (United States = com, Canada = ca, Europe = eu, Asia = asia)
- *p1Environment* - environment ID for the PingOne tenant (Can be found in PingOne tenant: Settings -> Environment Properties -> Environment ID)
- *p1ClientId* - client ID for the PingOne worker (Can be found in PingOne tenant: Applications -> Applications -> *Your worker app* -> Configuration -> Client ID)
- *p1ClientSecret* - client secret for the PingOne worker (Can be found in PingOne tenant: Applications -> Applications -> *Your worker app* -> Configuration -> Client Secret)
- *p1GatewayId* - unique id of the P1 gateway instance (Can be found in PingOne tenant: Integrations -> Gateways -> *Your gateway* -> API -> id (ensure this is top level id, not a child of another JSON node))
- *p1GatewayUserType* - unique id of the P1 gateway user type (Can be found in PingOne tenant: Integrations -> Gateways -> *Your gateway* -> API -> userTypes -> id)
- *adUniqueAttribute* - unique source attribute for mapping from AD (ex. samaccountname)
- *p1UniqueAttribute* - unique destination attribute for mapping into P1 (Valid P1 options are: accountId, email, externalId, mobilePhone, username, id)
- *p1Population* - the PingOne population into which NEW users should be created (Can be found in PingOne tenant: Directory -> Populations -> *Your population* -> Population ID)
- *runState* - The tool can take several different actions:
   - listAd: this option will list all of the AD users that are in the provided path, as well as the value of their unique mapping attribute
   - compare: this option will retrieve the list of user from AD, then compare them to the users in PingOne and report on whether the AD users will be created or updated
   - updateonly: this option will read the users from AD and then update any matching existing users in PingOne and will ignore any users that don't exist in PingOne
   - fullsync: this option will read the users from AD and then create any users that don't exist in PingOne and update users that do exist

# To Operate
Make sure the **ldapgateway.cfg** is filled in and is in the same directory as the script.  Then, simply execute the script (ex: /usr/local/bin/python3 ./ldapgateway.py)
You may optionally pipe the output of the script (based on your runState) to a file if you like
