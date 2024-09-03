# Author: Jeremy Carrier
# Last Update: August 15, 2024

import os
import base64
# We need the 'requests', 'ldap3', and 'configparser' modules for this script
# Check to see if they are installed, and prompt if they are not
print ('Validating that necessary modules are installed')
try:
    import requests
    # 'requests' is installed, we can proceed
    print("Required module 'requests' is installed")
except ModuleNotFoundError:
    # 'requests' is not installed - prompt user for installation
    print("Required module 'requests' is not installed")
    allowInstallResponse = input("Allow installation of required Python module 'requests' (y/n): ")
    # If user provides a yes (y) value, attempt to install 'requests'
    if allowInstallResponse.lower() == "y":
        print("Installing 'requests'")
        import subprocess
        import sys
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
        except subprocess.CalledProcessError as e:
            # Installation of 'requests' failed, exit
            print('Unable to install requests package - error code returned: ' + str(e.returncode))
            quit()
        # Now that 'requests' is installed, import it for use
        import requests

    else:
        # If user provides any value other than a 'y', exit
        print("Installation of 'requests' not allowed, exiting")
        quit()

try:
    import ldap3
    from ldap3 import Server, Connection, ALL
    # 'ldap3' is installed, we can proceed
    print("Required module 'ldap3' is installed")
except ModuleNotFoundError:
    # 'ldap3' is not installed - prompt user for installation
    print("Required module 'ldap3' is not installed")
    allowInstallResponse = input("Allow installation of required Python module 'ldap3' (y/n): ")
    # If user provides a yes (y) value, attempt to install 'ldap3'
    if allowInstallResponse.lower() == "y":
        print("Installing 'ldap3'")
        import subprocess
        import sys
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "ldap3"])
        except subprocess.CalledProcessError as e:
            # Installation of 'ldap3' failed, exit
            print('Unable to install ldap3 package - error code returned: ' + str(e.returncode))
            quit()
        # Now that 'ldap3' is installed, import it for use
        import ldap3
        from ldap3 import Server, Connection, ALL

    else:
        # If user provides any value other than a 'y', exit
        print("Installation of 'ldap3' not allowed, exiting")
        quit()     

try:
    import configparser
    # 'configparser' is installed, we can proceed
    print("Required module 'configparser' is installed")
except ModuleNotFoundError:
    # 'configparser' is not installed - prompt user for installation
    print("Required module 'configparser' is not installed")
    allowInstallResponse = input("Allow installation of required Python module 'configparser' (y/n): ")
    # If user provides a yes (y) value, attempt to install 'configparser'
    if allowInstallResponse.lower() == "y":
        print("Installing 'configparser'")
        import subprocess
        import sys
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "configparser"])
        except subprocess.CalledProcessError as e:
            # Installation of 'configparser' failed, exit
            print('Unable to install configparser package - error code returned: ' + str(e.returncode))
            quit()
        # Now that 'configparser' is installed, import it for use
        import configparser

    else:
        # If user provides any value other than a 'y', exit
        print("Installation of 'configparser' not allowed, exiting")
        quit()          


########################
#    function: readConfigFile
########################
# description: Read configuration values from ldapgateway.cfg file
#      inputs: none
#     outputs: adHostname, adPort, adSsl, adUsername, adPassword, adPath, adUniqueAttribute, runState, p1Region, p1Environment, p1ClientId, p1ClientSecret
########################
def readConfigFile():
    adHostname = ""
    adPort = ""
    adSsl = ""
    adUsername = ""
    adPassword = ""
    adPath = ""
    adUniqueAttribute = ""
    runState = ""
    p1Region = ""

    #Ensure config file exists
    if(os.path.isfile("ldapgateway.cfg")):
        #Found file

        try:
            configFile = configparser.ConfigParser()
            configFile.read('ldapgateway.cfg')
        except Exception as err:
            print('Error reading config file ldapgateway.cfg: ' + err)
            quit()


        if "settings" in configFile.sections():

            if ("adHostname" in configFile['settings']) and \
            ("adPort" in configFile['settings']) and \
            ("adSsl" in configFile['settings']) and \
            ("adUsername" in configFile['settings']) and \
            ("adPassword" in configFile['settings']) and\
            ("adPath" in configFile['settings']) and\
            ("adUniqueAttribute" in configFile['settings']) and\
            ("runState" in configFile['settings']) and\
            ("p1Region" in configFile['settings']) and \
            ("p1Environment" in configFile['settings']) and \
            ("p1ClientId" in configFile['settings']) and \
            ("p1ClientSecret" in configFile['settings']) and \
            ("p1Population" in configFile['settings']) and \
            ("p1GatewayId" in configFile['settings']) and \
            ("p1GatewayUserType" in configFile['settings']):
                adHostname = configFile['settings']['adHostname']
                adPort = configFile['settings']['adPort']
                adSsl = configFile['settings']['adSsl']
                adUsername = configFile['settings']['adUsername']
                adPassword = configFile['settings']['adPassword']
                adPath = configFile['settings']['adPath']
                adUniqueAttribute = configFile['settings']['adUniqueAttribute']
                runState = configFile['settings']['runState']
                p1Region = configFile['settings']['p1Region']
                p1Environment = configFile['settings']['p1Environment']
                p1ClientId = configFile['settings']['p1ClientId']
                p1ClientSecret = configFile['settings']['p1ClientSecret']
                p1Population = configFile['settings']['p1Population']
                p1GatewayId = configFile['settings']['p1GatewayId']
                p1GatewayUserType = configFile['settings']['p1GatewayUserType']
                return adHostname, adPort, adSsl, adUsername, adPassword, adPath, adUniqueAttribute, runState, p1Region, p1Environment, p1ClientId, p1ClientSecret, p1Population, p1GatewayId, p1GatewayUserType
            else:
                print("Not all parameters were found in the configuration file - expected: adHostname, adPort, adSsl, asUsername, adPassword, adPath, adUniqueAttribute, runState, p1Region, p1Environment, p1ClientId, p1ClientSecret, p1Population, p1GatewayId, p1GatewayUserType")
                quit()
 
    else:
        #Config file not found
        print("Config file 'ldapgateway.cfg' was not found in the current directory.")
        quit()
########################
# END function: readConfigFile
########################


# Check to see if we get a response back from the server
def checkHost(adHostname, adPort, adSsl, adUsername, adPassword,):
    try:
        # Turn off warning for self-signed certs
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        # Call AD
        if adSsl == "y":

            adServer = ldap3.Server(f'ldaps://{adHostname}:{adPort}')
            adConnection = Connection(adServer, user=adUsername, password=adPassword, auto_bind=False)
            if not adConnection.bind():
                    print("Unable to connect to AD server on ldaps://" + adHostname + ":"+ adPort + ", error result: ", adConnection.result)
                    quit()
        else:
            #hostCheckResult = requests.get("https://" + pfHostname + ":" + pfPort + "/pf-admin-api/v1/",timeout=10,verify=False)
            adServer = ldap3.Server(f'ldap://{adHostname}:{adPort}')
            adConnection = Connection(adServer, user=adUsername, password=adPassword, auto_bind=False)
            if not adConnection.bind():
                    print("Unable to connect to AD server on ldap://" + adHostname + ":"+ adPort + ", error result: ", adConnection.result)
                    quit()

    except requests.exceptions.RequestException:
        # Couldn't connect to AD, exit
        print("Unable to connect to AD server.")
        quit()

    print ("Successful bind to " + adHostname + " on port " + adPort)

    return 0

# Get user list
def getAdUsers(adHostname, adPort, adSsl, adUsername, adPassword, adPath, adUniqueAttribute):

    adResults = []

    if adSsl == "y":
        adServer = ldap3.Server(f'ldaps://{adHostname}:{adPort}')
        adConnection = Connection(adServer, user=adUsername, password=adPassword, auto_bind=False)
    else:
        adServer = ldap3.Server(f'ldap://{adHostname}:{adPort}')
        adConnection = Connection(adServer, user=adUsername, password=adPassword, auto_bind=False)

    adConnection.bind()

    totalEntries = 0;   
    searchResults = adConnection.extend.standard.paged_search(search_base=adPath, search_filter="(objectCategory=Person)", search_scope=ldap3.SUBTREE, attributes=[adUniqueAttribute], paged_size=100, generator=True)
    for singleResult in searchResults:
        adResults.append(f'{singleResult["dn"]} {singleResult["attributes"]}')
        totalEntries += 1

        #print(singleResult["dn"], singleResult["attributes"])
    #print("Total entries retrieved:", totalEntries)

    return adResults

# Get user list
def getAdUsers2(adHostname, adPort, adSsl, adUsername, adPassword, adPath, adUniqueAttribute):

    adResults = {}

    if adSsl == "y":
        adServer = ldap3.Server(f'ldaps://{adHostname}:{adPort}')
        adConnection = Connection(adServer, user=adUsername, password=adPassword, auto_bind=False)
    else:
        adServer = ldap3.Server(f'ldap://{adHostname}:{adPort}')
        adConnection = Connection(adServer, user=adUsername, password=adPassword, auto_bind=False)

    adConnection.bind()

    totalEntries = 0;   
    searchResults = adConnection.extend.standard.paged_search(search_base=adPath, search_filter="(objectCategory=Person)", search_scope=ldap3.SUBTREE, attributes=[adUniqueAttribute], paged_size=100, generator=True)
    for singleResult in searchResults:
        adResults[singleResult["attributes"][adUniqueAttribute]] = singleResult["dn"]
        totalEntries += 1

        #print(singleResult["dn"], singleResult["attributes"])
    #print("Total entries retrieved:", totalEntries)

    return adResults



#print AD user list
def printAdUsers(adUsers):
    for user in adUsers:
        print(f'{user} : {adUsers[user]}')

def getP1Token(p1Region, p1Environment, p1ClientId, p1ClientSecret):
    #Get base64 encoded credentials
    credStringBytes = (f'{p1ClientId}:{p1ClientSecret}').encode("ascii")
    credB64bytes = base64.b64encode(credStringBytes)
    creds = credB64bytes.decode("ascii")

    access_token_url = f'https://auth.pingone.{p1Region}/{p1Environment}/as/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {creds}'
    }

    # Authenticate and get an access token
    data = {
        'grant_type': 'client_credentials',
    }

    response = requests.post(access_token_url, data=data, headers=headers)
    access_token = response.json().get('access_token')

    return access_token

def getP1UserList(p1Region, p1Environment, p1AccessToken):
    
    p1UserList = {}
    currentPageUsers = []
    nextPageUrl = f'https://api.pingone.{p1Region}/v1/environments/{p1Environment}/users?limit=100'
    currentPage = 1
    totalUsers = 0

    while nextPageUrl:  
        currentPageUsers.clear()
        headers = {
            'Authorization': f'Bearer {p1AccessToken}',
        }

        response = requests.get(nextPageUrl, headers=headers)

        if response.status_code == 200:
            userPage = response.json()
            currentPageUsers.extend(userPage.get('_embedded', {}).get('users', []))
            #p1UserList.extend(userPage.get('_embedded', {}).get('users', []))
            for user in currentPageUsers:
                p1UserList[user["username"]] = user
            nextPageUrl = userPage['_links'].get('next', {}).get('href', None)
            totalUser = userPage['count']
            print(f'Retrieved {currentPage * 100} of {totalUser} Users')
            currentPage += 1  # Increment the page count
        else:
            print(f'Error: {response.status_code} - {response.text}')
            quit()    

    return p1UserList


def generateComparison(adUsers, p1UserList):

    for adUser in adUsers:
        if adUser in p1UserList:
            #if ad user in p1, indicate and remove from p1 user list
            print(f'MATCHED: AD user {adUser} found in PingOne')
            p1UserList.pop(adUser)
        else:
            #if ad user not in p1, indicate
            print(f'ONLY IN AD: AD user {adUser} does not exist in PingOne')
        #remaining p1 users, indicate
        #print(adUser)

    for p1User in p1UserList:
        print(f'ONLY IN PINGONE: PingOne user {p1User} does not exist in AD')
    #print(p1UserList)

    return 0

def updateIndividualUser(p1Id, adUser, p1AccessToken, p1Region, p1Environment, p1GatewayId, p1GatewayUserType, adUniqueAttribute):

    #P1 password URL
    url = f'https://api.pingone.{p1Region}/v1/environments/{p1Environment}/users/{p1Id}/password'

    #Content type is specific to setting a user to a P1 gateway
    #P1 AT must be passed in to perform user update
    headers = {
        'Content-Type': 'application/vnd.pingidentity.password.setGateway+json',
        'Authorization': f'Bearer {p1AccessToken}'
    }

    #The P1 gateway ID and user type must be passed in
    #The correlation attribute is the unique attribute name defined in the gateway config, and the value is what we looked up in AD
    jsonBody = {
                    "id": p1GatewayId,
                    "userType": {
                        "id": p1GatewayUserType
                    },
                    "correlationAttributes": {
                        adUniqueAttribute: adUser
                    }
                }

    #Make a PUT call to the URL with the headers and JSON body
    response = requests.put(url, headers = headers, json = jsonBody)

    #If we get an HTTP 200 back, it was a success - report it
    if response.status_code == 200:
        print(f'Success, P1 user {p1Id} is successfully updated, with {adUniqueAttribute} now using {adUser} for mapping with gateway {p1GatewayId}')
    #If we didn't get an HTTP 200 back, we had an error - report it and keep trying with the others in the list
    else:
        print(f'Error - could not update P1 user with ID {p1Id}: {response.status_code} - {response.text}')

    return 0

def updateUsers(adUsers, p1UserList, p1AccessToken, p1Region, p1Environment, p1GatewayId, p1GatewayUserType, adUniqueAttribute):

    updatedUsers = []

    #Loop over the list of users in AD
    for adUser in adUsers:
        #If the current user from AD exists in P1, Update
        if adUser in p1UserList:
            #Update the current user
            updateIndividualUser(p1UserList[adUser]["id"], adUser, p1AccessToken, p1Region, p1Environment, p1GatewayId, p1GatewayUserType, adUniqueAttribute)
            #Track the list of users we've updated
            updatedUsers.append(adUser)        
    
    
    #Remove the updated users from the AD list so that our list only contains users we haven't worked on
    # - This is needed when we create users from the AD list that don't exist in P1
    for updatedUser in updatedUsers:
            adUsers.pop(updatedUser)

    return 0

def createIndividualUser(adUser, p1AccessToken, p1Region, p1Environment, p1Population):

    #create user
    #P1 create user URL
    url = f'https://api.pingone.{p1Region}/v1/environments/{p1Environment}/users'

    #P1 AT must be passed in to perform user create
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {p1AccessToken}'
    }

    #At a minimum, the username needs to be provided to create a user - we will also put that user into a specific population
    jsonBody = {
                    "username": adUser,
                    "population": {
                        "id": p1Population
                    }
                }

    #Make a POST call to the URL with the headers and JSON body
    response = requests.post(url, headers = headers, json = jsonBody)

    #If we get an HTTP 200 back, it was a success - report it
    if response.status_code == 201:
        p1UserId = response.json()["id"]
        print(f'Success, P1 user {adUser} is successfully created, with GUID {p1UserId}')
    #If we didn't get an HTTP 200 back, we had an error - report it and keep trying with the others in the list
    else:
        print(f'Error - could not create P1 user with ID {adUser}: {response.status_code} - {response.text}')
    
    return p1UserId


def createUsers(adUsers, p1AccessToken, p1Region, p1Environment, p1Population, p1GatewayId, p1GatewayUserType, adUniqueAttribute):
    
    #Loop overs users in AD list - create them and update their gateway configuration
    for adUser in adUsers:
        newUserId = createIndividualUser(adUser, p1AccessToken, p1Region, p1Environment, p1Population)
        updateIndividualUser(newUserId, adUser, p1AccessToken, p1Region, p1Environment, p1GatewayId, p1GatewayUserType, adUniqueAttribute)

    return 0


def main():
    #Read the config file
    adHostname, adPort, adSsl, adUsername, adPassword, adPath, adUniqueAttribute, runState, p1Region, p1Environment, p1ClientId, p1ClientSecret, p1Population, p1GatewayId, p1GatewayUserType = readConfigFile()
    if runState in ("listAd", "compare", "updateonly", "fullsync"):    
        # Validate connection using hostname and port
        checkHost(adHostname, adPort, adSsl, adUsername, adPassword)
        # Get Users
        adUsers = getAdUsers2(adHostname, adPort, adSsl, adUsername, adPassword, adPath, adUniqueAttribute)
        if runState == "listAd":
            # Output the AD user list
            printAdUsers(adUsers)
            quit()
        if runState in("compare", "updateonly", "fullsync"):
            #Get Token
            p1AccessToken = getP1Token(p1Region, p1Environment, p1ClientId, p1ClientSecret)
            #Loop over users
            p1UserList = getP1UserList(p1Region, p1Environment, p1AccessToken)
            #Ensure matching attribute
            if runState == "compare":
                generateComparison(adUsers, p1UserList)
            if runState == "updateonly":
                updateUsers(adUsers, p1UserList, p1AccessToken, p1Region, p1Environment, p1GatewayId, p1GatewayUserType, adUniqueAttribute)
            if runState == "fullsync":
                updateUsers(adUsers, p1UserList, p1AccessToken, p1Region, p1Environment, p1GatewayId, p1GatewayUserType, adUniqueAttribute)
                createUsers(adUsers, p1AccessToken, p1Region, p1Environment, p1Population,p1GatewayId, p1GatewayUserType, adUniqueAttribute)
    else:
        print("Invalid run state: ", runState)

main()