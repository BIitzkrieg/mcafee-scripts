# TIE Whitelisting Script Originally by Troja from the McAfee Community
# https://community.mcafee.com/t5/Threat-Intelligence-Exchange-TIE/Upload-a-golden-Image-to-TIE-including-Reputation-and-Comment/td-p/490716
# Modified 10/25/18


import mcafee
import sys
import base64
import time
import socket
import os
import json
import re

# ip or fqdn
ePOIP = ''
ePOUser = ''
ePOUserPwd = ''

# Directories to use
dir_to_whitelist = "C:\\Users\\user1\\Desktop\\whitelist"
dir_to_blacklist = "C:\\Users\\user1\\Desktop\\blacklist"

# This is the default Reputation Score written to the TIE Database
reputationWhite = '99'
reputationBlack = '1'

# Possible Reputation Values (You must provide a numeric value)
# Known Trusted Installer   100
# Known trusted 			99
# Most likely trusted 	85
# Might be trusted 		70
# Unknown 				50
# Might be malicious 	30
# Most likely malicious 	15
# Known malicious 		1
# Not set 				0

def whitelistLoop():
    md5base64 = ""
    sha1base64 = ""
    sha256base64 = ""
    f = open(dir_to_whitelist + "\hashes.txt")
    contents = f.read()
    file_as_list = contents.splitlines()
    for line in file_as_list:
        if re.match(r"^([a-fA-F\d]{32}$)", line):
            md5base64 = base64.b64encode(line.decode('hex'))

        elif re.match(r"^([a-fA-F\d]{40}$)", line):
            sha1base64 = base64.b64encode(line.decode('hex'))

        elif re.match(r"^([a-fA-F\d]{64}$)", line):
            sha256base64 = base64.b64encode(line.decode('hex'))

        else:
            print("Script only takes SHA-1 or MD5 hashes")

        mc = mcafee.client(ePOIP, '8443', ePOUser, ePOUserPwd, 'https', 'json')
        PresentTimeDate = time.strftime("%c")
        filePath = os.path.normpath(dir_to_whitelist)
        PresentHost = socket.gethostname()
        repString = '[{"sha256":"' + sha256base64 + '","sha1":"' + sha1base64 + '", "md5":"' + md5base64 + '","reputation":"' + reputationWhite +'","name":"' + str(line) + '","comment":"' + PresentTimeDate + " " + "Whitelisted by Script" + " on Host: " + PresentHost + "," + " " + "Located at path: " + str(json.dumps(filePath).replace('\"', '')) + '"}]'
        print('Adding Whitelisted Files to TIE Server: ' + repString)
        mc.tie.setReputations(repString)

def blacklistLoop():
    md5base64 = ""
    sha1base64 = ""
    sha256base64 = ""
    f = open(dir_to_blacklist + "\hashes.txt")
    contents = f.read()
    file_as_list = contents.splitlines()
    for line in file_as_list:
        if re.match(r"^([a-fA-F\d]{32}$)", line):
            md5base64 = base64.b64encode(line.decode('hex'))

        elif re.match(r"^([a-fA-F\d]{40}$)", line):
            sha1base64 = base64.b64encode(line.decode('hex'))

        elif re.match(r"^([a-fA-F\d]{64}$)", line):
            sha256base64 = base64.b64encode(line.decode('hex'))

        else:
            print("Script only takes SHA-1 or MD5 hashes")

        mc = mcafee.client(ePOIP, '8443', ePOUser, ePOUserPwd, 'https', 'json')
        PresentTimeDate = time.strftime("%c")
        filePath = os.path.normpath(dir_to_blacklist)
        PresentHost = socket.gethostname()
        repString = '[{"sha256":"' + sha256base64 + '","sha1":"' + sha1base64 + '", "md5":"' + md5base64 + '","reputation":"' + reputationBlack + '","name":"' + str(line) + '","comment":"' + PresentTimeDate + " " + "Blacklisted by Script" + " on Host: " + PresentHost + "," + " " + "Located at path: " + str(json.dumps(filePath).replace('\"', '')) + "," + " " + "Related to Grey Energy Malware" '"}]'
        print('Adding Blacklisted Files to TIE Server: ' + repString)
        mc.tie.setReputations(repString)


def __main__():
    whitelistLoop()
    blacklistLoop()


__main__()

# Optional: Track any File under the EPO issues
#           IssueString = "Filename: " + filename + " MD5: " + md5input + " sha1: " + sha1input + " from System: " + PresentHost
#           mc.issue.createIssue(name="Whitelist Entry by Script",desc=IssueString)
