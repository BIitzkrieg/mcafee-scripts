# TIE Whitelisting Script Originally by Troja from the McAfee Community
# https://community.mcafee.com/t5/Threat-Intelligence-Exchange-TIE/Upload-a-golden-Image-to-TIE-including-Reputation-and-Comment/td-p/490716
# Modified on 10/9/18
    # Added support for sha256 hashes on 10/25/18


import mcafee
import sys
import base64
import hashlib
import time
import socket
import os
import json

# ip or fqdn
ePOIP = ''
ePOUser = ''
ePOUserPwd = ''
# example C:\\Program Files

dir_to_whitelist = "C:\\Users\\user1\\Desktop\\whitelist"
dir_to_blacklist = "C:\\Users\\user1\\Desktop\\blacklist"
# dir_to_use = ""


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
    sha1input = ""
    md5input = ""
    sha256input = ""
    for root, dirs, files in os.walk(dir_to_whitelist):
        for file in files:
            # print(os.path.join(root, file))
            if file.endswith(".exe") | file.endswith(".dll") | file.endswith(".EXE") | file.endswith(".DLL"):
                filename = os.path.join(root, file)
                # filename = root + "\\" + file
                try:
                    sha1input = hashlib.sha1(open(filename, 'rb').read()).hexdigest()
                    md5input = hashlib.md5(open(filename, 'rb').read()).hexdigest()
                    sha256input = hashlib.sha256(open(filename, 'rb').read()).hexdigest()
                except IOError:
                    print("Unable to open file for hashing")
                    sys.exc_clear()

                sha1base64 = base64.b64encode(sha1input.decode('hex'))
                md5base64 = base64.b64encode(md5input.decode('hex'))
                sha256base64 = base64.b64encode(sha256input.decode('hex'))

                mc = mcafee.client(ePOIP, '8443', ePOUser, ePOUserPwd, 'https', 'json')
                PresentTimeDate = time.strftime("%c")
                PresentHost = socket.gethostname()
                filePath = os.path.normpath(filename)
                repString = '[{"sha256":"' + sha256base64 + '","sha1":"' + sha1base64 + '","md5":"' + md5base64 + '","reputation":"' + reputationWhite + '","name":"' + str(file) + '","comment":"' + PresentTimeDate + " " + "Whitelisted by Script" + " on Host: " + PresentHost + "," + " " + "Located at path: " + str(json.dumps(filePath).replace('\"', '')) + '"}]'
                print('Adding Whitelisted Files to TIE Server: ' + repString)
                mc.tie.setReputations(repString)


def blacklistLoop():
    sha1input = ""
    md5input = ""
    sha256input = ""
    for root, dirs, files in os.walk(dir_to_whitelist):
        for file in files:
            # print(os.path.join(root, file))
            if file.endswith(".exe") | file.endswith(".dll") | file.endswith(".EXE") | file.endswith(".DLL"):
                filename = os.path.join(root, file)
                # filename = root + "\\" + file
                try:
                    sha1input = hashlib.sha1(open(filename, 'rb').read()).hexdigest()
                    md5input = hashlib.md5(open(filename, 'rb').read()).hexdigest()
                    sha256input = hashlib.sha256(open(filename, 'rb').read()).hexdigest()
                except IOError:
                    print("Unable to open file for hashing")
                    sys.exc_clear()

                sha1base64 = base64.b64encode(sha1input.decode('hex'))
                md5base64 = base64.b64encode(md5input.decode('hex'))
                sha256base64 = base64.b64encode(sha256input.decode('hex'))

                mc = mcafee.client(ePOIP, '8443', ePOUser, ePOUserPwd, 'https', 'json')
                PresentTimeDate = time.strftime("%c")
                PresentHost = socket.gethostname()
                filePath = os.path.normpath(filename)
                repString = '[{"sha256":"' + sha256base64 + '","sha1":"' + sha1base64 + '","md5":"' + md5base64 + '","reputation":"' + reputationBlack + '","name":"' + str(file) + '","comment":"' + PresentTimeDate + " " + "Blacklisted by Script" + " on Host: " + PresentHost + "," + " " + "Located at path: " + str(json.dumps(filePath).replace('\"', '')) + '"}]'
                print('Adding Blacklisted Files to TIE Server: ' + repString)
                mc.tie.setReputations(repString)


def __main__():
    whitelistLoop()
    blacklistLoop()


__main__()

# Optional: Track any File under the EPO issues
#           IssueString = "Filename: " + filename + " MD5: " + md5input + " sha1: " + sha1input + " from System: " + PresentHost
#           mc.issue.createIssue(name="Whitelist Entry by Script",desc=IssueString)
