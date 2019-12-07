# mcafee-scripts
Scripts to interact with the McAfee ePO Web API. Credit to Troja from the McAfee community for the original code. I simply modified it for my use case.  

## How to use addTIEReputation.py  
Edit the script with your respective ePO server IP and credentials. Customize the "dir_to_whitelist" and "dir_to_blacklist" directories as needed.  
Place all files you'd like to whitelist, or blacklist, in those respective directories, and run the python script.  
python addTIEReputation.py

## How to use addTIERepFromList.py  
Modify the code as needed, like with addTIEReputation.py  
Place a hashes.txt file in the repsective directories, that you wish to blacklist or whitelist, one hash per line.  
The API will accept SHA-1, SHA-256, and MD5 hashes to be inserted into the TIE database.  
python addTIERepFromList.py
