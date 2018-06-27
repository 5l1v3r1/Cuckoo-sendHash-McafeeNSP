#!/usr/bin/env python3

import os
import concurrent.futures
import inotify.adapters
import json
from pprint import pprint
import subprocess
import requests
import getpass
import base64
import urllib3


def cuckoo_monitor():
	print("The watchdog is active now, waiting for any new Malware analysis...")
	
	reports_dir = '/home/ismail/.cuckoo/storage/analyses/'
	latest_report='latest/reports/report.json'

	i = inotify.adapters.Inotify()
	i.add_watch(reports_dir)
	
	try:
		for event in i.event_gen():
			if event is not None and 'IN_CREATE' in event[1]:
				print(event)
				print("\nfile '{0}' created in '{1}'".format(event[3], event[2]))
				
				with open(reports_dir+latest_report) as f:
					latest_report = json.load(f)
					print("Printing the whole Cuckoo report:")
					pprint(latest_report)
					print("\nPrinting info section only:")
					pprint(latest_report["info"])
					
					latest_score = latest_report["info"]["score"]
					print("\nRisk score is :", latest_score)

					md5_hash = latest_report["target"]["file"]["md5"]
					print("\nThe md5 hash of the analyzed file is :", md5_hash)

					if latest_score > 1:
						print("\nRisk score is high ! i'll call the API script")
						#os.system("McafeeIPS_API_sendHash.py")
						print("\nAuthenticating with the Mcafee NSM..")
						session_ID, user_ID = session()  # function for getting session and user ID
						print("\nMy Session: ", session_ID)
						print("\nUser ID: ", user_ID)
						
						#md5_hash = input("please enter the MD5 hash: ")
						md5_hash = latest_report["target"]["file"]["md5"]
						print("\nHash of scanned file is :", md5_hash)
						#fileName = input("please enter the Malware name: ")
						fileName = latest_report["target"]["file"]["md5"]
						print("fileName is :", fileName)
						#comment = input("please enter any comments: ")
						comment = latest_report["target"]["file"]["md5"]
						print("comment to be added in the Mcafee NSM :", comment)
						
						url2 = 'https://172.30.72.16/sdkapi/advancedmalware?type=blacklist'
						
                                                #call the fuction that will send the hash to Mcafee IPS
						print("\nblacklisting the hash..\n")
						send_hash(session_ID, user_ID, md5_hash, fileName, comment, url2)
						
						#call the function for Listing the blacklisted hashes
						url1 = 'https://172.30.72.16/sdkapi/advancedmalware/blacklistedhashes'
						query_nsm(session_ID, user_ID, url1)
						cuckoo_monitor()
						
					else:
						print("\nRisk score is low, i'll do nothing for this file and keep watching other files..")
						cuckoo_monitor()
						
            

	finally:
		i.remove_watch(reports_dir)


def session():
    username = b'admin'
    password = b'password'
    # username = input("Enter the admin username: ")
    # password = input('Enter the password: ')
    # username=bytes(username, encoding="ascii")
    # password=bytes(password, encoding="ascii")
    compination = username + b":" + password
    #print("\nCompination of NSM user/pass :", compination)

    s1 = requests.Session()
    myauth = base64.b64encode(compination)
    myauth2 = myauth.decode("utf-8")
    headers = {'NSM-SDK-API': myauth2, 'Accept': 'application/vnd.nsm.v2.0+json', 'Content-Type': 'application/json'}

    session_url = 'https://172.30.72.16/sdkapi/session'

    r = s1.get(session_url, headers=headers, verify=False)
    print("\nMcafee NSM Authentication Status code ", r.status_code)
    print(r.text)

    t = r.json()
    mysession = t['session']
    myuserid = t['userId']
    
    return (mysession, myuserid)

def send_hash(session_ID, user_ID, md5_hash, fileName, comment, url):
    s1 = requests.Session()
    z = bytes(session_ID + ":" + user_ID, encoding="ascii")
    myauth = base64.b64encode(z)
    #print("\nCompination of NSM user ID/session ID:", myauth)
    myauth2 = myauth.decode("utf-8")

    payload = {"fileHash":md5_hash , "fileName":fileName, "comment":comment }
    #print(payload)
    payload2 = json.dumps(payload)
    #print(payload2)
    headers = {'NSM-SDK-API': myauth2, 'Accept': 'application/vnd.nsm.v2.0+json', 'Content-Type': 'application/json'}
    # NSM-SDK-API: Base64 encoded "session:user id" string
    # r=s1.put (url, headers=headers, verify=False, data=payload2)
    try:
        r = s1.post(url, headers=headers, data=payload2, verify=False)
    except Exception as e:
        print(str(e))
    #print("Status code: ", r.status_code)
    #print(r.text)
    t = r.json()
    print("\nMcafee NSM reply post sending the hash: \n",t)

def query_nsm(session_ID, user_ID, url):
    s1 = requests.Session()
    z = bytes(session_ID + ":" + user_ID, encoding="ascii")
    myauth = base64.b64encode(z)
    #print("Compination of NSM user ID/session ID:", myauth)
    myauth2 = myauth.decode("utf-8")
    headers = {'NSM-SDK-API': myauth2, 'Accept': 'application/vnd.nsm.v2.0+json', 'Content-Type': 'application/json'}
    # NSM-SDK-API: Base64 encoded "session:user id" string
    r = s1.get(url, headers=headers, verify=False)
    #print("Status code ", r.status_code)
    t = r.json()
    #print(t)
    print("\nListing all blacklisted hashs added in the Mcafee NSM: \n")
    pprint(t)
    
def main():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	cuckoo_monitor()

if __name__ == "__main__":
    main()
