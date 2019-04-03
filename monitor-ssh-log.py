#!/usr/bin/env python

import re, smtplib, requests

"""
Author: PythonBlack
Description: This script will read the ssh log and loook for new connections.
Once a new connection is found and the IP address is not in the whitelist,it will send me a text message from an email
account with the IP address of the user and the username of the login.
"""
# Whitelisted IPs
ip_whitelist = [] # Example ["1.1.1.1","2.2.2.2","3.3.3.3"]


# Compile regex expressions to match content
ipaddr = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

def iplocation(ip,user,date):
    url = "http://iplocation.com/?ip="

    # Query geo-ip service and save response in JSON
    response = requests.post(url+ip)
    json_response = response.json()

    # Parse response and take needed values for message
    for k,v in json_response.items():
        if k == "city":
            city = v
        if k == "region_name":
            region = v
        if k == "country_name":
            country = v
        if k == "postal_code":
            postal_code = v
        if k == "company":
            organization = v
    sendtext(ip,user,date,city,region,country,postal_code,organization)

def sendtext(ip,user,date,city,region,country,postal_code,organization):
    # Declare login (messge sent from this address)
    email_provider = "smtp.example.com"   # CHANGE EMAIL PROVIDER
    email_address = "example@example.com" # CHANGE EMAIL ADDRESS
    email_port = 587                      # CHANGE EMAIL PORT
    password = ""                         # ADD PASSWORD

    # Recepient
    phone_num = "1112223333@txt.bell.ca"  # Example txt addresses ["@txt.bell.ca", "@pcs.rogers.com", "@fido.ca", "@txt.windmobile.ca", "@msg.telus.com"]

    msg = """*ALERT*
New SSH login on host:
IP address: {ip}
User: {user}
When: {date}

IP Details:
Location: {city}, {region}, {country}, {postal_code}\nOrganization: {organization}"""

    # Login to server
    server = smtplib.SMTP(email_provider, email_port)
    server.starttls()
    server.login(email_address, password)

    # Send text message and logout
    server.sendmail(email_address,phone_num,msg.format(date=date,ip=ip,user=user,city=city,region=region,country=country,postal_code=postal_code,organization=organization))
    server.quit()

    monitor() # Return to monitoring log

def monitor():
    with open("/var/log/auth.log", "rb") as log: # Edit the path to
        while True:
            log.seek(0,2)
            for line in log:
		if "Accepted password" in line:
	    	    #log_ip = re.findall(ipaddr, line)
	    	    ip = line.split()[10]
		    date = line[:15]
		    user = line.split()[8]
		    print user
		    print date
	   	    print ip
		    if ip in ip_whitelist:
			print "Login from approved IP\n"
			pass
		    else:
		        #sendtext(ip,user,date)
		        iplocation(ip,user,date)
monitor()
