#!/usr/bin/python3

import sys
import mailbox
from email.header import decode_header
from email.utils import parseaddr
import email.utils
from datetime import date
from datetime import datetime
import json
from urllib.request import urlopen
import os
import dns.resolver
import socket
import argparse
import copy
import smtplib
import time
import asyncio



class GlobalConfig:
	"""This class stores the global configurations you may want to adapt for your installation."""
	
	FAKE_HOSTNAME = 'mail.localhost'
	# If run in batch mode, will run every X seconds
	BATCH_RUN_INTERVAL = 300
	
	# A relative MAILBOX_PATH path will be interpreted starting from the user's home folder 
	MAILBOX_PATH = "smtp/smtp/"
	MAILBOX_INBOX_NAME = 'inbox'
	MAILBOX_LOGS_NAME = 'logs'
	MAILBOX_SENTPROBE_NAME = 'sentProbes'
	
	# The script forwards max MAX_RELAY_PER_DAY messages per day to avoid being used as spam relay
	MAX_RELAY_PER_DAY = 10
	# To avoid mbox corruption and not put load on the machine, we don't parse the mbox if it contains 
	# more than MAX_INBOX_SIZE messages
	MAX_INBOX_SIZE = 20
	
	# Relays the message if the following string is found in the subject of an email
	# To facilitate your tests, consider using swaks:
	# $ swaks --to proberecipient@malicious.com --server smtp.example.org --from victim@example.com --header "Subject: TEST-EMAIL_bd5328c8"
	TEST_PROBE_RELAY_SUBJECT = 'TEST-EMAIL_bd5328c8'
	TEST_PROBE_RELAY_SMTPFROM = 'sender@example.org'
	TEST_PROBE_RELAY_SMTPTO = 'recipient@example.org'
	TEST_PROBE_RELAY_SERVER = [('smtp.example.org', 25)]
	# Set this variable to True if your TEST_PROBE_RELAY_SERVER server supports explicit TLS on tcp/465 or tcp/587
	TEST_PROBE_RELAY_SERVER_EXPLICIT_TLS = False

	# Configuration settings IPV6_* only apply if your machine has IPv6 connectivity to Internet.
	# If your machine does NOT have IPv6, ignore these settings as they are irrelevant for you
	
	# IPV6_FORCE_IPV4_MX_FOR_DOMAINS forces the script to connect to the IPv4 address of the MX for all listed domains. 
	# This is mainly due to some providers (typically GMail) requesting PTR records for IPv6 addresses used to send mails.
	# (see https://github.com/waaeh/FakeOpenSmtpRelay/issues/1)
	# If you have IPv6 connectivity AND you have a valid PTR record for the IPv6 address used to relay mail, simply set [].
	IPV6_FORCE_IPV4_MX_FOR_DOMAINS = ['gmail.com']



class Helpers:
	"""Helper class with static methods usable in the whole project."""
	
	def get_path(mailbox_name):
		"""Returns an absolute path for a given mailbox_name."""
		if '/' in GlobalConfig.MAILBOX_PATH[0]:
			return os.path.join(GlobalConfig.MAILBOX_PATH, mailbox_name)
		else:
			return os.path.join(os.path.expanduser("~"), GlobalConfig.MAILBOX_PATH, mailbox_name)
	
	
	def get_mailbox(mailbox_name):
		"""Returns a mailbox object for a given mailbox_name."""
		return mailbox.mbox(Helpers.get_path(mailbox_name))
	
	
	def prompt_choice(options, prompt):
		"""Proposes options to the choice to the user, with prompt as description."""
		while True:
			output = input(prompt)
			if output in options:
				return output
			else:
				print("Bad option. Options: " + ", ".join(options))
	
	
	def trim_str(s, l, ellipsis = True):
		"""Trims string s to length l-2 and completes the string with "..", unless ellipsis is set to False."""
		if s is None:
			return ""
		if ellipsis:
			return (s[:l-2] + '..') if len(s) > l else s
		else:
			return (s[:l]) if len(s) > l else s
	
	
	def get_json_from_url(url):
		"""Requests value from url, assumes the response is a JSON string and converts it directly to a Python object."""
		j = json.loads(urlopen(url).read().decode())
		return j
	
	
	async def check_port(ip, port, loop):
		"""Async port scanner - source: http://gunhanoral.com/python/2017/07/04/async-port-check.html"""
		conn = asyncio.open_connection(ip, port, loop=loop)
		try:
				reader, writer = await asyncio.wait_for(conn, timeout=5)
				# TODO: P2 - enable in verbose / debug mode
				#print(ip, port, 'ok')
				#return (ip, port, True)
				return {'hostname': ip, 'port': port, 'open': True}
		except:
				# TODO: P2 - enable in verbose / debug mode
				#print(ip, port, 'nok')
				#return (ip, port, False)
				return {'hostname': ip, 'port': port, 'open': False}
	
	
	async def get_open_tcp_ports_async(dests, ports, loop):
		"""Async scheduler for port scanner - source: http://gunhanoral.com/python/2017/07/04/async-port-check.html"""
		tasks = [asyncio.ensure_future(Helpers.check_port(d, p, loop)) for d in dests for p in ports]
		responses = await asyncio.gather(*tasks)
		return responses
	
	
	def get_open_tcp_ports(hostnames, arr_ports):
		"""Async port scanner helper - source: http://gunhanoral.com/python/2017/07/04/async-port-check.html"""
		#print("%s: Starting..." % datetime.now().isoformat())
		loop = asyncio.get_event_loop()
		future = asyncio.ensure_future(Helpers.get_open_tcp_ports_async(hostnames, arr_ports, loop))
		loop.run_until_complete(future)
		#print('#'*50)
		#print('Results: ', future.result())
		#print('#'*50)
		#print('Total time: ', time.time() - now)
		return future.result()
	
	
	def reset_flags(mbox):
		"""Only useful for debugging / testing purposes. Resets all the flags of all messages in a given mbox object."""
		mbox.lock()
		for key, msg in mbox.iteritems():
			m = mbox[key]
			m.remove_flag("ROA")
			mbox[key] = m
		
		mbox.unlock()
		mbox.flush()



class ParseOpenRelayInbox:
	"""Logic to periodically parse an inbox. Contains various safeguards / limits to avoid spam diffusion and performance issues."""

	def __init__(self, startup_args):
		self.configObj = ConfigInEmail()
		self.config = self.configObj.read()
		self.startup_args = startup_args
	
	
	def run(self):
		# check that the preconditions to parse the inbox are fullfilled, => verify if we reached various thresholds
		if self.config["global"]["parseInbox"]:
			self.parse_inbox()
	
	
	def parse_inbox(self):
		# Check if we reached mbox limits, otherwise parse msg and pass emails with no flags to filter_message
		if self.config["global"]["todayRelayCount"] > self.config["global"]["maxRelayPerDay"]:
			self.config["global"]["parseInbox"] = False
			self.config["logs"].append(datetime.now().isoformat() + ": todayRelayCount limit reached, disabling parsing the inbox for today")
			self.configObj.write(self.config)
			return
		
		# Check limit on mailbox size
		self.inbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_INBOX_NAME)
		if len(self.inbox) > self.config["global"]["maxInboxSize"]:
			self.config["global"]["parseInbox"] = False
			self.config["logs"].append(datetime.now().isoformat() + ": maxInboxSize limit reached, disabling parsing the inbox for today")
			self.configObj.write(self.config)
			return
		
		msgToRelay = []
		self.inbox.lock()
		
		# We only rely on the key, not on msg, as alteration to msg aren't recorded in the mailbox...
		for key, msg in self.inbox.iteritems():
			m = self.inbox[key]
			# If the message is new and hasn't been read
			if 'R' not in m.get_flags():
				m.add_flag("R")
				if self.filter_message(m):
					m.add_flag("A")
					msgToRelay.append(key)
					# The presence of Subject was verified earlier in filter_message
					self.config["logs"].append(datetime.now().isoformat() + (": got 1 new message, which would get relayed: %s" % m["Subject"]))
					self.config["logs"].append(datetime.now().isoformat() + (": flag for msg %s: %s" % (m["Subject"], m.get_flags())))
				else:
					self.config["logs"].append(datetime.now().isoformat() + ": got 1 new message, which would NOT get relayed")
				
				# Required so that the flag is saved
				self.inbox[key] = m
				#self.config["logs"].append(datetime.now().isoformat() + (": VERIFICATION - flag for msg %s: %s" % (m["Subject"], self.inbox[key].get_flags())))
		
		self.inbox.unlock()
		self.inbox.flush()
		
		# TODO: P2 - add if the numbers of msgToRelay is above the daily limit and log the occurence
		if len(msgToRelay) > 0:
			self.config["logs"].append(datetime.now().isoformat() + ": verification results of the " + str(len(msgToRelay)) + " new message(s) which would get relayed:")
			# Iteration through a list of message keys
			for k in msgToRelay:
				rm = RelayMessage(self.inbox, k, self.config['global']['ipv4'])
				rm.verify()
				self.config["logs"].append("Would message be relayed? " + str(rm.canRelay) + " - Details:")
				
				# No interactive mode, testMode enabled if passed so via command line
				rm.relay(False, self.startup_args.testMode)
				
				# Save the logs for this RelayMessage instance
				self.config["global"]["todayRelayCount"] += 1
				self.config["logs"] = self.config["logs"] + rm.logs
									
		self.configObj.write(self.config)
		self.inbox.close()
	
	
	def filter_message(self, msg):
		"""Key function: received a email as msg and returns True if it's identified as an email probe worth relaying further."""
		if "Subject" in msg.keys():
			# We keep this check active so you can "debug" your prod daemon in case of doubt
			if GlobalConfig.TEST_PROBE_RELAY_SUBJECT in msg["Subject"]:
				return True
			
			# We only search for IPv4 addresses right now.
			# INetSim doesn't handle IPv6 inbound emails as far as I tried out
			if self.config['global']['ipv4'] in msg["Subject"]:
				return True
				
			# Add you other conditions to relay a message here...
			
		return False



class RelayMessage:
	"""Routines to verify if a message can be relayed and perform the relay if desired. If in TestMode , configurations GlobalConfig.TEST_PROBE_RELAY_* will be used for the relay."""

	def __init__(self, inbox, msgKey, ipv6_address = None):
		self.inbox = inbox
		self.msg = inbox[msgKey]
		self.msgKey = msgKey
		self.ipv6_address = ipv6_address
		self.canRelay = True
		self.logs = []
		self.rcpt = None
		self.smtpFrom = None
		self.secureConnSupport = False
		self.secureConnList = []
		self.rcptBestMx = []
		self.verifyDone = False
		self.sent_probes_mbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_SENTPROBE_NAME)
		
	
	# TODO: P2 investigate why this step can take soooo long (portscan?)
	def verify(self):
		if self.msg["Envelope-To"] is None:
			self.logs.append("No Envelope-To address")
			self.canRelay = False
		else:
			self.rcpt = self.msg["Envelope-To"]
			self.logs.append("Email would be relayed to " + self.rcpt)
			
		if self.msg["Return-Path"] is None:
			self.logs.append("No Return-Path address")
			self.canRelay = False
		else:
			self.smtpFrom = self.msg["Return-Path"]
			self.logs.append("Email would be relayed with SMTP envelope sender " + self.smtpFrom)
			
		# Get rcpt domain details
		if self.rcpt is not None:
			self.rcptDomain = self.rcpt.split("@")[1]
			self.rcptMxAnswers = dns.resolver.query(self.rcptDomain, 'MX')
			self.logs.append("Domain " + self.rcptDomain + " has " + str(len(self.rcptMxAnswers)) +" MX servers: " + ("; ".join(map(str,self.rcptMxAnswers))))
			if len(self.rcptMxAnswers) == 0:
				self.logs.append("No MX server for domain " + self.rcptDomain)
				self.canRelay = False
		
		
		refPorts = [587, 465]
		mx_servers = [r.exchange.to_text()[:-1] for r in self.rcptMxAnswers]
		scan_results = Helpers.get_open_tcp_ports(mx_servers, refPorts)

		# If there are services allowing explicit TLS found...
		secure_services_arr = [m for m in scan_results if m['open'] == True]
		if secure_services_arr:
			self.secureConnSupport = True
			for svc in secure_services_arr:
				self.logs.append("Support for secure port on %s, port %i" % (svc.hostname, svc.port))
				self.rcptBestMx.append( (svc.hostname, svc.port) )
		else:
			self.logs.append("No support for secure ports found... ")	
			# If no secure port is open, we get the best 3 email servers
			# TODO: P2 have a IPv6 preference for sending emails / selecting exchange servers
			# print(dns.resolver.query('gmail.com', 'MX').response)
			# Explore r.response.additional
			# r.response.additional[1].rdtype etc; 1 = A, 28 = AAAA
			# r.response.additional[1][0].address = IP address
			self.rcptMxAnswers.rrset.items.sort(key=lambda x: x.preference)
			for mx in self.rcptMxAnswers.rrset.items[:3]:
				self.rcptBestMx.append( (mx.exchange.to_text()[:-1], 25) )
		
		# Once we have our list of preferred MX servers, we need to check if we have some IPv6 edge case
		if self.ipv6_address is not None:
			# Verify the config only if we have an IPv6 address
			if self.rcptDomain in GlobalConfig.IPV6_FORCE_IPV4_MX_FOR_DOMAINS:
				# Get server, resolve ipv4 and force the IPv4 as host
				updated_rcptBestMx = []
				for mx in self.rcptBestMx:
					mx_a_response = dns.resolver.query(mx[0], 'A')
					ipv4_of_mx = mx_a_response.rrset[0].address
					updated_rcptBestMx.append( (ipv4_of_mx, mx[1]) )
				
				self.rcptBestMx = updated_rcptBestMx
				
		
		self.logs.append("Has support for Secure connexion: " + str(self.secureConnSupport))
		for i in self.rcptBestMx:
			self.logs.append("Possible connexions: %s:%i" % i)
			
		self.verifyDone = True
	
	
	def relay(self, interactive=True, testMode=True):
		# We assume that all verifications were 
		if self.verifyDone is False:
			print("Message was not verified first. Perform this action before trying to relay it")
			return
		
		if self.canRelay is False:
			print("Message cannot be relayed - canRelay = False. See logs for further details")
			return
	
		pm = ProbeMessage(self.msg)
		pm.create_relayed_message()
		new_msg = pm.get_relayed_message()
		
		if testMode:
			self.smtpFrom = GlobalConfig.TEST_PROBE_RELAY_SMTPFROM
			self.rcpt = GlobalConfig.TEST_PROBE_RELAY_SMTPTO
			self.rcptBestMx = GlobalConfig.TEST_PROBE_RELAY_SERVERS
			self.secureConnSupport = GlobalConfig.TEST_PROBE_RELAY_SERVERS_EXPLICIT_TLS
		
		if interactive:
			print("\n\n" + new_msg.as_string() + "\n")
			print("This message will be sent with SMTP envelop From: %s -> To: %s" % (self.smtpFrom, self.rcpt))
			opt = Helpers.prompt_choice(['Y', 'N'], "Do you want to send this message ([Y]es, [N]o)? ")
			if opt == 'N':
				return
		
		# Sending the message
		# TODO: P2 enhance error handling and rotate across servers
		self.logs.append("Trying to send message '%s' from %s to %s using server %s..." % (new_msg["Subject"], self.smtpFrom, self.rcpt, self.rcptBestMx[0]))
		if self.secureConnSupport:
			# TODO: P2 This doesn't work as expected... FIXME
			server = smtplib.SMTP_SSL(self.rcptBestMx[0][0], self.rcptBestMx[0][1], GlobalConfig.FAKE_HOSTNAME, None, None, 30)
		else:
			server = smtplib.SMTP(self.rcptBestMx[0][0], self.rcptBestMx[0][1], GlobalConfig.FAKE_HOSTNAME, 30)
		
		server.set_debuglevel(1)
		smtplib_sendmail_res = None
		smtplib_sendmail_quit = None
		smtplib_sendmail_exception = None
		try:
			# If we're connecting over plain SMTP, we need to
			# 1. send a ehlo
			# 2. check the server capabilities for STARTTLS
			# 3. if available enable STARTTLS and reissue ehlo
			if self.secureConnSupport is False:
				server.ehlo(GlobalConfig.FAKE_HOSTNAME)
				if 'starttls' in server.esmtp_features:
					server.starttls()
			
			server.ehlo(GlobalConfig.FAKE_HOSTNAME)
			smtplib_sendmail_res = server.sendmail(self.smtpFrom, self.rcpt, new_msg.as_string())
			smtplib_sendmail_quit = server.quit()
		except Exception as inst:
			print(type(inst))     # the exception instance
			print(inst.args)      # arguments stored in .args
			smtplib_sendmail_exception = inst
			#print(inst)           # __str__ allows args to be printed directly
			self.logs.append("Error while trying to send message: %s" % inst)
			print("Error while trying to send message: %s" % inst)
		
		
		self.logs.append("smtplib terminated with sendmail status '%s' and quit '%s'" % (smtplib_sendmail_res, smtplib_sendmail_quit))
		print("smtplib terminated with sendmail status '%s' and quit '%s'" % (smtplib_sendmail_res, smtplib_sendmail_quit))
		
		# Store in the sent probes folder
		self.sent_probes_mbox.lock()
		# Adds the result of the sending probe in a header before storing it
		new_msg.add_header("X-Relay-Sendmail-Date", datetime.now().isoformat())
		new_msg.add_header("X-Relay-Sendmail-Sent", str(smtplib_sendmail_res))
		new_msg.add_header("X-Relay-Sendmail-Quit", str(smtplib_sendmail_quit))
		new_msg.add_header("X-Relay-Sendmail-Exception", str(smtplib_sendmail_exception))
		# Add a flag on the original message in the inbox that the message has been read and answered (RA)
		msg_in_inbox = self.msg
		msg_in_inbox.add_flag("RA")
		self.inbox[self.msgKey] = msg_in_inbox
		self.sent_probes_mbox.add(new_msg)
		self.sent_probes_mbox.unlock()
		self.sent_probes_mbox.flush()



class ProbeMessage:
	"""Converts a received email / probe message into a message ready to be relayed."""

	def __init__(self, msg):
		self.original_msg = msg
		self.relayed_msg = None
	

	def create_relayed_message(self):
		msg = copy.copy(self.original_msg)
		# We first delete all headers we added ourselves
		# TODO: P2 - remove X-Relay-Sendmail-* headers if found, in case someone copies an email from sentProbes to inbox again
		headers_to_delete = ['X-UID', 'Status', 'X-Keywords', 'X-Status', 'Envelope-To', 'Return-Path', 'X-INetSim-Id', '"X-INetSim-RCPT']
		for h in headers_to_delete:
			del(msg[h])
			
		# By default, the received header containing details about our honeypot will be stored in msg["Received"], regardless of many hopes it had before
		msg.replace_header('Received', msg['Received'].replace('victim', 'sender').replace('cheater (INetSim)', GlobalConfig.FAKE_HOSTNAME))
		
		# TODO: P3 add hop in received??
		self.relayed_msg = msg
	

	def get_relayed_message(self):
		# TODO: P2 error handling
		return self.relayed_msg



class ConfigInEmail:
	"""Daily logs and configuration are stored in an email in mailbox logs. This class assists in creating, retrieving or saving content."""

	def __init__(self):
		self.todayDate = date.today().isoformat()
		self.mbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_LOGS_NAME)
		#self.mbox.lock()
		if len(self.mbox) == 0 or self.mbox[len(self.mbox)-1]["Subject"] != "Logs from " + self.todayDate:
			self.msg = self.create_new_config()
		else:
			self.msgKey = len(self.mbox)-1
			self.msg = self.mbox[self.msgKey]
	

	def __del__(self):
		#self.mbox.unlock()
		self.mbox.flush()
		self.mbox.close()
	

	def create_new_mail(self):
		msg = mailbox.mboxMessage()
		address = email.utils.formataddr(('InetSim Relayer', 'tests@example.com'))
		# See https://pymotw.com/3/mailbox/
		#msg.set_unixfrom("InetSimRelayer " + datetime.now().strftime("%a %b %d %H:%M:%S %Y")) 
		msg["Date"] = email.utils.formatdate()
		msg["Message-ID"] = email.utils.make_msgid("logs-" + self.todayDate)
		msg["From"] = address
		msg["To"] = address
		msg["Subject"] = "Logs from " + self.todayDate
		return msg


	def create_new_config(self):
		msg = self.create_new_mail()
		ipv4 = Helpers.get_json_from_url('https://v4.ident.me/.json')['address']
		ipv6 = None
		try:
			ipv6 = Helpers.get_json_from_url('https://v6.ident.me/.json')['address']
		except:
			# We dont do anything special if no IPv6 is found, variable is already set to None
			pass
			
		obj = {
			'global':
				{
					'ipv4': ipv4,
					'ipv6': ipv6,
					'maxRelayPerDay' : GlobalConfig.MAX_RELAY_PER_DAY,
					'todayRelayCount': 0,
					'parseInbox': True,
					'maxInboxSize': GlobalConfig.MAX_INBOX_SIZE
				},
			'logs': []
		}
		msg.set_payload(json.dumps(obj, indent=2))
		
		self.msgKey = self.mbox.add(msg)
		self.mbox.flush()
		return msg
	

	def read(self):
		return json.loads(self.msg.get_payload())
	

	def write(self, config):
		# Only write back the config when a change actually occured
		if config != json.loads(self.msg.get_payload()):
			newMsg = self.create_new_mail()
			newMsg.set_payload(json.dumps(config, indent=2))
			#self.mbox.remove(self.msg)
			self.mbox.remove(self.msgKey)
			self.msgKey = self.mbox.add(newMsg)
			self.msg = newMsg
			self.mbox.flush()



class Exec():
	"""Handles the various runtime modes. This is the class to be run to start the program."""

	def __init__(self, startup_args):
		# startup_args is a Namespace set via argparser and containing the following key / values
		#	- interactive = False
		# 	- testMode = False
		#	- debug = False
		# TODO: P2 - enhance console logs in batch mode
		# TODO: P2 - implement -debug across the board to be verbose output. Hide irrelevant txt (typically SMTP relaying).
		self.startup_args = startup_args


	def run(self):
		# Check prerequisits
		if 'dns.resolver' not in sys.modules:
			print("This script requires module dns.resolver. Please install it before re-running the script:")
			print("E.g. sudo apt-get install python3-pip && sudo pip3 install dnspython3")
			raise

		if self.startup_args.interactive:
			self.run_interactive()
		else:
			self.run_batch()

			
	def get_screen_width(self):
		self.rows, self.columns = os.popen('stty size', 'r').read().split()
		self.rows = int(self.rows)
		self.columns = int(self.columns)
		return self.columns


	def print_mailbox(self, mailbox):
		# Try to optimize the screen size: static colums are 26 char in size. Default match is for a console of 80 char width
		dynSize = (17, 17, 20)
		widthColumns = self.get_screen_width()
		if widthColumns > 80:
			widthToDistribute = int((widthColumns - 80) / 3)
			dynSize = tuple(x+widthToDistribute for x in dynSize)
		
		tableFormat = '%-3i%-5s%-18s' + '%-' + str(dynSize[0]) + 's%-' + str(dynSize[1]) + 's%-' + str(dynSize[2]) + 's'
		
		# TODO: P2 fix subject if Unicode with the emails.util helper
		# TODO: P2 add column "would relay" Y / N
		for key, msg in mailbox.iteritems():
			content = (
				key,
				msg.get_flags(),
				Helpers.trim_str(msg["Date"],17, False),
				Helpers.trim_str(msg["Return-Path"], dynSize[0]),
				Helpers.trim_str(msg["Envelope-To"], dynSize[1]),
				Helpers.trim_str(msg["Subject"], dynSize[2])
			)
			print(tableFormat % (content))
	

	def run_interactive(self):
		self.inbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_INBOX_NAME)
		self.print_mailbox(self.inbox)
		ipv6 = None
		try:
			ipv6 = Helpers.get_json_from_url('https://v6.ident.me/.json')['address']
		except:
			# We dont do anything special if no IPv6 is found, variable is already set to None
			pass
		
		while True:
			opt = Helpers.prompt_choice(['R', 'V', 'S', 'Q'], "Enter your prompt_choice ([R]efresh, [V]erify, [S]end, [Q]uit): ")
			
			if opt == "Q":
				print("Bye!")
				return
			
			if opt == 'R':
				self.inbox.close()
				self.inbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_INBOX_NAME)
				self.print_mailbox(self.inbox)
			
			# Option Verify and Send share the same initial steps (verify)
			if opt in ['V', 'S']:
				if opt == 'S':
					input_text = "Enter the ID of the email to verify: "
				else:
					input_text = "Enter the ID of the email to send: "

				indexMail = int(input(input_text))				
				rm = RelayMessage(self.inbox, indexMail, ipv6)
				rm.verify()
				for log in rm.logs:
					print (log)

				# Specific code branch for sending emails
				if opt == 'S':
					opt = Helpers.prompt_choice(['Y', 'N'], "Confirm you want to send this message ([Y]es, [N]o): ")
					if opt == 'Y':
						# We already run the script in interactive mode, so we force the relay to be interactive as well
						rm.relay(True, self.startup_args.testMode)


	# Idea: run it on startup e.g. with https://coderwall.com/p/quflrg/run-a-script-on-startup-in-a-detached-screen-on-a-raspberry-pi
	def run_batch(self):
		while True:	
			p = ParseOpenRelayInbox(self.startup_args)
			p.run()
			time.sleep(GlobalConfig.BATCH_RUN_INTERVAL)



if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Manages emails received on a SMTP open relay.')
	parser.add_argument('-i', '--interactive', action='store_true')
	parser.add_argument('-t', '--testMode', action='store_true')
	parser.add_argument('-d', '--debug', action='store_true')
	args = parser.parse_args()
	
	e = Exec(args)
	e.run()
