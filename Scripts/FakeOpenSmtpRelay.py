#!/usr/bin/python3

import sys
import mailbox
from email.header import decode_header
from email.utils import parseaddr
import email.utils
# TODO: P2 Tidy up unused code such as below
#from configparser import ConfigParser
from datetime import date
from datetime import datetime
import json
from urllib.request import urlopen
import os
# TODO: P2 ensure that dnspython is installed - sudo apt-get install python3-pip && sudo pip3 install dnspython3
import dns.resolver
import socket
import argparse
import copy
import smtplib
import time


# TODO: P2 - "python-ify the various class and function names
# TODO: P2 - "python-ify and create relevant documentation

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


class Helpers:
	def get_path(mailbox_name):
		if '/' in GlobalConfig.MAILBOX_PATH[0]:
			return os.path.join(GlobalConfig.MAILBOX_PATH, mailbox_name)
		else:
			return os.path.join(os.path.expanduser("~"), GlobalConfig.MAILBOX_PATH, mailbox_name)
			
	def get_mailbox(mailbox_name):
		return mailbox.mbox(Helpers.get_path(mailbox_name))

	def choice(options, prompt):
		while True:
			output = input(prompt)
			if output in options:
				return output
			else:
				print("Bad option. Options: " + ", ".join(options))
	
	def trim_str(s, l, ellipsis = True):
		if s is None:
			return ""
		if ellipsis:
			return (s[:l-2] + '..') if len(s) > l else s
		else:
			return (s[:l]) if len(s) > l else s
	
	def get_json_from_url(url):
		j = json.loads(urlopen(url).read().decode())
		return j
		
	def getOpenTcpPorts(hostname, arrPorts):
		result = []
		for p in arrPorts:
			try:
				# Timeout set to 3 seconds
				socket.create_connection((hostname, p), 3)
				result.append(True)
			except:
				result.append(False)
				
		return result
		
	def resetFlags(mbox):
		mbox.lock()
		for key, msg in mbox.iteritems():
			m = mbox[key]
			m.remove_flag("ROA")
			mbox[key] = m
		
		mbox.unlock()
		mbox.flush()


class ParseOpenRelayInbox:
	def __init__(self, startup_args):
		self.configObj = ConfigInEmail()
		self.config = self.configObj.read()
		self.startup_args = startup_args
		
	def listMsgs(self):
		# TODO: P2 refactor with getter
		if self.inbox == None:
			self.inbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_INBOX_NAME)
		
		return self.inbox
			
	
	def Run(self):
		# check that the preconditions to parse the inbox are fullfilled, => verify if we reached various thresholds
		if self.config["global"]["ParseInbox"]:
			self.ParseInbox()
	
	
	def ParseInbox(self):
		# Check if we reached mbox limits, otherwise parse msg and pass emails with no flags to FilterMessage
		if self.config["global"]["todayRelayCount"] > self.config["global"]["maxRelayPerDay"]:
			self.config["global"]["ParseInbox"] = False
			self.config["logs"].append(datetime.now().isoformat() + ": todayRelayCount limit reached, disabling parsing the inbox for today")
			self.configObj.write(self.config)
			return
		
		# Check limit on mailbox size
		self.inbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_INBOX_NAME)
		if len(self.inbox) > self.config["global"]["maxInboxSize"]:
			self.config["global"]["ParseInbox"] = False
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
				if self.FilterMessage(m):
					m.add_flag("A")
					msgToRelay.append(key)
					# The presence of Subject was verified earlier in FilterMessage
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
				rm = RelayMessage(self.inbox, k)
				rm.Verify()
				self.config["logs"].append("Would message be relayed? " + str(rm.canRelay) + " - Details:")
				
				# No interactive mode, testMode enabled if passed so via command line
				rm.relay(False, self.startup_args.testMode)
				
				# Save the logs for this RelayMessage instance
				self.config["global"]["todayRelayCount"] += 1
				self.config["logs"] = self.config["logs"] + rm.logs
									
		self.configObj.write(self.config)
		self.inbox.close()
	
	
	def FilterMessage(self, msg):	
		if "Subject" in msg.keys():
			# We keep this check active so you can "debug" your prod daemon in case of doubt
			if GlobalConfig.TEST_PROBE_RELAY_SUBJECT in msg["Subject"]:
				return True
			
			if self.config['global']['ip'] in msg["Subject"]:
				return True
				
			# Add you other conditions to relay a message here...
			
		return False


class RelayMessage:
	def __init__(self, inbox, msgKey):
		self.inbox = inbox
		self.msg = inbox[msgKey]
		self.msgKey = msgKey
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
	def Verify(self):
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
		hostToPort = {}
		for mx in self.rcptMxAnswers:
			hostname = mx.exchange.to_text()[:-1]
			hostToPort[hostname] = Helpers.getOpenTcpPorts(hostname, refPorts)
			self.logs.append("Support for secure ports on " + hostname + ": " + str(hostToPort[hostname]))
			# Gets the index(es) if there's a secure port to be used
			for index in [i for i, e in enumerate(hostToPort[hostname]) if e == True]:
				self.secureConnSupport = True
				self.rcptBestMx.append( (hostname, refPorts[index]) )
		
		# If no secure port is open, we get the best 3 email servers
		# TODO: P2 have a IPv6 preference for sending emails / selecting exchange servers
		# print(dns.resolver.query('gmail.com', 'MX').response)
		# Explore r.response.additional
		if self.secureConnSupport is False:
			self.rcptMxAnswers.rrset.items.sort(key=lambda x: x.preference)
			for mx in self.rcptMxAnswers.rrset.items[:3]:
				self.rcptBestMx.append( (mx.exchange.to_text()[:-1], 25) )
		
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
			opt = Helpers.choice(['Y', 'N'], "Do you want to send this message (Yes, No)? ")
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
	def __init__(self, msg):
		self.original_msg = msg
		self.relayed_msg = None
	
	def create_relayed_message(self):
		msg = copy.copy(self.original_msg)
		# We first delete all headers we added ourselves
		# TODO: P2 - remove X-Relay-Sendmail-* headers if found, in case someone copies an email from sentProbes to inbox again
		headers_to_delete = ['X-UID', 'Status', 'X-Keywords', 'X-Status', 'Envelope-To', 'Return-Path', 'X-INetSim-Id']
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
		ip = Helpers.get_json_from_url('https://httpbin.org/ip')
		obj = { 'global': {'ip': ip['origin'], 'maxRelayPerDay' : GlobalConfig.MAX_RELAY_PER_DAY, 'todayRelayCount': 0, 'ParseInbox': True, 'maxInboxSize': GlobalConfig.MAX_INBOX_SIZE}, 'logs': []}
		msg.set_payload(json.dumps(obj, indent=2))
		
		self.msgKey = self.mbox.add(msg)
		self.mbox.flush()
		return msg
	
	def read(self):
		#config = ConfigParser()
		#return config.read_string(self.msg.get_payload())
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
	def __init__(self, startup_args):
		# startup_args is a Namespace set via argparser and containing the following key / values
		#	- interactive = False
		# 	- testMode = False
		#	- debug = False
		self.startup_args = startup_args
	
	def run(self):
		if self.startup_args.interactive:
			self.runInteractive()
		else:
			self.runBatch()
			
	def getScreenWidth(self):
		self.rows, self.columns = os.popen('stty size', 'r').read().split()
		self.rows = int(self.rows)
		self.columns = int(self.columns)
		return self.columns
		
	def printMailbox(self, mailbox):
		# Try to optimize the screen size: static colums are 26 char in size. Default match is for a console of 80 char width
		dynSize = (17, 17, 20)
		widthColumns = self.getScreenWidth()
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
	
	def runInteractive(self):
		self.inbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_INBOX_NAME)
		self.printMailbox(self.inbox)
		
		while True:
			opt = Helpers.choice(['R', 'V', 'S', 'Q'], "Enter your choice (Refresh, Verify, Send, Quit): ")
			
			if opt == "Q":
				print("Bye!")
				return
			
			if opt == 'R':
				self.inbox.close()
				self.inbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_INBOX_NAME)
				self.printMailbox(self.inbox)
			
			if opt == 'V':
				indexMail = int(input("Enter the ID of the email to verify: "))
				
				rm = RelayMessage(self.inbox, indexMail)
				rm.Verify()
				for log in rm.logs:
					print (log)
			
			# TODO: P2 merge with V
			if opt == 'S':
				indexMail = int(input("Enter the ID of the email to send: "))
				
				rm = RelayMessage(self.inbox, indexMail)
				rm.Verify()
				for log in rm.logs:
					print (log)
				
				opt = Helpers.choice(['Y', 'N'], "Confirm you want to send this message (Yes, No): ")
				if opt == 'Y':
					# We already run the script in interactive mode, so we force the relay to be interactive as well
					rm.relay(True, self.startup_args.testMode)
				
	# Idea: run it on startup e.g. with https://coderwall.com/p/quflrg/run-a-script-on-startup-in-a-detached-screen-on-a-raspberry-pi
	def runBatch(self):
		while True:	
			p = ParseOpenRelayInbox(self.startup_args)
			p.Run()
			time.sleep(GlobalConfig.BATCH_RUN_INTERVAL)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Manages emails received on a SMTP open relay.')
	parser.add_argument('-i', '--interactive', action='store_true')
	parser.add_argument('-t', '--testMode', action='store_true')
	parser.add_argument('-d', '--debug', action='store_true')
	args = parser.parse_args()
	
	e = Exec(args)
	e.run()
