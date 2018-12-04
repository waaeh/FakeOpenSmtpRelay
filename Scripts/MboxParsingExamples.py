#
#	MBOX PARSING EXAMPLES
#
#
#	This script is part of the FakeOpenSmtpRelay toolkit, available at
#	https://github.com/waaeh/FakeOpenSmtpRelay
#
# 	Sources: https://pymotw.com/2/mailbox/ & https://docs.python.org/3/library/mailbox.html
#

# COMMON PART FOR ALL THE PYTHON SNIPPETS BELOW
# 1. The current path is set to the mbox folder (typically /var/lib/inetsim/smtp/smtp)
# 2. You use python3 as interpreter
import sys
import mailbox
from email.header import decode_header
from email.utils import parseaddr




# Open the inbox mbox and print the subject of each email; decode the subject value if required
mbox = mailbox.mbox('inbox')

for message in mbox:
	subj = decode_header(message['subject'])

	if subj[0][1] is None:
		print(subj[0][0])
	else:
		print((subj[0][0]).decode(subj[0][1]))


		
# Function opening the inbox mbox and parsing the message content to find URLs and store them in array a.
a = []
import re

def scanInboxForUrls():
	mbox = mailbox.mbox('inbox')
	print("Size of MBox:", len(mbox))
	for message in mbox:
		s = message.get_payload(decode=True)
		if s is not None:
			u = re.findall(b'(https?://\S+)"', s)
			if u not in a:
				a.append(u)
				print(u)
				
	
	
# Open the inbox mbox and export the various headers of each email into a standard CSV file
import csv
writer = csv.writer(open("mbox-output.csv", "w"))
mbox = mailbox.mbox('inbox')

for message in mbox:
	subj = decode_header(message['subject'])
	if subj[0][1] is None:
		subj2 = (subj[0][0])
	else:
		subj2 = ((subj[0][0]).decode(subj[0][1]))
	writer.writerow([message['message-id'], subj2, message['from'], message['to']])
	

	
# Almost identical to the previous script (dump details into CSV), but optimized CSV for Excel and further includes the domain of the recipients + the URLs in the email
import csv
writer = csv.writer(open("mbox-report-YYYY-MM-DD_Campaign-C.csv", "w"), dialect='excel')
mbox = mailbox.mbox('inbox')

for message in mbox:
	subj = decode_header(message['subject'])
	if subj[0][1] is None:
		subj2 = (subj[0][0])
	else:
		subj2 = ((subj[0][0]).decode(subj[0][1]))
	a = parseaddr(message['to'])[1].split('@')
	if a != ['']:
		d = a[1]
	s = message.get_payload(decode=True)
	u = re.findall(b'(https?://\S+)', s)
	writer.writerow([message['message-id'], subj2, message['from'], message['to'], d, u])
	

	
# Finally, move all messages matching a given criteria from the inbox to a dedicated mbox
# Caution: run this script while no messages is incoming, as otherwise the purge of the inbox WILL fail
mboxO = mailbox.mbox('inbox')
mboxD = mailbox.mbox('YYYY-MM-DD - Campaign C')

print("Size of MBox origin: ", len(mboxO))
print("Size of MBox destination: ", len(mboxD))

to_transfer = []
mboxD.lock()
for key, msg in mboxO.iteritems():
	
	# Always check if a given header exists before matching criteras onto it
	if msg['Date'] is not None and 'DD MMM YYYY' in msg['Date']:
		if msg['from'] is not None and '[PHISHED_COMPANY]' in msg['from']:
			to_transfer.append(key)
			mboxD.add(msg)

print("Items to tranfert / remove: ", len(to_transfer))
mboxO.lock()
try:
	for key in to_transfer:
		mboxO.remove(key)
finally:
	print("Size of MBox origin: ", len(mboxO))
	print("Size of MBox destination: ", len(mboxD))
	mboxO.flush()
	mboxO.close()
	mboxD.flush()
	mboxD.close()
	
	
	
# As filtering condition: is a given header written in e.g. Cyrillic alphabet? 
import unicodedata

if msg['Subject'] is not None:
	subj = decode_header(msg['Subject'])
	if subj[0][1] is None:
		subj2 = (subj[0][0])
	else:
		subj2 = ((subj[0][0]).decode(subj[0][1]))

	'CYRILLIC' in unicodedata.name(subj2.strip()[0])
