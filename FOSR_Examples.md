# Fake Open SMTP Relay command examples
The script extracts below are mainly designed to be used with the FakeOpenSmtpRelay (FOSR) toolkit, available at https://github.com/waaeh/FakeOpenSmtpRelay.

This page contains three main sections:
- [Commands and actions available in the interactive FOSR prompt](#commands-and-actions-available-in-the-interactive-fosr-prompt)
- [Python3 code to run outside FOSR](#python3-code-to-run-outside-fosr)
- [Code examples (extract from function `RuleHandler.init()`](#rule-examples)



## Commands and actions available in the interactive FOSR prompt

### What is this interactive FOSR prompt?
When you start FakeOpenSmtpRelay.py, you are welcomed by the following screen:
```
$ ./FakeOpenSmtpRelay.py
You have 14 rules loaded, 9 of them being enabled.

Welcome in the FOSR interactive prompt. Type RuleHandler.help() to get help or [Ctrl]+[d] to close the script
and stop all controllers!


>>>
```

This prompt is a standard Python prompt where you can access all loaded Python object, execute desired Python code and alter on the fly FOSR's configuration.


### I just got 1 message in my inbox, how can I have a look at it from Python?

Using FOSR's predefined helpers, you can quickly
1. Create a variable inbox representing this mailbox
2. Request the number of emails in the inbox with method len()
3. Load the only message (index 0 of the inbox's keys()) into variable msg, which is of type [MaildirMessage](https://docs.python.org/3/library/mailbox.html?highlight=maildirmessage#mailbox.MaildirMessage), which is a subclass of [email.message.Message](https://docs.python.org/3/library/email.compat32-message.html#email.message.Message)
4. Start exploring the attributes of variable msg

In the interactive FOSR prompt, type
```python
>>> inbox = Helpers.get_inbox()
>>> len(inbox)
1
>>> msg = inbox[inbox.keys()[0]]
>>> type(msg)
<class 'mailbox.MaildirMessage'>
>>> dir(msg)
['__bytes__', '__class__', '__contains__', '__delattr__', '__delitem__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__gt__', '__hash__', '__init__', '__iter__', '__le__', '__len__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setitem__', '__sizeof__', '__slotnames__', '__str__', '__subclasshook__', '__weakref__', '_become_message', '_charset', '_date', '_default_type', '_explain_to', '_get_params_preserve', '_headers', '_info', '_payload', '_subdir', '_type_specific_attributes', '_unixfrom', 'add_flag', 'add_header', 'as_bytes', 'as_string', 'attach', 'defects', 'del_param', 'epilogue', 'get', 'get_all', 'get_boundary', 'get_charset', 'get_charsets', 'get_content_charset', 'get_content_disposition', 'get_content_maintype', 'get_content_subtype', 'get_content_type', 'get_date', 'get_default_type', 'get_filename', 'get_flags', 'get_info', 'get_param', 'get_params', 'get_payload', 'get_subdir', 'get_unixfrom', 'is_multipart', 'items', 'keys', 'policy', 'preamble', 'raw_items', 'remove_flag', 'replace_header', 'set_boundary', 'set_charset', 'set_date', 'set_default_type', 'set_flags', 'set_info', 'set_param', 'set_payload', 'set_raw', 'set_subdir', 'set_type', 'set_unixfrom', 'values', 'walk']
```

You can access the message's details in various ways, for example

| Python command        | Result                                    | 
|---	                |---                                        |
| ```msg._headers```	| List all SMTP headers and their values    |
| ```msg['Subject']```	| Get a given SMTP header (here the email subject)  |
| ```msg.as_string```	| Displays the whole message as a string  |
| ```msg.get_payload()```	| [Displays the message content, or a list of Messages](https://docs.python.org/3/library/email.compat32-message.html#email.message.Message.get_payload)  |


FOSR adds the following SMTP headers to the email:

| SMTP header        | Description                                    | 
|---	                |---                                        |
| X-Peer    	| String containing tuple source IP address and port number     |
| X-MailFrom    | SMTP envelop MAIL FROM |
| X-RcptTo    	| SMTP envelop RCPT TO   |


Based on object msg, you can start writing a custom lambda expression to filter and identify a given set of messages. The following statement will return ```True``` if
- The sender IP address was `50.X.Y.Z`
- The SMTP message header `From` exists
- This header is a str and not an [object of type Header, used for internationalized values](https://docs.python.org/3/library/email.header.html)
- This header contains string `info@spammerdomain.com`

```python
'50.X.Y.Z' in msg['X-Peer'] and msg['From'] is not None and type(msg['From']) is str
and 'info@spammerdomain.com' in msg['From']
```


### How do FOSR rules work?
A rule (see class `Rule`) is composed of the following attributes:
- Name of the rule
- Priority. The lower the priority, the earlier the rule is executed compared to others
- An array of conditions, which are lambda expressions (typically the type of string we just saw above)
- A boolean value `enabled`. Several predefined rules are provided as examples (see code in `RuleHandler.init()`) and are disabled by default.
- Boolean `save_msg` to save the message on disk
- The name of the mailbox where a message has to be saved (by default `inbox` if `mailbox_folder` is empty)
- Boolean `relay` if the message should be relayed to its intended recipient
- The return code to sent to the client
- `code_on_init` is Python code executed on rule creation, allowing e.g. to define a method extracting phishing URLs out of a message
- `code_on_msg` is a lambda expression executed each time a given rule is triggered. This lambda can e.g. call the def defined in `code_on_init` to parse each message and extract the embedded phishing URL. If the lambda returns `True`, the message is saved otherwise it is just logged.

Rules can then be assigned to one of the following rulesets, having each their trigger and lambda format

| Rule set name          | Trigger                                                  | Lambda format                         |
|---	                 |---                                                       |---                                    |
| RuleHandler.EHLO_rules | Executed after the client sent a EHLO command            | lambda (session, envelope, hostname)  |
| RuleHandler.RSET_rules | Executed after the client sent a RSET command            | lambda (session, envelope)            |
| RuleHandler.AUTH_rules | Executed after the client completed an authentication    | lambda (session, envelope, auth_arr)  |
| RuleHandler.DATA_rules | Executed after the client sent the email, including DATA | lambda (msg)                          |

Examples are available in function `RuleHandler.init()` or [at the end of this document](#rule-examples)


### OK, I get now how rules work and I have defined condition(s) allowing me to identify a set of messages. How can I create my own rule?

Two options exist:
- Create your rule interactively in the Python prompt while running FOSR
- Insert your rule in file `rules.json` once created and reload the ruleset

#### Creating a rule in the interactive FOSR console

You can directly create and insert your new rule in the FOSR interactive prompt:
```python
>>> myNewRule = Rule("My new rule", RuleType.SPAM)
>>> myNewRule   # View the values of this new rule
Object Rule with attributes {'conditions': [], 'enabled': True, 'code_on_msg': None, 'code_on_msg_str': '',
'mailbox_folder': '', 'relay': False, 'name': 'My new rule', 'return_code': 250,
'rule_type': <RuleType.SPAM: 50>, 'code_on_init_str': '', 'return_code_str': '250 OK', 'save_msg': True,
'priority': 100, 'conditions_str': []} and conditions
...
```

Once your rule is created, add it to the relevant ruleset (DATA_rules in the example below) and rebuild the filters to have the change take effect:
```python
>>> RuleHandler.DATA_rules.append(myNewRule)
>>> RuleHandler.rebuild_filters()
```

Rules get written to disk in file `rules.json` when you exit FOSR using the recommended method (pressing [ctrl] + [d]). You can of course force the saving of the rules to prevent accidental losses:
```python
>>> mRuleHandler.dump_rules_to_file()
```


#### Inserting a rule in rules.json
1. Save the current ruleset to disk using the following command in the FOSR interactive prompt:
```python
>>> mRuleHandler.dump_rules_to_file()
```
2. Edit file `rules.json` and add your rule(s). Don't forget to enable rules if you edit existing examples (attribute `enabled`).
3. When done, load the JSON file back by running the following command in the FOSR interactive prompt:
```python
>>> RuleHandler.load_rules_from_file()
You have 14 rules loaded, 9 of them being enabled.
```

FOSR keeps previous versions of file rules.json in case you want to revert your ruleset back.


### My server is getting a spam / phishing campaign and I created a rule to process it. All new emails are now filtered accordingly, but how can I purge my inbox of the 10'000 already received messages?

Function `RuleHandler.purge_inbox_per_rule` runs a rule against the current inbox. If defined in the rule, lambda expression `code_on_msg` will be  executed for each matching message:
```python
>>> myNewRule = Rule("My new rule", RuleType.SPAM)
[...]
>>> RuleHandler.purge_inbox_per_rule(myNewRule)
```

Use `RuleHandler.purge_inbox_per_lambda(msg, lambda)` to delete selected messages matching a given lambda from your inbox. A log entry will be created in aiosmtpd.log with text `msg`:
```python
>>> RuleHandler.purge_inbox_per_lambda('SPAM message (from info@spammerdomain.com)',
... msg['From'] is not None and type(msg['From']) is str and 'info@spammerdomain.com' in msg['From'])
```


### I need further advanced methods to create my lambda expression
Consider having a look at class `RuleHelper` and its functions:
- `get_base64_repr(keyword)` searches for the base64 representation of `keyword`
- `is_str_in_lines(str, lines)` returns True if `str` is found in array of line `lines`
- `get_unicode_name(character)` returns the unicode name of `character`
- `decode_header_content(msg, header_name)` decodes `header_name` of message `msg`



## Python3 code to run outside FOSR
As FOSR is using mailbox format Maildir, you can reasonably safely interact with the inbox from another process. Below are a few examples of pure Python3 code:

```python
# COMMON PART FOR ALL THE PYTHON SNIPPETS BELOW
# 1. The current path is set to the Maildir folder
# 2. You use python3 as interpreter
import sys
import mailbox
from email.header import decode_header
from email.utils import parseaddr


# Open the inbox maildir and print the subject of each email; decode the subject value if required
m = mailbox.Maildir('/path/to/maildir')

for message in m:
	subj = decode_header(message['subject'])

	if subj[0][1] is None:
		print(subj[0][0])
	else:
		print((subj[0][0]).decode(subj[0][1]))


# Moves all messages matching a given criteria to a subfolder
m = mailbox.Maildir('/path/to/maildir')
mO = m.add_folder('YYYY-MM-DD CAMPAIGN_NAME')

print("Size of MBox origin: ", len(m))
print("Size of MBox destination: ", len(mO))

to_transfer = []
for key, msg in m.iteritems():
	
	# Always check if a given header exists before matching criteria onto it
	if msg['From'] is not None and msg['From'].startswith('VICTIM_NAME'):
		to_transfer.append(key)
		mO.add(msg)

print("Items to transfer / remove: ", len(to_transfer))
try:
	for key in to_transfer:
		m.remove(key)
finally:
	print("Size of MBox origin: ", len(m))
	print("Size of MBox destination: ", len(mO))
	m.close()
	mO.close()
```



## Rule examples
Below is an extract of the code provided in function `RuleHandler.init()`. Such rules can be directly created in the FOSR interactive prompt.
```python

# Only rule enabled by default, relaying emails containing the server's IPv4 address in the subject
rule1 = Rule("Relay msg if IP address is present", RuleType.PROBE)
rule1.add_condition("lambda msg: msg['Subject'] is not None and type(msg['Subject']) is str and GlobalConfig.TEST_PROBE_RELAY_SUBJECT in msg['Subject']")
rule1.add_condition("lambda msg: msg['Subject'] is not None and type(msg['Subject']) is str and GlobalConfig.IPV4 in msg['Subject']")
rule1.relay = True
RuleHandler.DATA_rules.append(rule1)

# When enabled, this rule has a higher priority than rules with default priority (100). This allows us to explicitly not relay messages which would otherwise be forwarded by rule1
rule2 = Rule("Known spammers we want to ignore", RuleType.PROBE)
rule2.priority = 50
rule2.add_condition("lambda msg: msg['Subject'] is not None and type(msg['Subject']) is str and 'UNIQUE_STRING_IN_PROBE' in msg['Subject']")
rule2.add_condition("lambda msg: msg['To'] is not None and type(msg['To']) is str and 'XXXX@gmail.com' in msg['To']")
rule2.enabled = False
RuleHandler.DATA_rules.append(rule2)

# Example of a SPAM rule, discarding received messages matching either conditions. The only reference to the received email is in the logs
rule3 = Rule("Unicode spammers", RuleType.SPAM)
rule3.add_condition("lambda msg: msg['From'] is not None and type(msg['From']) is str and msg['From'].startswith('NAME_OF_SPAMMER')")
# Covers emails having a Unicode tick as first character in their subject
rule3.add_condition("lambda msg: msg['Subject'] is not None and type(msg['Subject']) is str and msg['Subject'].startswith('=?UTF-8?b?4pyF?=')")
rule3.save_msg = False
rule3.enabled = False
RuleHandler.DATA_rules.append(rule3)

# Second example of a SPAM rule with high priority to discard all msgs sent by John Doe
rule4 = Rule("Scammer John Doe", RuleType.SPAM)
rule4.save_msg = False
rule4.enabled = False
rule4.priority = 50
rule4.add_condition("lambda msg: msg['From'] is not None and type(msg['From']) is str and 'John Doe' in msg['From']")
RuleHandler.DATA_rules.append(rule4)

# This spam rule relies on helpers in RuleHelper, throwing away emails if the from is in cyrillic
rule5 = Rule("Cyrillic 'from'", RuleType.SPAM)
rule5.add_condition("lambda msg: msg['From'] is not None and type(msg['From']) is email.header.Header and 'CYRILLIC' in RuleHelper.get_unicode_name(RuleHelper.decode_header_content(msg, 'From'))")
rule5.save_msg = False
rule5.enabled = False
RuleHandler.DATA_rules.append(rule5)

# Phisher1 is sending out creative probes we want to relay, including the server's IP address in SMTP header X-SpamInfo instead of subject or within the last 20 lines of the email content
rulePhisher1 = Rule("Phisher1 probes", RuleType.PROBE)
rulePhisher1.add_condition("lambda msg: msg['To'] is not None and type(msg['To']) is str and 'XXXX@hotmail.com' in msg['To']")
rulePhisher1.add_condition("lambda msg: msg['X-SpamInfo'] is not None and type(msg['X-SpamInfo']) is str and GlobalConfig.IPV4 in msg['X-SpamInfo']")
# Is our IP address in the last 20 lines of the payload?
rulePhisher1.add_condition("lambda msg: type(msg.get_payload()) is str and RuleHelper.is_str_in_lines(GlobalConfig.IPV4, msg.get_payload().split('\\n')[-20:])")
rulePhisher1.relay = True
rulePhisher1.enabled = False
RuleHandler.DATA_rules.append(rulePhisher1)

# Here we intercept a phishing campaign which sends its messages from a very specific From address
rulePhisher2 = Rule("Phisher2 campaign", RuleType.PHISH)
rulePhisher2.add_condition("lambda msg: msg['From'] is not None and type(msg['From']) is str and 'XXXXX@XXXX.com' in msg['From']")
rulePhisher2.save_msg = False
# We want to be sure that the rule gets executed after the IP lookup
rulePhisher2.priority = 110
# The following code will be run when the rule is created, defining a custom function get_Phisher2_urls and a global empty array Phisher2_urls
# If the URL retrieved in the email is new, we return True, causing the message to be saved in our inbox
#pylint: disable=anomalous-backslash-in-string
rulePhisher2.set_code_on_init(
"""
Phisher2_urls = []
def get_Phisher2_urls(msg):
	p = base64.b64decode(msg.get_payload().replace('\\n',''))
	urls = re.findall('<a href="(https?://\S+)"', str(p))
	for url in set(urls):
		if url not in Phisher2_urls:
			logging.warn('Phishing URL - %s' % url)
			Phisher2_urls.append(url)
			return True

	return False
""" 
)
rulePhisher2.set_code_on_msg("lambda msg: get_Phisher2_urls(msg)")
rulePhisher2.enabled = False
RuleHandler.DATA_rules.append(rulePhisher2)


# OTHER TEST RULES
t = Rule("TEST RSET RULE", RuleType.PROBE)
t.add_condition("lambda session, envelope: session.host_name == GlobalConfig.TEST_PROBE_RELAY_SUBJECT")
t.return_code_str = '200 LOL'
t.enabled = False
RuleHandler.RSET_rules.append(t)

t2 = Rule("TEST EHLO RULE", RuleType.PROBE)
t2.add_condition("lambda session, envelope, hostname: hostname == GlobalConfig.TEST_PROBE_RELAY_SUBJECT")
t2.return_code_str = '200 LOL'
t2.enabled = False
RuleHandler.EHLO_rules.append(t2)

ruleAuth1 = Rule("TEST AUTH RULE", RuleType.PROBE)
ruleAuth1.enabled = False
ruleAuth1.add_condition("lambda session, envelope, args: session.auth is not None and type(session.auth) is tuple and len(session.auth) == 2 and session.auth[0] == 'XXXX' and session.auth[1] == 'XXXX'")
RuleHandler.AUTH_rules.append(ruleAuth1)

t_code = Rule("TEST CODE RULE", RuleType.PHISH)
t_code.add_condition("lambda msg: msg['Subject'] is not None and msg['Subject'] == 'My_super_secret_subject'")
t_code.save_msg = False
t_code.set_code_on_init(
"""
Test_test_test_msg = []
def Test_test_test_def(msg):
	p = msg.get_payload().replace('\\n','')
	if p not in Test_test_test_msg:
		logging.warn('New email content - %s' % p)
		Test_test_test_msg.append(p)
		return True

	return False
""" 
)
t_code.set_code_on_msg("lambda msg: Test_test_test_def(msg)") 
t_code.enabled = False
RuleHandler.DATA_rules.append(t_code)


RuleHandler.rebuild_filters()

```