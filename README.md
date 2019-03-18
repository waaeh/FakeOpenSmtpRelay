# FakeOpenSmtpRelay
FakeOpenSmtpRelay.py is a Python3 script simulating a working open SMTP relay. The solution is based on the following three building blocks:
- FakeOpenSmtpRelay.py implements [aiosmtpd](https://github.com/aio-libs/aiosmtpd) to simulate an open SMTP relay server on Internet (tcp/25, tcp/465 and tcp/587), accepting any emails.
- FakeOpenSmtpRelay.py also implements a dynamic rule engine, identifying email probes from wannabe spammers and selectively relays them to their author. This script can be run in an automated way or with user-interaction. Safeguards are implemented to avoid turning into a true open relay in case of a logic flaw - such as the number of maximum emails relayed per day.
- Optionally, a SMTP server can be installed to monitor remotely the SMTP honeypot and retrieve some of its logs


## How to get started
1. Get a running python3 environment (Python version 3.5 or greater), including pip ```sudo apt-get install python3-pip``` and the following installed modules:
    - dnspython (aka dns.python - install it with ```sudo pip3 install dnspython3```)
    - aiosmtpd (install it with ```sudo pip3 install aiosmtpd```)
2. [Download, install and configure script FakeOpenSmtpRelay.py](FakeOpenSmtpRelay.py). Assign execution permissions to the script (```chmod +x FakeOpenSmtpRelay.py```) and review all the settings located in class GlobalConfig, notably:
    - Create or reference certificate files to handle command STARTTLS and explicit TLS SMTP (parameters ```INSTALL_CERTIFICATE_CERT_FILE``` & ```INSTALL_CERTIFICATE_KEY_FILE``` or just run ```openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem``` in the folder you saved FakeOpenSmtpRelay.py)
    - Take note or adapt the ```BASE_PORT_NUMBER``` parameter and configure your router or machine to route traffic for ports tcp/25, tcp/465 & tcp/587 accordingly. This can be done by e.g. configuring NAT rules on your Internet facing router or add iptable PREROUTING & REDIRECT rules.
    - Adapt variables ```TEST_PROBE_RELAY_*``` if you intend to use the test mode (-t, --testMode, see details below)
3. [(Optional) Install your preferred mail daemon](Configuration%20of%20IMAP%20Server.md) to be able to monitor the emails being trapped in your fake open SMTP relay. The provided example uses Dovecot for this purpose.


## Usage of FakeOpenSmtpRelay.py
```
usage: FakeOpenSmtpRelay.py [-h] [-i] [-t] [-d]

Simulates a Fake Open SMTP relay.

optional arguments:
  -h, --help         show this help message and exit
  -i, --interactive
  -t, --testMode
  -d, --debug
```  

Run without any argument, FakeOpenSmtpRelay.py will 
- create a maildir folder (by default in ./maildir - see parameter ```MAILBOX_PATH```)
- start 3 SMTP(S) daemons under the identity of ```FAKE_HOSTNAME``` and save the received messages in ```inbox``` (parameter ```MAILBOX_INBOX_NAME```)
- load a set of default rules to relay email probes containing your server's IP address in the email subject
- relay such email probes to their recipient (up to 20 per day - parameter ```MAX_RELAY_PER_DAY```)
- store a global log in file aiosmtpd.log (archived daily)
- store an additional relay log in an email located in subfolder ```logs``` (parameter ```MAILBOX_LOGS_NAME```)
- keep all relayed messages in subfolder ```sentProbes``` (parameter ```MAILBOX_SENTPROBE_NAME```)

Use the interactive mode (```-i, --interactive```) to manually list, select and relay the messages you want to forward. No SMTP daemons are started in this mode.

Use the test mode (```-t, --testMode```) for all your tests, so that the relaying is done toward one of your server / email account and not directly to the spammer (see variables ```TEST_PROBE_RELAY_*``` in class GlobalConfig).



## FAQ

### Why should I such a fake open SMTP relay?
(Mal)spam is unfortunately very common. A given share of (mal)spam is sent using open SMTP relays all over the Internet. To find such open SMTP relays, spammers scan the whole Internet for open port tcp/25, tcp/465 and/or tcp/587. The goal of this project is to simulate an open SMTP relay but without forwarding any spam (only the email probes are forwarded).

Fooled spammers might then use your fake open SMTP relay to try to send mass emails, without success. Various safeguards ensure such content never reaches victims. Having such campaigns hitting your honeypot can be useful for research and increase costs & effort to malicious actors.


### My ISP will ban me if I start relaying random emails received from the Internet!
Don't worry, this won't happen! The key point of FakeOpenSmtpRelay is to identify when a message is just a spam or an email probe sent by a spammer to himself to find new vulnerable SMTP open relay servers.

In the author's experience, spammers will first check that an open relay actually relays the message. To verify this, they usually send a few emails to themselves with in the header the IP address (and optionally SMTP credentials) of the open relay. 

[FakeOpenSmtpRelay.py](FakeOpenSmtpRelay.py/) identifies such email probes and only relays them. Spam messages will not be relayed but kept locally so you can study / report them.


### I received an email probe, but it wasn't relayed because the criteria are not met. How can I relay it?
First of all, relay it manually using the interactive mode (start [FakeOpenSmtpRelay.py](FakeOpenSmtpRelay.py/) with command line argument ```-i, --interactive``` or running command ```>>> RuleHandler.show_emails()``` in the interactive Python window), then selecting option [R] Relay and then the message to forward. Confirm the various prompts to send the message.

If you want to add a detection condition on whether a message is a probe or not, edit or create your own rule(s) - see below!


### When running the script, I get a Python `SyntaxError: invalid syntax` on line `async def check_port(ip, port, loop):`
[FakeOpenSmtpRelay.py](FakeOpenSmtpRelay.py/) requires at least Python version 3.5 (support of the `async` keyword).


### Why do I get SMTP exception `5.7.1 Command rejected` when trying to relay an email?
Some SMTP servers will reject emails missing key SMTP headers, such as Date. As the email we relay are (almost) unchanged as when they were received, there's nothing we should do. A true open relay would operate the same way, thus have the email rejected as well.


### How many resources does it require?
I run the whole setup on a Rasperry Pi. While idling, less than 20 MB of RAM are used for FakeOpenSmtpRelay.py.

These numbers of course dramatically change when your honeypot is receiving a massive (mal)spam campaign. Consider having enough storage if you don't plan to purge daily your received inbox.

### I won't have time to check the result of the spam traps out daily. Does it matter?
While reviewing daily your logs might be good to best report phishing attempts and tune your rules and spam traps, it isn't required. Having a community of people running a fake open SMTP relay on the Internet should be enough to make the abuse of open relays unattractive to fraudsters.


### The relaying SMTP server used to sent email probes isn't the one referenced in the logs / the official MX of the domain (according to the server EHLO / QUIT message etc). Why?
Several ISPs do a Man-in-the-Middle (MitM) for outbound SMTP connexions on port 25, so you might interact with the ISP's SMTP server instead of the intended MX server. FakeOpenSmtpRelay attempts to prefer SMTPS service with explicit TLS or unconventional ports (ports tcp/587 & tcp/465), but it seems that most major email providers don't offer this service. IPv6 is also preferred, which is sometimes enough to "evade" the ISP MitM and directly connect to the genuine MX server. Note that a true open relay would operate the same way (aside probably the search for explicit TLS enabled services).


### What is the difference between version 0.6 and version 1.0?
[Version 0.6, released back in December 2018](releases/tag/v0.6), used INetSim as SMTP server. This had several disadvantages, now addressed in version 1.0:
- INetSim stored emails in mailbox format mbox, which cannot be processed by two processes simultaneously
- INetSim did not support the usage of STARTTLS or explicit TLS SMTP
- Implementing custom rules or filters was difficult to implement in a consistent way
- Extending the SMTP daemon features was delicate

Version 1.0 addresses all these shortcomings in a pure Python script.


### What is the purpose of the interactive Python prompt once FOSR is loaded?
You can use this interactive Python console to alter on the fly the configuration of FOSR, without having to restart the script / SMTP daemons. A common scenario is to create on the fly a custom filtering rule for an ongoing phishing campaign.

Most useful commands:
- Helpers.get_inbox() returns a maildir object referencing the current inbox
- Class Rule allows you to define your own rules
- Class RuleHelper defines several methods designed to be used in your custom rule
- RuleHandler.show_emails() shows you the emails currently in your inbox and allows you relaying selected messages to their intended recipients
- RuleHandler.load_rules_from_file() loads the rules from file `rules.json`
- RuleHandler.dump_rules_to_file() saves the current ruleset to file `rules.json`
- RuleHandler.purge_inbox_per_rule([rule_object]) applies [rule] to the current inbox.
- RuleHandler.rebuild_filters() is required after you added or edited a rule

See [FOSR_Examples.md](FOSR_Examples.md) for further examples of commands to run within this interactive window.


### FakeOpenSmtpRelay.py works great, thanks! I now have 1'000 / 10'000 / 100'000 / 1'000'000 (mal)spams in my inbox. How do I analyse / handle that volume?
Depending on your server specs, handling more than a few hundreds of emails per IMAP is... _delicate_. [Script FOSR_Examples.md](FOSR_Examples.md) gives examples how to explore, analyse and triage large amounts of emails. It also gives you hint how to use the interactive Python prompt in FOSR.
