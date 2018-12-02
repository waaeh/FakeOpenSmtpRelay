# FakeOpenSmtpRelay
FakeOpenSmtpRelay is a collection of scripts, configuration settings and programs to simulate a working open SMTP relay. The solution is based on the following three building blocks:
- INetSim simulates an open SMTP relay server on Internet (tcp/25 & tcp/465), accepting any emails sent to it but relaying nothing further.
- Script FakeOpenSmtpRelay.py checks the INetSim inbox, identifies email probes from wannabe spammers and selectively relays them to their author. This script can be run in an automated way or with user-interaction. Several safeguards are implemented - such as the number of maximum emails relayed per day.
- Optionally, a SMTP server can be installed to monitor remotely the SMTP honeypot and retrieve its logs


## How to get started
1. [Install and configure INetSim](INetSim/)
2. [Download, install and configure script FakeOpenSmtpRelay.py](Scripts/). You need Python version 3 and module dnspython installed (```sudo apt-get install python3-pip && sudo pip3 install dnspython3``` to install dnspython)
3. [(Optional) Install your preferred mail daemon](IMAP%20Server/) to be able to monitor the emails being trapped in your fake open SMTP relay. The provided example use Dovecot for this purpose.


## FAQ

### Why should I such a fake open SMTP relay?
(Mal)spam is unfortunately very common. A given share of (mal)spam is sent using open SMTP relays all over the Internet. To find such open SMTP relays, spammers scan the whole Internet for open port tcp/25. The goal of this project is to simulate an open SMTP relay but without forwarding any spam (only the email probes are forwarded).

Fooled spammers might then use your fake open SMTP relay to try to send mass emails, without success. Various safeguards ensure such content never reaches victims. Having such campaigns hitting your honeypot can be useful for research and increase costs & effort to malicious actors.


### My ISP will ban me if I start relaying random emails received from the Internet!
Don't worry, this won't happen! The key point of FakeOpenSmtpRelay is to identify when a message is just a spam or an email probe sent by a spammer to himself to find new vulnerable SMTP open relay servers.

In the author's experience, spammers will first check that an open relay actually relays the message. To verify this, they usually send a few emails to themselves with in the header the IP address (and optionally SMTP credentials) of the open relay. 

[FakeOpenSmtpRelay.py](Scripts/) identifies such email probes and only relays them. Spam messages will not be relayed but kept locally so you can study / report them.


### I received an email probe, but it wasn't relayed because the criterias are not met. How can I relay it?
First of all, relay it manually using the interactive mode ([FakeOpenSmtpRelay.py](Scripts/) command line argument ```-i, --interactive```), then selecting option [R] Relay and then the message to forward. Confirm the various prompts to send the message.

If you want to add a detection condition on wherethere a message is a probe or not, edit function ParseOpenRelayInbox.FilterMessage to return True if an email is a probe.


### Why is STARTTLS disabled when receiving emails?
While INetSim claims to support STARTTLS when receiving emails, it does not work according to my tests. Therefore this setting is disabled until the root cause can be determined.


### Why do I get SMTP exception `5.7.1 Command rejected` when trying to relay an email?
Some SMTP servers will reject emails missing key SMTP headers, such as Date. As the email we relay are (almost) unchanged as when they were received, there's nothing we should do. A true open relay would operate the same way, thus have the email rejected as well.


### How many ressources does it require?
I run the whole setup on a Rasperry Pi. While idling, ~100 MB of RAM are used for INetSim (~60 MB) and FakeOpenSmtpRelay.py (~40 MB).

These numbers of course dramatically change when your honeypot is receiving a massive (mal)spam campaign. 


### The relaying SMTP server used to sent email probes isn't the one referenced in the logs / the official MX of the domain (according to the server EHLO / QUIT message etc). Why?
Several ISPs do a Man-in-the-Middle for outbound SMTP connexions on port 25, so you might interact with the ISP's SMTP server instead of the intended MX server. FakeOpenSmtpRelay attempts to prefer SMTPS service with explicit TLS (ports tcp/587 & tcp/465), but it seems that most major email providers don't offer this service. IPv6 is also preferred, which is sometimes enough to "evade" the ISP MitM and directly connect to the genuine MX server. Note that a true open relay would operate the same way (aside probably the search for explicit TLS enabled services. 


### FakeOpenSmtpRelay.py works great, thanks! I now have 1'000 / 10'000 / 100'000 / 1'000'000 (mal)spams in my inbox. How do I analyse / handle that volume?

Depending on your server specs, handling more than a few hundreds of emails per IMAP is... _delicate_. [Script MboxParsingExamples.py](Scripts/MboxParsingExamples.py) gives examples how to explore, analyze and triage large amounts of emails.
