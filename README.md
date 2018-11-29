# FakeOpenSmtpRelay
FakeOpenSmtpRelay is a collection of scripts, configuration settings and programs to simulate a working open SMTP relay. The solution is based on the following three building blocks:
- INetSim simulates an open SMTP relay server on Internet (tcp/25 & tcp/465), accepting any emails sent to it but relaying nothing further.
- Script FakeOpenSmtpRelay.py checks the INetSim inbox, identifies email probes from wannabe spammers and selectively relays them to their author. This script can be run in an automated way or with user-interaction. Several safeguards are implemented - such as the number of maximum emails relayed per day.
- Optionally, a SMTP server can be installed to monitor remotely the SMTP honeypot and retrieve its logs


## How to get started
1. [Install and configure INetSim](INetSim/)
2. [Download, install and configure script FakeOpenSmtpRelay.py](Scripts/). You need Python version 3 and module dnspython installed (```sudo apt-get install python3-pip && sudo pip3 install dnspython3``` to install dnspython)
3. (Optional) Install your preferred mail daemon to be able to monitor the emails being trapped in your fake open SMTP relay (TODO: steps for dovecot)


## FAQ

### Why should I such a fake open SMTP relay?
(Mal)spam is unfortunately very common. A given share of (mal)spam is sent using open SMTP relays all over the Internet. To find such open SMTP relays, spammers scan the whole Internet for open port tcp/25. The goal of this project is to simulate an open SMTP relay but without forwarding any spam (only the email probes are forwarded).

Fooled spammers might then use your fake open SMTP relay to try to send mass emails, without success. Various safeguards ensure such content never reaches victims. Having such campaigns hitting your honeypot can be useful for research and increase costs & effort to malicious actors.


### My ISP will ban me if I start relaying random emails received from the Internet!
Don't worry, this won't happen! The key point of FakeOpenSmtpRelay is to identify when a message is just a spam or an email probe sent by a spammer to himself to find new vulnerable SMTP open relay servers.

In the author's experience, spammers will first check that an open relay actually relays the message. To verify this, they usually send a few emails to themselves with in the header the IP address (and optionally SMTP credentials) of the open relay. 

[FakeOpenSmtpRelay.py](Scripts/) identifies such email probes and only relays them. Spam messages will not be relayed but kept locally so you can study / report them.


### Why is STARTTLS disabled when receiving emails?
While INetSim claims to support STARTTLS when receiving emails, it does not work according to my tests. Therefore this setting is disabled until the root cause can be determined.
