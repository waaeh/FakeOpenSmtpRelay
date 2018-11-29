# FakeOpenSmtpRelay
Collection of scripts, configuration settings and programs to simulate an open and working open SMTP relay. The solution is based on the following three building blocks:
- INetSim simulates an open SMTP relay server on Internet (tcp/25 & tcp/465), accepting any emails sent to it but relaying nothing further.
- Script FakeOpenSmtpRelay.py checks the INetSim inbox, identifies email probes from wannabe spammers and selectively relays them to their author. This script can be run in an automated way or with user-interaction. Several safeguards are implemented - such as the number of maximum emails relayed per day.
- Optionally, a SMTP server can be installed to monitor remotely the SMTP honeypot and retrieve its logs


## How to get started
1. Install INetSim and adapt it to your needs (see folder TODO)
2. Download, install and configure [script FakeOpenSmtpRelay.py](Scripts/). You need Python version 3 and module dnspython installed (```sudo apt-get install python3-pip && sudo pip3 install dnspython3``` to install dnspython)
3. (Optional) Install your preferred mail daemon to be able to monitor the emails being trapped in your fake open SMTP relay (TODO: steps for dovecot)


## FAQ

### My ISP will ban me if I install and start relaying random emails received from the Internet!
The key point of FakeOpenSmtpRelay is to identify when a message is just a spam or an email probe sent by a spammer to himself to find new vulnerable SMTP open relay servers. In the author's experience, spammers will first check that an open relay actually relays the message. To verify this, they usually send a few emails to themselves with in the header the IP address (and optionally SMTP creds) of the open relay. 

[FakeOpenSmtpRelay.py](Scripts/) identifies such email probes and only relays them. Spam messages will not be relayed.


### Why is STARTTLS disabled when receiving emails?
While INetSim claims to support STARTTLS when receiving emails, it does not work according to my tests. Therefore this setting is disabled until the root cause can be determined.
