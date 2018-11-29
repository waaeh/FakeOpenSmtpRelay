# FakeOpenSmtpRelay
Collection of scripts, configuration settings and programs to simulate an open and working open SMTP relay. The solution is based on the following three building blocks:
- INetSim simulates an open SMTP relay server on Internet (tcp/25 & tcp/465), accepting any emails sent to it but relaying nothing further.
- Script FakeOpenSmtpRelay.py checks the INetSim inbox, identifies email probes from wannabe spammers and selectively relays them to their author. This script can be run in an automated way or with user-interaction. Several safeguards are implemented - such as the number of maximum emails relayed per day.
- Optionnally, a SMTP server can be installed to monitor remotely the SMTP honeypot and retrieve its logs


## How to get started
1. Install INetSim and adapt it to your needs (see folder TODO)
2. Download, install and configure script FakeOpenSmtpRelay.py (TODO link)
3. (Optional) Install your preferred mail daemon to be able to monitor the emails being trapped in your fake open SMTP relay (TODO: steps for dovecot)


## FAQ

### Why is STARTTLS disabled when receiving emails?
While INetSim claims to support STARTTLS when receiving emails, it does not work according to my tests. Therefore this setting is disabled until the root cause can be determined.
