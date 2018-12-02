# Scripts

[Script FakeOpenSmtpRelay.py](FakeOpenSmtpRelay.py) is the central component, as it tries to differenciate in the received emails between email probes sent by spammers and spam messages.

Aside this main script, this folder also features the follow file(s):
- [MboxParsingExamples.py](MboxParsingExamples.py) containing examples on how to explore, analyze and triage emails (typically once your honeypot received 1'000 / 10'000 / 100'000 / 1'000'000 (mal)spams).

## FakeOpenSmtpRelay.py

### Installation
[FakeOpenSmtpRelay.py](FakeOpenSmtpRelay.py) was written for Python3 and requires module dns.resolver (previously known as dnspython - ```sudo apt-get install python3-pip && sudo pip3 install dnspython3``` to install the module).

Download the [script](FakeOpenSmtpRelay.py) and assign it execution permissions (```chmod +x FakeOpenSmtpRelay.py```). Review the settings in class GlobalConfig and adapt them to your needs before executing the script for the first time.


### Usage
```
usage: FakeOpenSmtpRelay.py [-h] [-i] [-t] [-d]

Manages emails received on a SMTP open relay.

optional arguments:
  -h, --help         show this help message and exit
  -i, --interactive
  -t, --testMode
  -d, --debug
```  

Run without any argument, FakeOpenSmtpRelay.py will parse every 5 minutes the mbox located at ```~/smtp/smtp/inbox``` to detect email probes containing your server's IP address in the email subject. These emails will be relayed to destination (max 10 a day). The mailbox parsing is only done if the inbox contains less than 20 messages. A daily log is stored in mailbox ```~/smtp/smtp/logs``` and relayed messages are stored in ```~/smtp/smtp/sentProbes```.

Use the interactive mode (```-i, --interactive```) to manually list, select and relay the messages you want to forward.

Use the test mode (```-t, --testMode```) for all your tests, so that the relaying is done toward one of your server / email account and not directly to the spammer (see variables ```TEST_PROBE_RELAY_*``` in class GlobalConfig).
