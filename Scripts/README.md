# Scripts

Script FakeOpenSmtpRelay.py is the central component, as it tries to differenciate in the received emails between email probes sent by spammers and spam messages.


## FakeOpenSmtpRelay.py

Before running this script, review the settings in class GlobalConfig and adapt them to your needs.

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
