# IMAP server

Installing an IMAP server is optional but recommended if you want to supervise FakeOpenSmtpRelay running as a daemon.

Thanks to an IMAP server and your preferred mail client, you can:
- monitor in realtime the honeypot's `inbox`
- read some of the logs of FakeOpenSmtpRelay by viewing the emails stored in folder `logs`. Each day will produce a new message named ```Logs from YYYY-MM-DD```. Your mail client will signal you whenever the message gets updated during the day by flagging it again as unread.
- view the relayed messages in folder `sentProbes`. These messages are almost identical to the ones sent, but contain 4 additional SMTP headers with details on how the relaying occurred:
	- ```X-Relay-Sendmail-Date```: date and time when the message was relayed.
	- ```X-Relay-Sendmail-Sent```: result of the sentmessage command. Only errors are reported, ```X-Relay-Sendmail-Sent: {}``` means everything went well.
	- ```X-Relay-Sendmail-Quit```: result of the QUIT command.
	- ```X-Relay-Sendmail-Exception```: should be ```None``` unless an exception occurred
 
Consider restricting access to the IMAP server to yourself (e.g. bind it on an internal interface only, unreachable from the Internet).


## Installation
Any IMAP daemon might do the job, as long as it supports mailbox format maildir.

There are the installation steps to install and configure Dovecot:
- Install Dovecot with imapd support: `apt-get install dovecot-imapd`
- Edit file /etc/dovecot/dovecot.conf to 
  - point to our maildir folder (provide full path of folder ./maildir/ by default)
  - define the username & password DB for IMAP authentication in a flat file
  - let Dovecot run under the same identity than you run script FakeOpenSmtpRelay.py (adapt mail_uid & mail_gid accordingly)
  ```
  # Sample for /etc/dovecot/dovecot.conf
	# Source: https://wiki2.dovecot.org/QuickConfiguration
	passdb {
	  driver = passwd-file
	  args = /etc/dovecot/fosr-user-pass-db
	}
	userdb {
	  driver = passwd-file
	  args = /etc/dovecot/fosr-user-pass-db
	}

	namespace {
	  inbox = yes
	  separator = /
	}

	protocols = imap
	ssl = no
	disable_plaintext_auth=no
  # UID of user fosr
	first_valid_uid = 109 
  # UID of user fosr
	mail_uid = 109
  # UID of group fosr
	mail_gid = 114  
  ```
- Create file /etc/dovecot/fosr-user-pass-db to have a userid pointing to our maildir folder:
  ```
	fosr:{plain}[SUPER_STRONG_AND_RANDOM_PASSWORD]::::::userdb_mail=maildir:/YOUR_PATH_TO/maildir

  ```
