# IMAP server

Installing an IMAP server is optional but recommended if you want to supervise FakeOpenSmtpRelay running as a daemon.

Thanks to an IMAP server and your preferred mail client, you can:
- monitor in realtime the honeypot's `inbox`
- read the logs of FakeOpenSmtpRelay by viewing the emails stored in folder `logs`. Each day will produce a new message named ```Logs from YYYY-MM-DD```. Your mail client will signal you whenever the message gets updated during the day by flagging it again as unread.
- view the relayed messages in folder `sentProbes`. These messages are almost identical to the ones sent, but contain 4 additional SMTP headers with details on how the relaying occured:
	- ```X-Relay-Sendmail-Date```: date and time when the message was relayed.
	- ```X-Relay-Sendmail-Sent```: result of the sentmessage command. Only errors are reported, ```X-Relay-Sendmail-Sent: {}``` means everything went well.
	- ```X-Relay-Sendmail-Quit```: result of the QUIT command.
	- ```X-Relay-Sendmail-Exception```: should be ```None``` unless an exception occured
 
Consider restricting access to the IMAP server to yourself (e.g. bind it on an internal interface only, unreachable from the Internet).


## Installation
Any IMAP daemon might do the job, as long as it supports mailbox format mbox.

There are the installation steps to install and configure Dovecot:
- Install Dovecot with imapd support: `apt-get install dovecot-imapd`
- Edit file /etc/dovecot/dovecot.conf to 
  - point to our mbox folder ([see INetSim's adaptation for dedicated mailboxes](../INetSim#allow-the-mboxes-to-be-accessed-from-a-mail-client))
  - define the username & password DB for IMAP authentication in a flat file
  - let Dovecot run as user and group inetsim (adapt mail_uid & mail_gid accordingly)
  ```
  # Sample for /etc/dovecot/dovecot.conf
	# Source: https://wiki2.dovecot.org/QuickConfiguration
	passdb {
	  driver = passwd-file
	  args = /etc/dovecot/inetsim-user-pass-db
	}
	userdb {
	  driver = passwd-file
	  args = /etc/dovecot/inetsim-user-pass-db
	}

	namespace {
	  inbox = yes
	  separator = /
	}

	protocols = imap
	ssl = no
	disable_plaintext_auth=no
  # UID of user inetsim
	first_valid_uid = 109 
  # UID of user inetsim
	mail_uid = 109
  # UID of group inetsim
	mail_gid = 114  
  ```
- Create file /etc/dovecot/inetsim-user-pass-db to have 2 userids pointing to our 2 mbox folders:
  ```
	inetsim_smtp:{plain}[SUPER_STRONG_AND_RANDOM_PASSWORD_1]::::::userdb_mail=mbox:/var/lib/inetsim/smtp/smtp
	inetsim_smtps:{plain[SUPER_STRONG_AND_RANDOM_PASSWORD_2]::::::userdb_mail=mbox:/var/lib/inetsim/smtp/smtps  
  ```
