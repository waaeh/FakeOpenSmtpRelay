# INetSim

[INetSim](https://www.inetsim.org/) is a software suite for simulating common internet services, under GPL licence, ©2007-2018 Thomas Hungenberg & Matthias Eckert.

We use INetSim to simulate a SMTP and SMTPS server on Internet. INetSim will store any received email in a mbox format. [Script FakeOpenSmtpRelay.py](Scripts/) will then parse this mbox and relay relevant messages.


## Installation
I used the package version of inetsim (```sudo apt-get install inetsim``` - version 1.2.8-1 at the time of the writing), which creates a dedicated user inetsim.

The following changes were done to this installation:

### Configure the services in /etc/inetsim/inetsim.conf
- Disabled all services but smtp & smtps:
  ```diff
  -  start_service dns
  -  start_service http
  -  start_service https
  +  #start_service dns
  +  #start_service http
  +  #start_service https
     start_service smtp
     start_service smtps
  -  start_service pop3
  -  start_service pop3s
  +  #start_service pop3
  +  #start_service pop3s
  [...]
  ```
- Specified a ```service_bind_address```
- Enabled a customized SMTP banner for settings ```smtp_banner``` & ```smtps_banner```
- Specified a fully qualified domain name for settings ```smtp_fqdn_hostname``` & ```smtps_fqdn_hostname```
- Disabled STARTTLS as smtp_service_extension
  ```diff
      [...]
      smtp_service_extension		DSN
      smtp_service_extension		ETRN
  -   smtp_service_extension		STARTTLS
  +   #smtp_service_extension		STARTTLS
  ```
- Generated a self-signed certificate for SMTPS and referenced it in
  - ```smtp_ssl_keyfile```
  - ```smtp_ssl_certfile```
  - ```smtps_ssl_keyfile```
  - ```smtps_ssl_certfile```


### Start INetSim as daemon on system startup, in /etc/default/inetsim
  - Activated parameter ```ENABLED=1``` [as documented by the authors](https://www.inetsim.org/documentation.html)
    
If your services do not fork / bind on startup, consider adding some delay (e.g. ```sleep 60``` as in the example below) in /usr/share/perl5/INetSim.pm:
```perl
&INetSim::Log::MainLog("=== INetSim main process started (PID $PPID) ===");
&INetSim::Log::MainLog("Session ID:     " . &INetSim::Config::getConfigParameter("SessionID"));
&INetSim::Log::MainLog("Listening on:   " . &INetSim::Config::getConfigParameter("Default_BindAddress"));
&INetSim::Log::MainLog("Real Date/Time: " . strftime "%Y-%m-%d %H:%M:%S", localtime);
&INetSim::Log::MainLog("Fake Date/Time: " . (strftime "%Y-%m-%d %H:%M:%S", localtime(&INetSim::FakeTime::get_faketime())). " (Delta: " . &INetSim::Config::getConfigParameter("Faketime_Delta") . " seconds)");
# ADDITION - waiting 60 seconds to see if the forking issues at startup get solved...
sleep 60
&INetSim::Log::MainLog(" Forking services...");
```

### Allow the mboxes to be accessed from a mail client
In step 3 we will configure an email server on the machine to retrieve and monitor our fake open relay. To view the emails received over SMTP and SMTPS we need them to be stored in 2 different folders. To do so, alter file /usr/share/perl5/INetSim/Config.pm as follow:
```diff
      [...]
		  SMTP_Extended_SMTP => 1,
		  SMTP_Service_Extensions => {},
-		  SMTP_MBOXFileName => $datadir . "smtp/smtp.mbox",
+		  SMTP_MBOXFileName => $datadir . "smtp/smtp/inbox",
		  SMTP_AuthReversibleOnly => 0,
      [...]
		  SMTPS_HELO_required => 0,
		  SMTPS_Extended_SMTP => 1,
		  SMTPS_Service_Extensions => {},
-		  SMTPS_MBOXFileName => $datadir . "smtp/smtps.mbox",
+		  SMTPS_MBOXFileName => $datadir . "smtp/smtps/inbox",
		  SMTPS_AuthReversibleOnly => 0,
```

### WORK IN PROGRESS - Adaptations to support STARTTLS / explicit SMTPS
[As already noted in the FAQ](../../../#why-is-starttls-disabled-when-receiving-emails), STARTTLS / explicit SMTPS doesn't work according to my tests. The following attempts to correct this have been made, without success so far:

Alter file /usr/share/perl5/INetSim/SMTP.pm to remove the hardcoded reference to SSL version 2 & 3 only:
```diff
	sub upgrade_to_ssl {
		my $self = shift;
+		# EDITED to exclude the SSL version stuff
-		my %ssl_params = (  SSL_version             => "SSLv23",
-		                    SSL_cipher_list         => "ALL",
-		                    SSL_server              => 1,
-		                    SSL_use_cert            => 1,
-		                    SSL_key_file            => $self->{ssl_key},
-		                    SSL_cert_file           => $self->{ssl_crt} );
+		my %ssl_params = ( SSL_server              => 1,
+		                    SSL_use_cert            => 1,
+		                    SSL_key_file            => $self->{ssl_key},
+		                    SSL_cert_file           => $self->{ssl_crt} );
+		# ADDED for debugging purposes
+		$IO::Socket::SSL::DEBUG = 3;
```
