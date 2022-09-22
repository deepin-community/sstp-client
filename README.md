# Sstp-Client
Sstp-Client is an SSTP client for Linux. It can be used to establish a SSTP connection to a Windows 2008 Server.
This software is similar commandline and configuration as the pptp-client software.

## Background
SSTP is Microsofts Remote Access Solution (RAS) for PPP over SSL. It can be used
instead of PPTP or L2TP, and is only available with Windows Vista/7 connecting to
a Windows 2008 Server. For further information on SSTP check out wikipedia's
article on Secure Socket Tunneling Protocol.

http://en.wikipedia.org/wiki/Secure_Socket_Tunneling_Protocol

## Features:
* Establish a SSTP connection to a remote Windows 2k8 server.
* Async PPP support (most distributions provide this).
* Similar command line handling as pptp-client for easy integration.
* IPv6 support
* Basic HTTP Proxy support
* Certficate handling and verification
* SSTP plugin integration with NetworkManager v0.9 (available as separate package)

## Running Sstp-Client
There are two different ways one can establish a connection to a remote SSTP server.
1. Run sstpc on the command line
2. Have pppd load sstpc via the plugin directive

In the first case, sstpc will start pppd once a connection is established with the SSTP server and spawn an instance of
pppd to perform authentication, and configuring the ppp interface. This is the less ideal way of connecting to your
remote, and should be considered experimental or testing purposes. Establishing your connection this way is limited to
use of PAP, MSCHAPv2, and EAP-MSCHAPv2 for authentication.

Typically, one will need some integration with your Linux distribution, e.g. the pon/poff scripts provided by pppd. 
An example script is provided in support/peer-sstp-example.txt. The general outline for setting this up is as follows:

- Specify your MSCHAP password in /etc/ppp/chap-secrets
  Example Entry:
     SSTP-TEST\\JonDoe  sstp-test   'testme1234!'    *
- Create a script in /etc/ppp/peers/sstp-test, following an example provided in the support directory. Adjust
necessary settings including username, password, etc.
- Start the script as: sudo pon sstp-test
- Stop the script using: sudo poff sstp-test

Integration with network-manager project is available via a separate project and supplies a purpose built plugin to
launch sstpc in a similar way.
  https://gitlab.gnome.org/GNOME/network-manager-sstp

Connection to a Windows Server or an Azure VNetGway is possible using EAP-TLS, but does require additional patches to
pppd 2.4.9. Code is already in place in upstream versions of pppd for this to work, including PEAP-TLS.

For additional information and examples, please visit the wiki page for this project.
  https://gitlab.com/eivnaes/sstp-client/-/wikis

## Compiling:
To compile this on your favorite distribution make sure you have the development tools and headers available. This
project depends on the PPP package, libevent and OpenSSL.

For example:
 - sudo apt-get install ppp-dev
 - sudo apt-get install libevent-dev
 - sudo apt-get install libssl-dev

## Dependent Projects
* OpenSSL  (http://www.openssl.org)
* PPPD     (http://ppp.samba.org)
* Libevent (monkey.org/~provos/libevent)

## Important Links:
 * How to setup SSTP on windows 2008 server, technotes from Microsoft, http://technet.microsoft.com/en-us/library/cc731352%28WS.10%29.aspx
 * The SSTP specification: http://msdn.microsoft.com/en-us/library/cc247338%28v=prot.10%29.aspx
 * A reference to the pptp-client software, this has much in common with the SSTP project, e.g. command line. http://pptpclient.sourceforge.net/
 * OpenSSL Examples: http://www.rtfm.com/openssl-examples/
 * MicroTik have a working server and client version in the router software (as of March 2010).
 * SSToPer is another SSTP client, but doesn't support Async HDLC frames


