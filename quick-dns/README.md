# quick-dns
A script written to quickly gather email information about a certain domain. Supports the following **checks**:
+ Nameserver lookup and verification.
+ SPF lookup.
+ DMARC lookup.
+ MX-record lookup.
+ RBL check against for the A-record of the domain (_the hosting web server_) and the MX-record(s).
+ A designated, extensive RBL check for a specified IP (using the `-r` flag for IPv4, and `-R` for IPv6).

## TODO
+ [X] Add reverse-DNS lookup to both the A-record and the MX-record hosts. Warn the user if there are hosts without a valid PTR record.
+ [-] ~~For RBL lookups, many of these providers use specific codes for the reason of the block. Maybe send this output to the user for more info. For example, see https://spfbl.net/en/dnsbl/.~~ _NOTE_ (2020-01-05): This is really not worth pursuing, due to the complexity and obscurity of vendor codes, it would be easier for an administrator to just contact the organization during the de-listing process anyway to find out the reason.
+ [X] Complete IPv6 support.
  - Note (2020-01-05): The IPv6 parsing seems to be fully supported and consolidated now for rDNS.

## Sample Bash Output
```
[notso@anonymous quick-dns]$ ./quick-dns.sh "test.net example.com" -n
################################################################################
Checking DNS information for test.net...
Primary Nameserver: shades18.rzone.de.
SPF Record: NONE
DMARC Record: NONE
MX Record(s):
	5 smtpin.rzone.de. 	(Resolved IP: 81.169.145.97)


Attempting A-record RBL check for 85.214.110.167...
Checking "Barracuda RBL"                                : [NOT LISTED]
	PTR Record:	h2439270.stratoserver.net.

Attempting MX-record RBL check...
  --========--   81.169.145.97 (PTR: smtpin.rzone.de.)    --========--  
Checking "Barracuda RBL"                                : [NOT LISTED]
Checking "SORBS Spam"                                   : [NOT LISTED]
Checking "UCEPROTECTL1"                                 : [NOT LISTED]
Checking "SpamCop"                                      : [NOT LISTED]
Checking "SpamRats NoPTR (no-PTR-record spammers)"      : [NOT LISTED]
Checking "SpamRats DYNA (suspicious PTR records)"       : [NOT LISTED]
Checking "MegaRBL"                                      : [NOT LISTED]
Checking "Spamhaus ZEN"                                 : [NOT LISTED]
Checking "SPFBL"                                        : [NOT LISTED]
Checking "LASHBACK"                                     : [NOT LISTED]
Checking "WPBL"                                         : [NOT LISTED]
Checking "Composite Blocking List (CBL)"                : [NOT LISTED]


################################################################################
Checking DNS information for example.com...
Primary Nameserver: a.iana-servers.net.
SPF Record: "v=spf1 -all"
DMARC Record: NONE
MX Record(s): NONE

Attempting A-record RBL check for 93.184.216.34...
Checking "Barracuda RBL"                                : [NOT LISTED]
	No PTR Record found for 93.184.216.34...


[notso@anonymous quick-dns]$ ./quick-dns.sh.experimental -r 1.1.1.1             
Checking RBLs for IP address: 1.1.1.1
	PTR Record:	one.one.one.one.
  --========--   1.1.1.1 (PTR: one.one.one.one.)    --========--  
Checking "Barracuda RBL"                                : [NOT LISTED]
Checking "SORBS Spam"                                   : [NOT LISTED]
Checking "UCEPROTECTL1"                                 : [NOT LISTED]
Checking "SpamCop"                                      : [NOT LISTED]
Checking "SpamRats NoPTR (no-PTR-record spammers)"      : [NOT LISTED]
Checking "SpamRats DYNA (suspicious PTR records)"       : [LISTED]
 ----> Given Reason (if any): "SPAMRATS IP Addresses See: http://www.spamrats.com/bl?1.1.1.1"
Checking "MegaRBL"                                      : [NOT LISTED]
Checking "Spamhaus ZEN"                                 : [NOT LISTED]
Checking "SPFBL"                                        : [NOT LISTED]
Checking "LASHBACK"                                     : [NOT LISTED]
Checking "WPBL"                                         : [NOT LISTED]
Checking "Composite Blocking List (CBL)"                : [NOT LISTED]

[notso@anonymous quick-dns]$
```
