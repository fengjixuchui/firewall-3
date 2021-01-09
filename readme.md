# firewall.exe v0.93

![](screenshot.png)



## Requirements:

  [WinDivert 2.2](https://www.reqrypt.org/windivert.html) (included)
  



## Instruction

1. Edit settings

* settings.txt

2. Edit firewall rule tables

* loopback.txt (Loopback rules)
* out.txt (Outbound rules)
* in.txt (Inbound rules)

Rules are executed in sequential order. \
The sequence is terminated on a match, \
with one of the following actions: \
\
  ACCEPT      - accept the connection and show activity \
  ACCEPT_HIDE - accept the connection but hide activity \
  DROP        - drops the packet silently \
\
If no match is found, the default is DROP. \
\
\# precedes a comment \
\* represents a wildcard \
IP Subnets are allowed in CIDR format eg. 192.168.0.0/24

3. Start firewall.exe



## Known Limitations

* Ports are not validated and treated as strings. "001" not equals "1"
* Invalid action defaults to DROP
* Only supports TCP and UDP. IPv6, ICMP and other protocols are dropped



## Changes

### v0.93

* Added settings
* Added logging mode
* Added colours to UI
* Added mutex to socket and network handles
* Added auto-disable Windows Firewall
* Added re-enable Windows Firewall on close
* Added legend
* Fixed display issues on console columns not equal 80

### v0.92

* Fixed minor memory leak
* Added reload
* Added refresh interval
* Added pause refresh
* Added quit



## Upcoming

* More clean up
* Windows GUI
* Run as Windows Service
* Stress Testing
* Fix stability issue under extreme load
* Performance Tuning
  * enums instead of strings
  * switch (enum)
  * store ip addresses and subnet masks in binary