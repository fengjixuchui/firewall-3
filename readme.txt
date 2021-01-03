firewall.exe v0.91
==================



Requirements:
-------------

  WinDivert 2.2 (included)
  https://www.reqrypt.org/windivert.html



Instruction
-----------

1. Edit firewall tables

  -> loopback.txt (Loopback rules)
  -> out.txt (Outbound rules)
  -> in.txt (Inbound rules)

  Rules are executed in sequential order.
  The sequence is terminated on a match,
  with one of the following actions:
.
      ACCEPT      - accept the connection and show activity
      ACCEPT_HIDE - accept the connection but hide activity
      DROP        - drops the packet silently

  If no match is found, the default is DROP.

  # precedes a comment
  * represents a wildcard
  IP Subnets are allowed in CIDR format eg. 192.168.0.0/24

2. Disable Windows Firewall

3. Start firewall.exe



Known Limitations
-----------------

* Ports are not validated and treated as strings.
    "001" not equals "1"
* Invalid action defaults to DROP



Upcoming
--------

* Reload Rules without restarting
* Windows GUI
* Run as Windows Service
* Disable network while firewall is off
