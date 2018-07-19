# check-disk-snmp 

A Nagios plugin to checking disk usage on remote systems via SNMP, using the
values provided via UCD-SNMP-MIB:dskTable (.1.3.6.1.4.1.2021). This MIB table
is used in favor over the others since it gives a fuller set of values, such
as inodes used and percentages, as well as the thresholds configured for
trapping.

## Requirements

This script is currently written for Python 2.7+, but uses the Python future
library to provide the print() function.

## Installation

At this moment, the installation is to manually copy the `check-disk-snmp.py`
script to the Nagios plugin directory (e.g. `/usr/lib64/nagios/plugins`)

## Example

### CLI Usage

```
$ check-disk-snmp.py -H panparis -C public -w 80%,50%i -c 90% /tmp
OK dskPercent=14 dskPercentNode=0
```

### Nagios command definition

```
define command {
    command_name        check_remote_disk
    command_line        $USER1$/check-disk-snmp.py -H $HOSTADDRESS$ -C public -w $ARG1$ -c $ARG2$ $ARG3$
}
```

### Nagios service definition

```
define service {
    use				remote-service
    host_name			nas
    service_description		mirrors:centos Partition
    check_command 		check_remote_disk!80%!90%!/mirrors/centos
}
```

## Known issues

- Some partitions will cause the command to fail with the error of 
  AttributeError("'DisplayString' object has no attribute 'strip'",) 

## License

This software is open-sourced software licensed under the
[Mozilla Public License, v2.0](https://www.mozilla.org/en-US/MPL/2.0/)

## Author Information

This plugin was created 2018 July 17 by [Douglas Needham](https://www.ka8zrt.com/).



