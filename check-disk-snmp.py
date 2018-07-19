#!/usr/bin/env python
# encoding: utf-8
'''
check-disk-snmp -- Check disk utilization of a remote system via SNMP

This utility checks disk utilization of a partition via SNMP, allowing checks
on remote systems without the use of SSH or similar shell access.

@author:     Doug Needham

@copyright:  2018 Doug Needham. All rights reserved.

@license:    MPL-2.0

@contact:    cinnion@gmail.com
@deffield    updated: Updated
'''

from __future__ import print_function

import sys
import os

from argparse import ArgumentParser as originalArgumentParser
from argparse import RawDescriptionHelpFormatter
from argparse import SUPPRESS

from pysnmp.hlapi import *
import cmd

__all__ = []
__version__ = 0.4
__date__ = '2018-07-04'
__updated__ = '2018-07-12'

DEBUG = 1
TESTRUN = 0
PROFILE = 0


class snmpUCDDskTable(object):
    '''
    Query a host via the UCD-SNMP-MIB module to get the disk path column to find the row index, then retrieve the row for checking.
    '''

    # Nagios return codes
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3

    # The text versions of the return code.
    NAGIOS_STATUSES = ('OK', 'Warning', 'Critical', 'Unknown')

    # Status
    status = OK

    # Information text
    infoText = ''

    # The columns in UCD-SNMP-MIB:dskTable entries which are looked at.
    MIB_COLUMNS = ('dskMinimum', 'dskMinPercent', 'dskTotal', 'dskAvail', 'dskUsed', 'dskPercent', 'dskPercentNode', 'dskTotalLow',
                   'dskTotalHigh', 'dskAvailLow', 'dskAvailHigh', 'dskUsedLow', 'dskUsedHigh', 'dskErrorFlag', 'dskErrorMsg')

    def __init__(self, **kwargs):
        '''
        Initialize this instance for getting the remote disk information. It will reflect the state of the check as it progresses through the initialization steps.
        '''
        self.status = self.UNKNOWN
        self.infoText = 'Initialization not completed'
        self.verbosity = kwargs['verbose']

        self.setupThresholds(**kwargs)
        self.setupEngine(**kwargs)
        self.setupAuthData(**kwargs)
        self.setupTransportTarget(**kwargs)
        self.setupContextData(**kwargs)

        self.infoText = 'Data not loaded'

    def __str__(self):
        '''
        Return a string giving the status in textual format, suitable for printing immediately before exiting back to Nagios.
        '''
        return ' '.join([self.NAGIOS_STATUSES[self.status], self.infoText.strip()])

    def __int__(self):
        '''
        Return an integer status value to be returned to Nagios.
        '''
        return self.status

    def setupThresholds(self, **kwargs):
        '''
        Setup the thresholds we will use.
        '''
        crits=kwargs['critical'].split(',')
        warns=kwargs['warning'].split(',')


        dskPercent=[80,90]
        dskPercentNode=[50,75]
        dskAvail=[]

        for warn in warns:
            if '%i' in warn:
                dskPercentNode[0] = warn[:-2]
            elif '%' in warn:
                dskPercent[0] = warn[:-1]
            else:
                dskAvail[0] = warn

        for crit in crits:
            if '%i' in crit:
                dskPercentNode[1] = crit[:-2]
            elif '%' in crit:
                dskPercent[1] = crit[:-1]
            else:
                dskAvail[1] = crit

        self.thresholds = {
            'dskPercent': tuple(dskPercent),
            'dskPercentNode': tuple(dskPercentNode)
        }

    def getPartitionData(self):
        '''
        Get the data associated with the partition, and having successfully loaded the information, set the status to OK.
        '''
        mibOids = []
        for mibName in self.MIB_COLUMNS:
            mibId = ObjectType(ObjectIdentity('UCD-SNMP-MIB', mibName, self.partIndex))
            mibOids.append(mibId)

        cmd = getCmd(self.engine, self.authData, self.transportTarget, self.contextData, *mibOids)

        (errorIndication, errorStatus, errorIndex, varBinds) = next(cmd)
        if errorIndication:
            print(errorIndication)
        elif errorStatus:
            print("%s at %s".format(errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            values = dict()
            for varBind in varBinds:
                name = varBind[0].getLabel()[-1]
                value = varBind[1]
                values[name] = value

        self.dskValues = values

        self.status = self.OK
        self.infoText = ''

    def checkValues(self):
        '''
        Do the actual checks on the status of the disk.
        '''
        if self.dskValues['dskErrorFlag']:
            status = self.CRITICAL
            self.infoText = self.dskValues['dskErrorMsg']

        for column in self.thresholds:
            self.evalThresholds(column, self.dskValues[column], self.thresholds[column])

    def evalThresholds(self, name, value, threshold):
        '''
        Evaluate the threshold against the value.
        '''
        status = self.OK
        msg = None

        if self.verbosity:
            print("Evaluating threshold for {}, value={}, threshold={}".format(name, value, threshold), file=sys.stderr)

        if value is None:
            status = self.UNKNOWN
            msg = "No value found for {}".format(name)
        if value > threshold[1]:
            status = self.CRITICAL
            msg = "{} > critical threshold of {} for {}".format(value, threshold[1], name)
        elif value > threshold[0]:
            status = self.WARNING
            msg = "{} > warning threshold of {} for {}".format(value, threshold[0], name)
        else:
            msg = "{}={}".format(name,value)

        if self.status in (self.OK, self.WARNING) and status > self.status:
            self.status = status
        if msg is not None:
            self.infoText += ' ' + msg

    def lookupDiskIndex(self, mountPoint):
        '''
        Lookup the disk index for the specified partition mount point.
        '''

        try:
            dskPathMib = ObjectIdentity('UCD-SNMP-MIB', 'dskPath')
            cmd = nextCmd(self.engine, self.authData, self.transportTarget, self.contextData, ObjectType(dskPathMib))

            for (errorIndication, errorStatus, errorIndex, varBinds) in cmd:
                if errorIndication:
                    print(errorIndication)
                    break
                elif errorStatus:
                    print("%s at %s".format(errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                    break
                elif 'UCD-SNMP-MIB::dskPath' not in varBinds[0][0].prettyPrint():
                    break
                elif mountPoint == varBinds[0][1].prettyPrint():
                    index = varBinds[0][0].prettyPrint().split('.')[-1]
                    break

            if index is None:
                raise CLIError('Partition not found via SNMP')

            self.partIndex = index

        except Exception as e:
            raise(e)

    def setupAuthData(self, **kwargs):
        '''
        Setup the authentication data which will be used for connecting to the host via SNMP
        '''
        if (kwargs['protocol'] in ['1', '2c']):
            self.authData = CommunityData(kwargs['community'], mpModel=(1 if kwargs['protocol'] == '2c' else 0))
        else:
            self.setupAuthUsm(**kwargs)

    def setupAuthUsm(self, **kwargs):
        '''
        Setup the SNMPv3 authentication data which will be used for connecting to the host via SNMP
        '''
        authProtocol = usmNoAuthProtocol
        authKey = kwargs['authpasswd']
        if authKey:
            authProtocol = usmHMACMD5AuthProtocol
            if kwargs['authproto'] == 'SHA':
                authProtocol = usmHMACSHAAuthProtocol

        privProtocol = usmNoPrivProtocol
        privKey = kwargs['privpasswd']
        if privKey:
            privProtocol = usmDESPrivProtocol
            if kwargs['privproto'] == 'AES':
                privProtocol = usmAesCfb128Protocol

        usmArgs = {'privKey': privKey, 'authKey': authKey, 'authProtocol': authProtocol, 'privProtocol': privProtocol}
        self.authData = UsmUserData(kwargs['secname'], **usmArgs)

    def setupContextData(self, **kwargs):
        '''
        Setup the context data which will be used for connecting to the host via SNMP
        '''
        self.contextData = ContextData()

    def setupEngine(self, **kwargs):
        '''
        Setup the SNMP engine instance which will be used for connecting to the host via SNMP
        '''
        self.engine = SnmpEngine()

    def setupTransportTarget(self, **kwargs):
        '''
        Setup the transport data which will be used for connecting to the host via SNMP
        '''
        # TODO: Validate address as IPv4 or IPv6
        self.transportTarget = UdpTransportTarget((kwargs['hostname'], kwargs['port']), timeout=kwargs['timeout'], retries=kwargs['retries'])


class ArgumentError(Exception):
    '''
    Generic exception to raise and log different fatal errors.
    '''

    def __init__(self, msg):
        super(ArgumentError).__init__(type(self))
        self.msg = "UNKNOWN %s" % msg

    def __str__(self):
        return self.msg

    def __unicode__(self):
        return self.msg


class ArgumentParser(originalArgumentParser):
    '''
    Overrides the error method of the vanilla ArgumentParser class to raise an ArgumentError exception instead of exiting.
    '''

    def exit(self, status=0, message=None):
        '''
        Override to raise an ArgumentError instead of printing the message and exiting.
        '''
        raise ArgumentError(message)


def main(argv=None):  # IGNORE:C0111
    '''Command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s

  Created by Doug Needham on %s.
  Copyright (c) 2018 Doug Needham

  This program and the accompanying materials are made
  available under the terms of the Mozilla Public License 2.0
  which is available at https://www.mozilla.org/en-US/MPL/2.0/

  SPDX-License-Identifier: MPL-2.0

USAGE
''' % (program_shortdesc, str(__date__))

    try:
        # Setup argument parser
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter, add_help=False)
        parser.add_argument('-h', '--help', action='help', default=SUPPRESS, help='show this help message and exit')
        parser.add_argument('-V', '--version', action='version', version=program_version_message)
        parser.add_argument('-v', '--verbose', dest='verbose', action='count', help='set verbosity level [default: %(default)s]')

        parser.add_argument('-H', '--hostname', help='Host', required=True)
        parser.add_argument('-w', '--warning', help='Warn')
        parser.add_argument('-c', '--critical', help='Critical')

        parser.add_argument('-t', '--timeout', type=float, default=1,
                            help='Timeout in seconds, with a resolution of around 0.5s [default: %(default)s sec]')
        parser.add_argument('-r', '--retries', type=int, default=5, help='The number of retries to be used in the requests [default: %(default)s]')

        parser.add_argument('-p', '--port', type=int, default=161, help='Port number [default: %(default)s]')
        parser.add_argument('-P', '--protocol', choices=['1', '2c', '3'], default='2c', help='Protocol version [%(choices)s, default: %(default)s]')

        snmpv12_group = parser.add_argument_group(description='SNMPv1 and SNMPv2c Options')
        snmpv12_group.add_argument('-C', '--community', default='public',
                                   help='Optional community string for SNMP communication [default: %(default)s]')

        snmpv3_group = parser.add_argument_group(description='SNMPv3 Options')
        snmpv3_group.add_argument('-l', '--seclevel', choices=['noAuthNoPriv', 'authNoPriv',
                                                               'authPriv'], help='SNMPv3 securityLevel to be used [default: %(default)s]')
        snmpv3_group.add_argument('-a', '--authproto', choices=['MD5', 'SHA'], default='MD5',
                                  help='SNMPv3 authentication protocol [default: %(default)s]')
        snmpv3_group.add_argument('-A', '--authpasswd', help='SNMPv3 authentication password')
#        snmpv3_group.add_argument('-E', '--context', help='SNMPv3 context')
        snmpv3_group.add_argument('-u', '--secname', help='SNMPv3 username')
        snmpv3_group.add_argument('-x', '--privproto', choices=['DES', 'AES'], default='DES', help='SNMPv3 priv proto [default: %(default)s]')
        snmpv3_group.add_argument('-X', '--privpasswd', help='SNMPv3 privacy password used for encrypted messages [default: %(default)s]')

        parser.add_argument(dest='mount_point',
                            help='paths for the mount point [default: %(default)s]', metavar='mount-point')

        # Process arguments
        args = parser.parse_args()

        d = snmpUCDDskTable(**vars(args))
        d.lookupDiskIndex(args.mount_point)
        d.getPartitionData()

        if args.verbose >= 3:
            print(args, file=sys.stderr)
            print('Table index is {}'.format(d.partIndex), file=sys.stderr)
            print(d.dskValues, file=sys.stderr)

        d.checkValues()

        print(d)
        return int(d)

    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return 0

    except ArgumentError as e:
        ### Return 3 after printing the Unknown service status ###
        print(str(e))
        return 3

    except Exception as e:
        if DEBUG or TESTRUN:
            raise(e)
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")
        return 3


if __name__ == "__main__":
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = '_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())
