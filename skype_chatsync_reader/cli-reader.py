#!/usr/bin/env python
"""
Command line tool to decode and display messages in Skype chatsync/*/*.dat files

Utilizes chatsync scanner/parser originally by Konstantin Tretyakov

Copyright 2017, Peter Parkkali
MIT License.
"""

# Common stuff
from __future__ import print_function
import sys
import os
import codecs
from datetime import datetime
from HTMLParser import HTMLParser

# Local stuff
from scanner import SkypeChatSyncScanner
from scanner import SkypeChatSyncParser
from scanner import ThreadedSkypeChatHistory
from scanner import FlatSkypeChatHistory
from scanner import ScanException
from scanner import walk_dat_files

from dump_var import dump_var

class CliTool:
    """USAGE: cli-reader.py <COMMAND> <COMMAND OPTIONS>

    COMMANDS AND THEIR OPTIONS:
        thread <path> <myusername> [FILTER OPTIONS]
            Read .dat file(s), combine messages from all files, sort into threads and print out

        flat <path> <myusername> [FILTER OPTIONS]
            Read .dat file(s), combine messages from all files, print out without threading

        flat-per-file <path> [FILTER OPTIONS]
            Read .dat file(s), print out each file's name and contents sequentially

        dump <file.dat>
            Read a single .dat file and dump the results

        test <path> --dump-invalids
            Test .dat file(s) for scan and parse errors

    COMMON OPTIONS:
        <path>           Path to a a single .dat file or a directory of files to recurse
        <myusername>     Skype username of this account
        --hide-warnings  Hides warnings
        --hide-errors    Hides errors

    FILTER OPTIONS:
        --users=username1,username2,...   Include only threads where at least one of these users is present
        --time-from=unix_timestamp        Include only messages after this timestamp
        --time-to=unix_timestamp          Include only messages before this timestamp

    EXAMPLES:
        ./cli-reader.py thread /tmp/chatsync/ john_smith jane_smith,john_doe,jane_doe 1451606400
        ./cli-reader.py dump "~/Library/Application Support/Skype/john_smith/chatsync/af/afXXYYZZ.dat"
        ./cli-reader.py test "~/Library/Application Support/Skype/john_smith/chatsync/"
    """

    #######################################################################################
    def __init__(self):
        self.mode             = None
        self.srcpath          = None
        self.myusername       = None
        self.username_filter  = None
        self.timestamp_from   = None
        self.timestamp_to     = None
        self.dump_invalids    = False
        self.hide_warnings    = False
        self.hide_errors      = False

    #######################################################################################
    def main(self, argv):
        self.parse_args(argv)
        self.choose_mode()

    #######################################################################################
    def parse_args(self, argv):
        try:
            self.mode       = argv[1]
            self.srcpath    = argv[2]
            if self.mode == "thread" or self.mode == "flat":
                self.myusername = argv[3]
        except IndexError:
            print("Insufficient arguments", file=sys.stderr)
            print(self.__doc__, file=sys.stderr)
            exit(1)

        self.hide_warnings = self.parse_arg(argv, '--hide-warnings')
        self.hide_errors   = self.parse_arg(argv, '--hide-errors')

        if self.mode == "thread" or self.mode == "flat" or self.mode == "flat-per-file":
            self.username_filter = self.parse_arg_value(argv, '--users')
            self.timestamp_from  = self.parse_arg_value(argv, '--time-from')
            self.timestamp_to    = self.parse_arg_value(argv, '--time-to')

            if self.username_filter != None:
                self.username_filter = self.username_filter.split(",")

            if self.timestamp_from != None:
                self.timestamp_from = int(self.timestamp_from)

            if self.timestamp_to != None:
                self.timestamp_to = int(self.timestamp_to)

        elif self.mode == "test":
            self.dump_invalids = self.parse_arg(argv, '--dump-invalids')

        else:
            if len(argv) > 3:
                print("Too many arguments", file=sys.stderr)
                print(self.__doc__, file=sys.stderr)
                exit(1)

    #######################################################################################
    @staticmethod
    def parse_arg_value(args, name):
        for arg in args:
            if arg[:len(name)] + "=" == name + "=":
                return arg[len(name)+1:]
            if arg == name:
                return True
        return None

    #######################################################################################
    @staticmethod
    def parse_arg(args, name):
        for arg in args:
            if arg == name:
                return True
        return None

    #######################################################################################
    def choose_mode(self):
        if self.mode == "thread":
            self.mode_thread()
            return

        if self.mode == "flat":
            self.mode_flat()
            return

        if self.mode == "flat-per-file":
            self.mode_flatperfile()
            return

        if self.mode == "dump":
            self.mode_dump()
            return

        if self.mode == "test":
            self.mode_test()

        print("Unknown mode {}".format(self.mode), file=sys.stderr)
        exit(1)

    #######################################################################################
    def mode_thread(self):
        """Reads the (directory of) .dat file(s) at /srcpath/ and prints the messages."""

        history = ThreadedSkypeChatHistory(self.myusername, self.username_filter, self.timestamp_from, self.timestamp_to)
        self.import_path(history)

        history.clean_threads()
        history.sort_threads()

        print("==== THREADS FOUND: ====")
        for peer_set in history.threads:
            print(" - " + ", ".join(peer_set))

        print("\n")

        for peer_set in history.threads:
            print("==== THREAD WITH {} ====".format(", ".join(peer_set)))
            for message in history.threads[peer_set]:
                print("    " + self.printable_message(message), end="")
            print("\n")


    #######################################################################################
    def mode_flat(self):
        """Reads the (directory of) .dat file(s) at /srcpath/ and prints the messages."""

        history = FlatSkypeChatHistory(self.myusername, self.username_filter, self.timestamp_from, self.timestamp_to)
        self.import_path(history)

        history.sort_messages()

        print("==== MESSAGES ====")
        for message in history.messages:
            print(self.printable_message(message), end="")

    #######################################################################################
    def mode_test(self):
        for filepath in walk_dat_files(self.srcpath):
            self.test_datfile(filepath)

    #######################################################################################
    def mode_flatperfile(self):
        for filepath in walk_dat_files(self.srcpath):
            print(self.printable_file(filepath), end="")

    #######################################################################################
    def mode_dump(self, srcpath):
        """Scans and dumps the .dat file at /srcpath/"""

        with open(srcpath, 'rb') as filehandle:
            s = SkypeChatSyncScanner(filehandle)
            try:
                s.scan()
                if s.warnings == 0:
                    print("Scan completed without problems")
                else:
                    print("Scan completed with {} warnings".format(s.warnings))

            except ScanException as e:
              if not self.hide_errors:
                print("Scan error, skipping: {}: {}".format(srcpath, e.message))

            print("\n== DUMPING SCANNED BLOCKS ===")
            dump_var(s.blocks)

    #######################################################################################
    def import_path(self, history):
        """Imports the file/dir at self.srcpath into history object /history/."""

        for filepath in walk_dat_files(self.srcpath):
            # Scan it
            with open(filepath, 'rb') as filehandle:
                try:
                    snr = SkypeChatSyncScanner(filehandle)
                    snr.scan(validate = False)
                except ScanException as e:
                    print(self.printable_warning_list("SCAN", filepath, snr.warning_list), end='')
                    print(self.printable_error("{}: Scan error: {}".format(filepath, e.message)), end='')
                    continue
                print(self.printable_warning_list("SCAN", filepath, snr.warning_list), end='')

            # Parse it
            try:
                psr = SkypeChatSyncParser(snr)
                psr.parse()
            except ScanException as e:
                print(self.printable_warning_list("PARSE", filepath, psr.warning_list), end='')
                print(self.printable_error("{}: Parse error: {}".format(filepath, e.message)), end='')
                continue
            print(self.printable_warning_list("PARSE", filepath, psr.warning_list), end='')

            # Append the history
            history.append_history(psr)

    #######################################################################################
    def test_datfile(self, filepath):
        with open(filepath, 'rb') as filehandle:
            # Scan it
            try:
                snr = SkypeChatSyncScanner(filehandle)
                snr.scan(validate = False)
            except ScanException as e:
                print(self.printable_warning_list("SCAN", filepath, snr.warning_list), end='')
                print(self.printable_error("{}: scan error: {}".format(filepath, e.message)), end='')
                if self.dump_invalids:
                    print("==== DUMPING BLOCKS FROM INVALID FILE =====")
                    try:
                        dump_var(snr.blocks)
                    except AttributeError:
                        print("No scan results to dump")
                return

            print(self.printable_warning_list("SCAN", filepath, snr.warning_list))

            # Parse it
            try:
                psr = SkypeChatSyncParser(snr)
                psr.parse()
            except ScanException as e:
                print(self.printable_warning_list("PARSE", filepath, psr.warning_list), end='')
                print(self.printable_error("{}: parse error: {}".format(filepath, e.message)), end='')
                if self.dump_invalids:
                    dump_var(snr.blocks)
                return

            print(self.printable_warning_list("PARSE", filepath, psr.warning_list), end='')

            # K
            print("{}: OK".format(filepath))

    #######################################################################################
    @staticmethod
    def printable_message(message):
        """Returns the message object /message/ in a printable form."""

        edited = ""
        if message.is_edit:
            edited = " (edited)"

        # Decode HTML entities, replace Unicode characters with ?s and indent multi-line messages
        # FIXME: print out unicode properly
        message_text = HTMLParser().unescape(
            message.text.encode('ascii', 'replace').replace("\n", "\n\t")
        )

        return "<{}> {:15s}{} {}".format(
            datetime.fromtimestamp(message.timestamp),
            "<" + message.author + ">",
            edited,
            message_text
        ) + "\n"

    #######################################################################################
    def printable_warning_list(self, kind, filepath, warning_list):
        if self.hide_warnings:
            return ""

        if len(warning_list) == 0:
            return ""

        buf = []
        buf.append("==== {} WARNINGS FROM {} ====".format(kind, filepath))
        for warning in warning_list:
            buf.append(warning)
        return "\n".join(buf) + "\n"

    #######################################################################################
    def printable_error(self, error_str):
        if self.hide_errors:
            return ""
        return error_str + "\n"

    #######################################################################################
    def printable_file(self, filepath):
        bufstr = ""
        head = ("==== FILE {} ====".format(filepath)) + "\n"

        with open(filepath, 'rb') as filehandle:
            # Scan it
            try:
                s = SkypeChatSyncScanner(filehandle)
                s.scan()
            except ScanException as e:
                bufstr += (self.printable_error("{}: scan error: {}".format(filepath, e.message)))
                bufstr += (self.printable_warning_list("SCAN", filepath, s.warning_list))
                if bufstr == "":
                    return ""
                return head + bufstr + "\n"
            bufstr += (self.printable_warning_list("SCAN", filepath, s.warning_list))

        # Parse it
        try:
            p = SkypeChatSyncParser(s)
            p.parse()
        except ScanException as e:
            bufstr += (self.printable_error("{}: parse error: {}".format(filepath, e.message)))
            bufstr += (self.printable_warning_list("PARSE", filepath, p.warning_list))
            if bufstr == "":
                return ""
            return head + bufstr + "\n"
        bufstr += (self.printable_warning_list("PARSE", filepath, p.warning_list))

        # Check usernames
        if not self.check_username_filter(p.peers):
            return ""

        # Add metadata
        bufstr += ("Session: {}".format(repr(p.session))) + "\n"
        bufstr += ("Empty: {}".format(p.is_empty)) + "\n"
        bufstr += ("Time: {}".format(datetime.fromtimestamp(p.timestamp))) + "\n"
        bufstr += ("Peers: {}".format(p.peers)) + "\n"
        bufstr += ("User name map: {}".format(p.user_name_map)) + "\n"

        # Check timestamps & add messages
        valid = False
        for message in p.conversation:
            if self.check_timestamp_filters(message):
                valid = True
                bufstr += (self.printable_message(message))

        if valid:
            return head + bufstr + "\n"

        # Nothing to return
        return ""

    #######################################################################################
    def check_username_filter(self, peer_set):
        """Checks peer_set against self.userlist_filter"""

        if self.username_filter == None:
            return True

        for username in self.username_filter:
            if username in peer_set:
                return True

        return False

    #######################################################################################
    def check_timestamp_filters(self, message):
        """Checks message against timestamp filters"""

        if self.timestamp_from != None:
            if message.timestamp < self.timestamp_from:
                return False

        if self.timestamp_to != None:
            if message.timestamp > self.timestamp_to:
                return False

        return True

#######################################################################################
CliTool().main(sys.argv)
