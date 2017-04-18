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
import scanner
from dump_var import dump_var

def main(argv):
    """USAGE:
Read a file / directory, combine messages from all files, sort into threads and print out:
    cli-reader.py thread <dir|file.dat> <myusername> [username1,username2,...] [timestamp_from] [timestamp_to]

Read a file / directory, combine messages from all files, print out without threading:
    cli-reader.py flat <dir|file.dat> <myusername> [username1,username2,...] [timestamp_from] [timestamp_to]

Read a file / directory, print out each file's name and contents sequentially
    cli-reader.py flat-per-file <dir|file.dat>

Read a .dat file and dump the results:
    cli-reader.py dump <file.dat>

Test dat file(s) for scan and parse errors:
    cli-reader.py  test <dir|file.dat>

OPTIONS:
    <srcpath>        Path to a a single .dat file or a directory to recurse
    <myusername>     Your Skype username
    [username1,..]   Filter: Comma-separated list of usernames to include, default: all
    [timestamp_from] Filter: Min. Unix timestamp, default: none
    [timestamp_to]   Filter: Max. Unix timestamp, default: none

EXAMPLES:
    ./cli-reader.py thread /tmp/chatsync/ john_smith jane_smith,john_doe,jane_doe 1451606400
    ./cli-reader.py dump ~/Library/Application Support/Skype/john_smith/chatsync/af/afXXYYZZ.dat
    ./cli-reader.py test ~/Library/Application Support/Skype/john_smith/chatsync/
"""

    # Parse args
    try:
        mode       = argv[1]
        srcpath    = argv[2]

        if mode == "thread" or mode == "flat":
            myusername = argv[3]

            username_filter = None
            timestamp_from = None
            timestamp_to = None

            if len(argv) >= 5:
                username_filter = argv[4].split(",")

            if len(argv) >= 6:
                timestamp_from = int(argv[5])

            if len(argv) >= 7:
                timestamp_to = int(argv[6])

        elif len(argv) > 3:
            print("Invalid arguments", file=sys.stderr)
            print(main.__doc__, file=sys.stderr)
            exit(1)

    except Exception:
        print("Invalid arguments", file=sys.stderr)
        print(main.__doc__, file=sys.stderr)
        exit(1)


    # Do it
    if mode == "thread":
        mode_thread(srcpath, myusername, username_filter, timestamp_from, timestamp_to)
        return

    if mode == "flat":
        mode_flat(srcpath, myusername, username_filter, timestamp_from, timestamp_to)
        return

    if mode == "flat-per-file":
        mode_flatperfile(srcpath)
        return

    if mode == "dump":
        mode_dump(srcpath)
        return

    if mode == "test":
        mode_test(srcpath)
        return

    print("Unknown mode {}".format(mode), file=sys.stderr)
    exit(1)

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
    )


def import_path(srcpath, history):
    if os.path.isdir(srcpath):
        errors = history.import_directory(srcpath)
        for err in errors:
            print("WARNING: {}".format(err), file=sys.stderr)
    else:
        try:
            history.import_file(srcpath)
        except scanner.ScanException as e:
            print("Error while importing file: {}: {}".format(srcpath, e.message), file=sys.stderr)
            exit(1)

def mode_thread(srcpath, myusername, username_filter, timestamp_from, timestamp_to):
    """Reads the (directory of) .dat file(s) at /srcpath/ and prints the messages."""

    history = scanner.ThreadedSkypeChatHistory(myusername, username_filter, timestamp_from, timestamp_to)
    import_path(srcpath, history)

    history.clean_threads()
    history.sort_threads()

    print("==== THREADS FOUND: ====")
    for peer_set in history.threads:
        print(" - " + ", ".join(peer_set))

    print("\n")

    for peer_set in history.threads:
        print("==== THREAD WITH {} ====".format(", ".join(peer_set)))
        for message in history.threads[peer_set]:
            print("    " + printable_message(message))
        print("\n")


def mode_flat(srcpath, myusername, username_filter, timestamp_from, timestamp_to):
    """Reads the (directory of) .dat file(s) at /srcpath/ and prints the messages."""

    history = scanner.FlatSkypeChatHistory(myusername, username_filter, timestamp_from, timestamp_to)
    import_path(srcpath, history)

    history.sort_messages()

    print("==== MESSAGES ====")
    for message in history.messages:
        print(printable_message(message))



def print_file(filepath):

    print("==== FILE {} ====".format(filepath))

    with open(filepath, 'rb') as filehandle:
        try:
            s = scanner.SkypeChatSyncScanner(filehandle)
            s.scan()
        except scanner.ScanException as e:
            print("{}: scan error: {}".format(filepath, e.message))
            return

        try:
            p = scanner.SkypeChatSyncParser(s)
            p.parse()
        except scanner.ScanException as e:
            print("{}: parse error: {}".format(filepath, e.message))
            return

    print("Session: {}".format(repr(p.session)))
    print("Empty: {}".format(p.is_empty))
    print("Time: {}".format(datetime.fromtimestamp(p.timestamp)))
    print("Peers: {}".format(p.peers))
    print("User name map: {}".format(p.user_name_map))

    for message in p.conversation:
        print(printable_message(message))

def mode_flatperfile(srcpath):
    """ """

    if not os.path.isdir(srcpath):
        print_file(srcpath)

    # Iterate directories
    for root, dirs, files in os.walk(srcpath):
        # Iterate files in directory
        for filename in files:
            # Only consider *.dat files
            if filename[-4:] != ".dat":
                continue

            # Skip OS X's "._*" metadata files
            if filename[:2] == "._":
                continue

            print_file(root + "/" + filename)
            print("\n")


def mode_dump(srcpath):
    """Scans and dumps the .dat file at /srcpath/"""

    with open(srcpath, 'rb') as filehandle:
        s = scanner.SkypeChatSyncScanner(filehandle)
        try:
            s.scan()
            if s.warnings == 0:
                print("Scan completed without problems")
            else:
                print("Scan completed with {} warnings".format(s.warnings))

        except scanner.ScanException as e:
          print("Scan error, skipping: {}: {}".format(srcpath, e.message))

        print("\n== DUMPING SCANNED BLOCKS ===")
        dump_var(s.blocks)

def mode_test(srcpath):
    if not os.path.isdir(srcpath):
        # Test a single file
        test_datfile(srcpath)
        return

    # Iterate directories
    for root, dirs, files in os.walk(srcpath):
        # Iterate files in directory
        for filename in files:
            # Only consider *.dat files
            if filename[-4:] != ".dat":
                continue

            # Skip OS X's "._*" metadata files
            if filename[:2] == "._":
                continue

            test_datfile(root + "/" + filename)

def test_datfile(filepath):
    with open(filepath, 'rb') as filehandle:
        try:
            s = scanner.SkypeChatSyncScanner(filehandle)
            s.scan()
        except scanner.ScanException as e:
            print("{}: scan error: {}".format(filepath, e.message))
            return

        try:
            p = scanner.SkypeChatSyncParser(s)
            p.parse()
        except scanner.ScanException as e:
            print("{}: parse error: {}".format(filepath, e.message))
            return

        print("{}: OK".format(filepath))


main(sys.argv)
