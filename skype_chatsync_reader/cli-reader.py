#!/usr/bin/env python

from __future__ import print_function

import sys
import os
import codecs

from datetime import datetime
from HTMLParser import HTMLParser

import scanner

from dump_var import dump_var

def main(argv):
    """USAGE: cli-reader.py <thread|flat|dump> <srcpath> <myusername> [username1,username2,...] [timestamp_from] [timestamp_to]

    WHERE
      <srcpath>        Path to a a single .dat file or a directory to recurse
      thread|flat|dump Mode
      <myusername>     Your Skype username
      [username1,..]   Filter: Comma-separated list of usernames to include, default: all
      [timestamp_from] Filter: Min. Unix timestamp, default: none
      [timestamp_to]   Filter: Max. Unix timestamp, default: none

    EXAMPLE
      ./cli-reader.py thread /tmp/chatsync/ john_smith jane_smith,john_doe,jane_doe 1451606400
    """

    # Parse args
    mode       = argv[1]
    srcpath    = argv[2]
    myusername = argv[3]

    username_filter = None
    if len(argv) >= 5:
        username_filter = argv[4].split(",")

    timestamp_from = None
    if len(argv) >= 6:
        timestamp_from = int(argv[5])

    timestamp_to = None
    if len(argv) >= 7:
        timestamp_to = int(argv[6])

    # Do it
    if mode == "thread":
        threads(srcpath, myusername, username_filter, timestamp_from, timestamp_to)

    elif mode == "flat":
        flat(srcpath, myusername, username_filter, timestamp_from, timestamp_to)

    elif mode == "dump":
        with open(srcpath, 'rb') as filehandle:
            s = scanner.SkypeChatSyncScanner(filehandle)
            try:
                s.scan()
            except Exception as e:
              print("Scan error, skipping: {}: {}".format(srcpath, e.message))
              print("== DUMPING SCANNED BLOCKS ===")
              dump_var(s.blocks)

    else:
        print("Unknown mode {}".format(mode), file=sys.stderr)
        exit(1)

def printable_message(message):
    html = HTMLParser()

    edited = ""
    if message.is_edit:
        edited = " (edited)"

    message_text = html.unescape(message.text.encode('ascii', 'replace').replace("\n", "\n\t"))

    return "<{}> {:15s}{} {}".format(
        datetime.fromtimestamp(message.timestamp),
        "<" + message.author + ">",
        edited,
        message_text
    )


def threads(srcpath, myusername, username_filter, timestamp_from, timestamp_to):

    history = scanner.ThreadedSkypeChatHistory(myusername, username_filter, timestamp_from, timestamp_to)

    if os.path.isdir(srcpath):
        errors = history.import_directory(srcpath)
        for err in errors:
            print("WARNING: {}".format(err), file=sys.stderr)
    else:
        try:
            history.import_file(srcpath)
        except Exception as e:
            print("Error while importing file: {}: {}".format(srcpath, e.message), file=sys.stderr)
            exit(1)

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

def flat(srcpath, myusername, username_filter, timestamp_from, timestamp_to):

    history = scanner.FlatSkypeChatHistory(myusername, username_filter, timestamp_from, timestamp_to)

    if os.path.isdir(srcpath):
        errors = history.import_directory(srcpath)
        for err in errors:
            print("WARNING: {}".format(err), file=sys.stderr)
    else:
        try:
            history.import_file(srcpath)
        except Exception as e:
            print("Error while importing file: {}: {}".format(srcpath, e.message), file=sys.stderr)
            exit(1)

    history.sort_messages()

    print("==== MESSAGES ====")
    for message in history.messages:
        print(printable_message(message))

main(sys.argv)
