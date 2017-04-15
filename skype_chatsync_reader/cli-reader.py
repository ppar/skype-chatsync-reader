#!/usr/bin/env python

from __future__ import print_function

import sys
import os
import codecs

from datetime import datetime
from HTMLParser import HTMLParser

import scanner

def main(argv):
    srcdir = argv[1]
    myusername = argv[2]

    username_filter = None
    timestamp_from = None

    #username_filter = [ 'john.smith.1234', 'someone', 'someone.else']
    #timestamp_from = 1464739200
    #timestamp_from = 1451606400

    threads(srcdir, myusername, username_filter, timestamp_from, None)
    #flat(srcdir, myusername, username_filter, timestamp_from, None)


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


def threads(srcdir, myusername, username_filter, timestamp_from, timestamp_to):

    history = scanner.ThreadedSkypeChatHistory(myusername, username_filter, timestamp_from, timestamp_to)

    errors = history.import_directory(srcdir)

    for err in errors:
        print("WARNING: {}".format(err), file=sys.stderr)

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

def flat(srcdir, myusername, username_filter, timestamp_from, timestamp_to):

    history = scanner.FlatSkypeChatHistory(myusername, username_filter, timestamp_from, timestamp_to)
    errors = history.import_directory(srcdir)

    for err in errors:
        print("WARNING: {}".format(err), file=sys.stderr)

    history.sort_messages()

    print("==== MESSAGES ====")
    for message in history.messages:
        print(printable_message(message))

main(sys.argv)
