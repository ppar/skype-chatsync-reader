===============================================================================
Parser and GUI viewer of chatsync/\*.dat files from the Skype profile directory
===============================================================================

Skype stores conversations locally in two places. One is a SQLite database file, for which there are several convenient viewers out there.
Another is a set of ``dat`` files in the ``chatsync`` subdirectory of the profile. The latter contain, among other things, the "removed" messages
along with all the edits. Unfortunately, the format of those dat files does not seem to be documented anywhere, and the readers are scarce.

The package contains a crude file format parser for the ``dat`` files in the ``chatsync`` directory, created based on the hints,
given by user *kmn* in `this discussion <http://www.hackerfactor.com/blog/index.php?/archives/231-Skype-Logs.html#c1066>`__.

As the format specification used is not official and incomplete, the parser is limited in what it can do.
It may fail on some files, and on other files will only be able to extract messages partially.

In addition, the package contains a simple wx-based GUI tool for searching the log files visually and a CLI tool.

.. image:: http://fouryears.eu/wp-content/uploads/2015/01/skype-chatsync-viewer.png
   :align: center
   :target: http://fouryears.eu/2015/01/22/skype-removed-messages/

Installation
------------

The easiest way to install the latest Python package released by the original author is via ``easy_install`` or ``pip``::

    $ easy_install skype_chatsync_reader


NOTE: to get the most recent version, clone or download the GitHub repository's newest branch instead.

If you want to use the GUI tool, you will also need to install `wxPython 2.8 <http://wxpython.org/>`__ or later (it is not installed automatically).

A standalone executable version of the GUI tool for Windows can be downloaded `here <http://fouryears.eu/wp-content/uploads/skype-chatsync-viewer.exe>`__.

GUI Tool
--------
If you want to use the GUI tool, simply run the script::

    $ skype-chatsync-viewer

which is installed into your python's scripts directory together with the package.

NOTE: The GUI tool does not currently use all the features of the parser.

CLI Tool
--------
To use the CLI tool, simply run the cli-reader.py script:

    $ python skype_chatsync_reader/cli-reader.py

The CLI tool can currently

- scan a single file or a whole "chatsync" directory,
- print the output in threaded, flat or "raw" dump format and
- limit the filter the output based on usernames and a date/time ranges.

Specific usage instructions are provided by the script and not duplicated here.

Python Library
--------------

If you want to parse chatsync files programmatically, check out the classes in ``skype_chatsync_reader/scanner.py``:

- ``SkypeChatSyncScanner`` - low-level binary scanner for decoding a single .dat file
- ``SkypeChatSyncParser``  - parser for the latter's output
- ``ThreadedSkypeChatHistory`` - higher level class for sorting the message history into threads
- ``FlatSkypeChatHistory`` - higher level class for sorting the message history into an unthreaded list


A typical usage example for the -Scanner and -Parser classes is::

    with open(dat_file, 'rb') as f:
        s = SkypeChatSyncScanner(f)
        s.scan()
        p = SkypeChatSyncParser(s)
        p.parse()

Please see the classes' docstrings for a more accurate description of the API, including the -History classes.


ChangeLog
---------

 * 2015 / Konstantin Tretyakov - "This is a very crude implementation, written up in a single evening for fun. It is not meant to be production-quality software. There are numerous known and unknown issues."
 * 2017-04 / Peter Parkkali - "Added *History classes and CLI tool, extended the username search logic in SkypeChatSyncParser".

Copyright
---------

 * Copyright 2015, `Konstantin Tretyakov <http://kt.era.ee/>`
 * Copyright 2017, `Peter Parkkali <https://github.com/ppar/>`
 * MIT License
 * The icon used in the single-file executable is (c) `Umut Pulat <http://www.iconarchive.com/show/tulliana-2-icons-by-umut-pulat/log-icon.html>`__, licensed under LGPL.
