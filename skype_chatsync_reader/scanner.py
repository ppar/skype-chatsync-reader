'''
A file format parser for Skype's "chatsync" files.
Format as described by kmn in http://www.hackerfactor.com/blog/index.php?/archives/231-Skype-Logs.html#c1066

As the format specification used is not official and incomplete, the parser is limited in what it can do.
It may fail on some files, and on other files will only be able to extract messages partially.

Copyright 2015, Konstantin Tretyakov; 2017, Peter Parkkali
MIT License.

Portions of file format descriptions are from abovementioned blog article.
'''

from struct import unpack, calcsize
from collections import namedtuple
from datetime import datetime
from glob import glob
import warnings
import os
import re

from dump_var import dump_var

class ScanException(Exception):
    def __init__(self, message):
        super(ScanException, self).__init__(message)

#
# The FileHeader, BlockHeader and MessageHeader classes represent binary
# structures within the .dat file.
#
# The __format___ property descibes the data types found in the binary
# file and each field's byte sizes - https://docs.python.org/2/library/struct.html
#

class FileHeader(namedtuple('FileHeader', 'signature timestamp data_size padding')):
    """Represents the .dat file's main header - first 32 bytes

        FMT  TYPE            SIZE (b)    USE
        <    little-endian   -           -
        5s   5 x char[]      5x1         0x73; 0x43; 0x64; 0x72; 0x07 in ASCII terms "sCdB(bell)"
        I    unsigned int    4           4 bytes: unsigned int, unix timestamp
        I    unsigned int    4           4 or more bytes: unsigned int; total data size after header (filesize - 32)
        19s  19 x char[]     19          N bytes padding
    """
    __format__ = '<5sII19s'

    def validate(self, scanner):
        """Validates the read data"""
        if self.signature != 'sCdB\x07':
            raise ScanException("Error scanning header in %s. Invalid signature: %s." % (scanner.name, self.signature))
        if self.padding != '\x00'*19:
            scanner.warning_list.append("Header padding not all zeroes in %s." % scanner.name)
            scanner.warnings += 1

Block = namedtuple ('Block', 'block_header block_data')

class BlockHeader(namedtuple('BlockHeader', 'data_size x type padding')):
    """Represents a "block header" in the .dat file - 16 bytes.

       .dat files contain 6 major blocks of data enumerated #1 - #6. Each of them has a standard header:

        FMT  TYPE            SIZE (b)    USE
        <    little-endian   -           -
        I    unsigned int    4           4 bytes: unsigned int; block data size (in bytes)
        I    unsigned int    4           4 bytes: unknown id
        I    unsigned int    4           4 bytes: unsigned int; block number/descriptor (1,2,3,4,5 or 6)
        4s   5 x char[]      4           4 bytes padding

        Each major block, according to it's descriptor (1-6) has different internal data structure,
        these are represented by <......> below.
    """
    __format__ = '<III4s'

    def validate(self, scanner):
        if self.padding != '\x00'*4:
            scanner.warning_list.append("Block #%d header padding not all zeroes in %s." % (len(scanner.blocks) + 1, scanner.name))
            scanner.warnings += 1
        if self.type < 1 or self.type > 6:
            raise ScanException("Error scanning block #%d in %s. Type field value %d invalid." % (len(scanner.blocks) + 1, scanner.name, self.type))

Message = namedtuple('Message', 'header records')

class MessageHeader(namedtuple('MessageHeader', 'id x timestamp y data_size')):
    """Represents a binary structure within the .dat file"""

    # little-endian, 5x unsigned int
    __format__ = '<5I'
    def validate(self, scanner):
        pass

Record = namedtuple('Record', 'n fields')

class Field(namedtuple('Field', 'type code value')):
    INT = 0
    TYPE1 = 1
    STRING = 3
    BLOB = 4
    END_OF_RECORD = 5
    TYPE6 = 6


class SkypeChatSyncScanner(object):

    # Internal properties:
    #
    # input         File         Input file
    # name          string       Name/descr of the input file
    # file_header   FileHeader   The main header
    #

    # Scanned data is made available in properties:
    #
    # timestamp     datetime     The timestamp read from the file's main header
    # warnings      int          Nr of warnings
    # blocks        []

    def __init__(self, file_like_object, name=None):
        """Constructor method.
           file_like_object:   File handle to the input file
           name:               Optional name/description of the input file
        """
        self.input = file_like_object
        self.name = name if name is not None else repr(self.input)
        self.warning_list = []

    def scan(self, validate=True):
        """Scans the input file."""

        # Read in the file's main header
        size, self.file_header = self.scan_struct(FileHeader)
        self.timestamp = datetime.fromtimestamp(self.file_header.timestamp)

        self.warnings = 0
        self.blocks = []

        # Read in each of the file's major blocks
        size, self.blocks = self.scan_sequence(self.scan_block, self.file_header.data_size)

        if validate:
            # Validate the whole thing.
            self.validate()

    def validate(self):
        """Tries to validate the whole object by checking for presence of a single type-6 block. NOTE: not 100% correct; some files do not contain these blocks."""

        if len(self.blocks) != 6:
            self.warning_list.append("Incorrect number of blocks (%d) read from %s." % (len(self.blocks), self.name))
            self.warnings += 1
        else:
            block_ids = [b.block_header.type for b in self.blocks]
            if sorted(block_ids) != range(1, 7):
                self.warning_list.append("Not all blocks 1..6 are present in %s." % self.name)
                self.warnings += 1

        block_6 = [b for b in self.blocks if b.block_header.type == 6]

        if len(block_6) != 1:
            raise ScanException("Block 6 not found, or more than one found in file %s." % self.name)

    def scan_sequence(self, method, nbytes, stop_at=lambda x: False):
        """Calls the data type-specific scanner method /method/ sequentially until /nbytes/ bytes
           have been read from the input file or .....

           Returns (<the number of bytes left unread>, <a [] of items returned by /method/>)
        """
        items = []
        remaining = nbytes
        while remaining > 0:
            size, item = method(remaining)
            items.append(item)
            remaining -= size
            if stop_at(item):
                break
        if remaining < 0:
            self.warning_list.append("Invalid data size detected during sequence parsing in %s." % self.name)
            self.warnings += 1
        return nbytes - remaining, items

    def scan_struct(self, cls):
        """Reads a fixed number of bytes from the input file and interprets the data based on
           the class /cls/, which is one of the binary strcut-describing classes (FileHeader,
           BlockHeader, MessageHeader).

           Creates an object of the specified class and calls the class's validate() method.

           Returns (<nr of bytes read>, <the created object).
        """
        size = calcsize(cls.__format__)
        data = self.input.read(size)
        if len(data) != size:
            raise ScanException("Error while scanning %s in %s. File too short." % (cls.__name__, self.name))
        result = cls._make(unpack(cls.__format__, data))
        result.validate(self)
        return size, result

    def scan_block(self, nbytes):
        """Scanner callback for scan_sequence(). Scans a top-level data block header and branches to
           scan the block-type-specific data following it.

           Returns (<nr of bytes read>, <Block object containing the block header and data>)"""
        hsize, block_header = self.scan_struct(BlockHeader)
        dsize, block_data = self.scan_block_data(block_header)
        return hsize + dsize, Block(block_header, block_data)

    def scan_block_data(self, block_header):
        if block_header.type == 5:
            return self.scan_block_5_data(block_header)
        elif block_header.type == 6:
            return self.scan_block_6_data(block_header)
        else:
            return self.scan_block_1234_data(block_header)

    def scan_block_1234_data(self, block_header):
        """Scans a "type 1/2/3/4" block.

           These blocks share common internal structure: a collection of "variable clusters"
           (records). That is sequence of DBB variables in separate sub-blocks. Each "variable
           cluster" has the structure

           byte 0x41 "A"
           byte N
           --
           --
           DBB variables
           --
           --
           ( end of record )


           DBB variables:

           - All content begins with 0x03. Read the data until you hit an 0x03. This does not
           need to be on the even byte offset!

           - If the byte is a 0x03, then it is followed by a number. Numbers are in a 7-bit format.
           The MSB identifies whether it is the last byte in the number sequence. (If the MSB is
           set (Byte & 0x80), then it is not the last byte in the number. If the MSB is clear,
           then it is the last byte in the number.) This number identifies the TYPE of the data field.

           - All bytes after the type are the data for the field.

           - All data sections end with 0x00, 0x01, 0x02, or 0x03. If it is 0x03, then it denotes a
           new dataset immediately after the last data set. Process this next set of data. If it
           is 0x00, then the next bytes are junk. Read until you hit another 0x03.
        """
        return self.scan_sequence(self.scan_record, block_header.data_size)

    def scan_block_5_data(self, block_header):
        """Scans a "type 5" block (blocks?).

           "[Block type 5] is just a collection of 16byte records, containng four 4-byte integer values,
            which represent message id (as insert into main.dbb or DBB), message handles (relating to
            block #6) and a field i have no clue about. Data is aligned, so reading sequence of 32bit
            integers is straight-forward."
        """
        return block_header.data_size, [unpack('<4I', self.input.read(16)) for i in range(block_header.data_size/16)]

    def scan_block_6_data(self, block_header):
        """Scans a sequence of "type 6" blocks, i.e. messages"""
        return self.scan_sequence(self.scan_message, block_header.data_size)

    def scan_record(self, nbytes):
        """Scanner callback for scan_sequence(), utilized by scan_block_1234_data() and scan_message()."""
        signature = self.input.read(1)
        if (signature != 'A'):
            raise ScanException("Record expected to start with 'A' in %s." % self.name)
        n = ord(self.input.read(1))
        if n == 0:
            return 2, Record(n, [])
        else:
            size, fields = self.scan_sequence(self.scan_field, nbytes-2, lambda f: f.type == Field.END_OF_RECORD)
            return size + 2, Record(n, fields)

    def scan_field(self, nbytes):
        """Scanner callback for scan_sequence(), utilized by scan_record()"""

        type = ord(self.input.read(1))
        if type == Field.INT:
            csize, code = self.scan_7bitint()
            vsize, value = self.scan_7bitint()
        elif type == Field.STRING:
            csize, code = self.scan_7bitint()
            vsize, value = self.scan_cstring()
        elif type == Field.BLOB:
            csize, code = self.scan_7bitint()
            vsize, value = self.scan_blob()
        elif type == Field.TYPE1:
            csize, code = self.scan_7bitint()
            vsize, value = 8, self.input.read(8)
        elif type == Field.END_OF_RECORD:
            csize, code = self.scan_7bitint()
            vsize, value = 0, 0
        elif type == Field.TYPE6:
            code = self.input.read(1)             # Seems to always be 0x08
            csize, oneortwo = self.scan_7bitint() # Seems to always be 1 or 2
            vsize = 1
            value = []
            for i in range(oneortwo):
                _vsize, v = self.scan_7bitint()
                vsize += _vsize
                value.append(v)
        else:
            raise ScanException("Field of unexpected type %d detected in %s." % (type, self.name))
        return csize + vsize + 1, Field(type, code, value)

    def scan_message(self, nbytes):
        """Scanner callback for scan_sequence(), utilized by scan_block_6_data()"""
        hsize, header = self.scan_struct(MessageHeader)
        rsize, records = self.scan_sequence(self.scan_record, header.data_size)
        return hsize + rsize, Message(header, records)

    def scan_7bitint(self):
        result = 0
        coef = 1
        size = 0
        loop = True
        while loop:
            v = self.input.read(1)
            if (v == ''):
                raise ScanException("Error parsing 7 bit integer in %s. Unexpected end of file." % self.name)
            v = ord(v)
            if v & 0x80:
                v = v ^ 0x80
            else:
                loop = False
            result += v * coef
            coef <<= 7
            size += 1
        return size, result

    def scan_cstring(self):
        result = ''
        c = self.input.read(1)
        while c != '\x00' and c != '':
            result += c
            c = self.input.read(1)
        return len(result) + 1, result

    def scan_blob(self):
        sizesize, size = self.scan_7bitint()
        data = self.input.read(size)
        return sizesize + len(data), data


ConversationMessage = namedtuple('ConversationMessage', 'timestamp author text is_edit')

class SkypeChatSyncParser(object):
    """Represents data parsed from a single .dat file.

    After calling .parse(), data is available in fields:

    is_empty                Bool
    timestamp               UNIX timestamp from the file's main header
    conversation            A list of ConversationMessage tuples

    session_id              Session id of the form '#username_1/$username_2;6a2b3ce00f8123ca'
    session['caller']       Caller's username parsed from session_id
    session['recipient']    Receipient's username parsed from session_id
    session['connection_id'] Connection ID parsed from session_id
    participants[0]         An alias of session.caller
    participants[1]         An alias of session.recipient

    peers                   List containing usernames of all participants found in the .dat file

    user_name_map           A dict of [transient numeric userid] => [textual username] mappings

    As far as multi-user chats are recognized, .peers contains ids of all users in the chat.
    """

    def __init__(self, scanner):
        self.scanner = scanner
        self.debug_append_username_userids = False

        self.session = {
            "caller": None,
            "recipient": None,
            "connection_id": None
        }

    def parse(self):
        self.timestamp = self.scanner.file_header.timestamp
        self.conversation = []
        self.warning_list = []
        self.is_empty = False
        self.user_name_map = {}

        if (len(self.scanner.blocks) == 0
                or len(self.scanner.blocks[0].block_data) == 0
                or len(self.scanner.blocks[0].block_data[0].fields) == 0):
            self.is_empty = True
            return

        #
        # Parse the session id
        #
        self.session_id = self.scanner.blocks[0].block_data[0].fields[0].value
        # [value] <str(41)> '#username_caller/$username_recipient;6a2b3ce00f8123ca'
        # - Provides the caller's and recipient's usernames and the connection ID
        matches = re.match('^\#([^/]+)/\$([^;]+);([0-9a-fA-F]+)$', self.session_id)
        if matches:
            self.session["caller"] = matches.group(1)
            self.session["recipient"] = matches.group(2)
            self.session["connection_id"] = matches.group(3)
            self.participants = [self.session['caller'], self.session['recipient']]

        else:
            # '#username/$6ec145419e3abe10'
            matches = re.match('^\#([^/]+)/\$([0-9a-fA-F]+)$', self.session_id)
            if matches:
                self.session["caller"] = matches.group(1)
                self.session["connection_id"] = matches.group(2)
                self.participants = [self.session['caller'], None]
            else:
                raise ScanException("Could not parse session ID: {}".format(self.session_id))

        # Parse all "Type 2" blocks for usernames
        for block_index, block in enumerate(self.scanner.blocks):
            if block.block_header.type == 2:
                self.parse_blocktype_2(block_index)

        # Parse all "Type 6" blocks for usernames
        for block_index, block in enumerate(self.scanner.blocks):
            if block.block_header.type == 6:
                self.parse_blocktype_6_usernames(block_index)

        # Parse all "Type 6" blocks for messages
        for block_index, block in enumerate(self.scanner.blocks):
            if block.block_header.type == 6:
                self.parse_blocktype_6_messages(block_index)
        #
        self.parse_peers()

    def parse_blocktype_2(self, block_index):
        """Parses a type-2 block and looks for user id => user name mappings"""

        #    [5] <Tuple:Record>
        #        [n] <int> 6
        #        [fields] <list>
        #          [0] <Tuple:Field>
        #            [type] <int> 0
        #            [code] <int> 2
        #            [value] <int> XXXXXX
        #          [1] <Tuple:Field>
        #            [type] <int> 0
        #            [code] <int> 3
        #            [value] <int> NNNNNNNNN		// USER ID
        #          [2] <Tuple:Field>
        #            [type] <int> 4
        #            [code] <int> 4
        #            [value] <str(179)> '.........'  // Message text?
        #          [3] <Tuple:Field>
        #            [type] <int> 0
        #            [code] <int> 5
        #            [value] <int> XXXXXX
        #          [4] <Tuple:Field>
        #            [type] <int> 5
        #            [code] <int> 1
        #            [value] <int> 0
        #      [6] <Tuple:Record>
        #        [n] <int> 2
        #        [fields] <list>
        #          [0] <Tuple:Field>
        #            [type] <int> 3
        #            [code] <int> 0
        #            [value] <str(7)> 'UserName'      // USER NAME
        #          [1] <Tuple:Field>
        #            [type] <int> 4
        #            [code] <int> 1
        #            [value] <str(29)> '........'   // Message text?
        #          [2] <Tuple:Field>
        #            [type] <int> 4
        #            [code] <int> 6
        #            [value] <str(260)> '.........'  // Message text?
        #          [3] <Tuple:Field>
        #            [type] <int> 5
        #            [code] <int> 1
        #            [value] <int> 0
        #

        block = self.scanner.blocks[block_index]

        user_id_record_index = -2
        for record_index, record in enumerate(block.block_data):
            for field_index, field in enumerate(record.fields):
                # The user ID comes first
                # Assume the magic pair (type=0, code=3) signals the userid
                if field.type == 0 and field.code == 3 and field_index == 1:
                    user_id = field.value
                    user_id_record_index = record_index
                    #print("user_id {} field_index {} record_index {}".format(user_id, field_index, record_index))
                    continue

                # The user name comes in the record following it
                # Assume the magic pair (type=3, code=0) signals this
                if field.type == 3 and field.code == 0 and field_index == 0 and record_index == user_id_record_index + 1:
                    user_name = field.value
                    #print("user_name {} field_index {} record_index {} UIRI {}".format(
                    #    user_name, field_index, record_index, user_id_record_index))
                    self.user_name_map[user_id] = user_name
                    user_id_record_index = -2
                    user_id = None
                    user_name = None


    def parse_blocktype_6_usernames(self, block_index):
        """Tries to parse the caller's numeric userid from the first message.

        Searches for the first message with two parts. Assumemes the numeric userid found
        therein belongs to the caller and adds it to the userid map.

        NOTE: This is not always true; sometimes this numeric userid belongs to the recipient
        instead and calling this method results in an incorrect mapping!
        """

        # Typical / expected case:
        #
        #      [0] <Tuple:Message>
        #        [header] <Tuple:MessageHeader>
        #          [id] <int> XXXXXX
        #          [x] <int> XXXXX
        #          [timestamp] <int> XXXXX
        #          [y] <int> 64
        #          [data_size] <int> 237
        #        [records] <list>
        #          [0] <Tuple:Record>
        #            [n] <int> 2
        #            [fields] <list>
        #              [0] <Tuple:Field>
        #                [type] <int> 3
        #                [code] <int> 0
        #                [value] <str(24)> 'UserName'   /// USERNAME
        #              [1] <Tuple:Field>
        #                [type] <int> 5
        #                [code] <int> 2
        #                [value] <int> 0
        #          [1] <Tuple:Record>
        #            [n] <int> 3
        #            [fields] <list>
        #              [0] <Tuple:Field>
        #                [type] <int> 0
        #                [code] <int> 2
        #                [value] <int> 1
        #              [1] <Tuple:Field>
        #                [type] <int> 0
        #                [code] <int> 3
        #                [value] <int> NNNNNNN     // USER ID
        #              [2] <Tuple:Field>
        #                [type] <int> 4
        #                [code] <int> 4
        #                [value] <str(190)> '....'
        #

        # Exception in D / chatsync/0a/0a5beb1c1cc7d857.dat:
        #
        # [0] <Tuple:Message>
        #   [header] <Tuple:MessageHeader>
        #     [id] <int> 354454083
        #     [x] <int> 22549700
        #     [timestamp] <int> 1352983489
        #     [y] <int> 64
        #     [data_size] <int> 220
        #   [records] <list>
        #     [0] <Tuple:Record>
        #       [n] <int> 2
        #       [fields] <list>
        #         [0] <Tuple:Field>
        #           [type] <int> 3
        #           [code] <int> 0
        #           [value] <str(15)> 'CallersUserName' // CALLERS USERNAME
        #         [1] <Tuple:Field>
        #           [type] <int> 5
        #           [code] <int> 2
        #           [value] <int> 0
        #     [1] <Tuple:Record>
        #       [n] <int> 3
        #       [fields] <list>
        #         [0] <Tuple:Field>
        #           [type] <int> 0
        #           [code] <int> 2
        #           [value] <int> 1
        #         [1] <Tuple:Field>
        #           [type] <int> 0
        #           [code] <int> 3
        #           [value] <int> MMMMMMMM   // RECIPIENT'S USER ID
        #         [2] <Tuple:Field>
        #           [type] <int> 4
        #           [code] <int> 4
        #           [value] <str(182)> '..........'

        first_valid_block = -1
        for i, msg in enumerate(self.scanner.blocks[block_index].block_data):
            if len(msg.records) > 1 and len(msg.records[1].fields) > 1:
                first_valid_block = i
                break

        if first_valid_block == -1:
            #self.is_empty = True
            return

        user1_id = self.scanner.blocks[block_index].block_data[first_valid_block].records[1].fields[1].value

        if user1_id not in self.user_name_map:
            # Add the mapping
            self.user_name_map[user1_id] = self.session['caller']
            return

        if self.user_name_map[user1_id] == self.session['caller']:
            # Same mapping already existed
            return

        # Conflicting mapping already existed
        msg = "Mismatching user id: {} => {} (message block, session.caller) vs {} (type-2-block)".format(
            user1_id, self.session['caller'], self.user_name_map[user1_id])
        #raise ScanException(msg)
        self.warning_list.append(msg)
        self.user_name_map[user1_id] = self.user_name_map[user1_id] + "|" + self.session['caller']

    def blob2message(self, blob):
        """Decodes a message blob into text"""
        try:
            msg_start = blob.index('\x03\x02')
            msg_end = blob.index('\x00', msg_start+1)
            msg_text = blob[msg_start+2:msg_end]
            is_edit = False
        except:
            try:
                msg_start = blob.index('\x03"')
                msg_end = blob.index('\x00', msg_start+1)
                msg_text = blob[msg_start+2:msg_end]
                is_edit = True
            except:
                return None, None

        return msg_text, is_edit

    def parse_blocktype_6_messages(self, block_index):
        """Parses a Type 6 block for messages and appends them to self.conversation."""

        # Note: "first_valid_block / is_empty" check missing

        for block_data_index, msg in enumerate(self.scanner.blocks[block_index].block_data):
            if len(msg.records) < 2:
                continue
            if len(msg.records[1].fields) < 3:
                continue

            # Get the message's username
            author_user_id = msg.records[1].fields[1].value
            if author_user_id in self.user_name_map:
                author_user_name = self.user_name_map[author_user_id]
                if self.debug_append_username_userids:
                    author_user_name += ":" + str(author_user_id)
            else:
                author_user_name = "??:" + str(author_user_id)

            msg_text, is_edit = self.blob2message(msg.records[1].fields[2].value)

            ##############

            # ConversationMessage = namedtuple('ConversationMessage', 'timestamp author text is_edit')

            # self.conversation.append(ConversationMessage(
            #     msg.header.timestamp,
            #     author_user_name,
            #     unicode(msg_text, 'utf-8'),
            #     is_edit)
            # )

            if msg_text == None:
                self.warning_list.append("blob2message() failed at blocks[{}].block_data[{}]".format(block_index, block_data_index))
                msg_text = "<DECODING FAILED>"

            if is_edit == None:
                is_edit = False

            try:
                cm = ConversationMessage(
                    msg.header.timestamp,
                    author_user_name,
                    unicode(msg_text, 'utf-8'),
                    is_edit
                )

            except UnicodeDecodeError:
                cm = ConversationMessage(
                    msg.header.timestamp,
                    author_user_name,
                    unicode("<UNICODE ERROR>", 'utf-8'),
                    is_edit
                )

            self.conversation.append(cm)

    def parse_peers(self):
        """Iterates through self.conversation and appends all usernames found to self.peers"""

        peer_set = set()

        for username in [self.session['caller'], self.session['recipient']]:
            peer_set.add(username)

        for msg in self.conversation:
            peer_set.add(msg.author)

        if None in peer_set:
            peer_set.remove(None)

        if len(peer_set) == 0:
            peer_set.add('__UNKNOWN__')

        self.peers = list(peer_set)


class AbstractChatHistory(object):
    """Common methods for ThreadedSkypeChatHistory and FlatSkypeChatHistory"""

    # Input parameters
    my_username     = None
    username_filter = None
    timestamp_from  = None
    timestamp_to    = None

    def __init__(self, my_username, username_filter=None, timestamp_from=None, timestamp_to=None):
        """Constructor method. Messages are filtered by username_filter, timestamp_from and timestamp_to if any are set"""

        self.my_username     = my_username
        self.username_filter = username_filter
        self.timestamp_from  = timestamp_from
        self.timestamp_to    = timestamp_to

    def check_username_filter(self, peer_set):
        """Checks peer_set against self.userlist_filter"""

        if self.username_filter == None:
            return True

        for username in self.username_filter:
            if username in  peer_set:
                return True

        return False

    def check_timestamp_filters(self, message):
        """Checks message against timestamp filters"""

        if self.timestamp_from != None:
            if message.timestamp < self.timestamp_from:
                return False

        if self.timestamp_to != None:
            if message.timestamp > self.timestamp_to:
                return False

        return True

class ThreadedSkypeChatHistory(AbstractChatHistory):
    """Represents a complete parsed chat history, sorted into threads according to participants

    The .threads property is a dict containing the threads where the keys are frozenset()s
    containing the usernames of this thread's members and the values are lists of
    ConversationMessage tuples.
    """

    # Result: a {} of []s containing messages
    threads = {}

    def append_history(self, parser):
        """Appends messages in /parser/ to this object. parser: a SkypeChatSyncParser that has had parse() called"""

        #  p.timestamp, p.participants, and p.conversation

        # Find out who we're talking with
        peer_set = set(parser.peers)
        if self.my_username in peer_set:
            peer_set.remove(self.my_username)

        # Apply peer filter list
        if not self.check_username_filter(peer_set):
            return

        # frozensets can be used as keys
        peer_set = frozenset(peer_set)

        if peer_set not in self.threads:
            self.threads[peer_set] = []

        for message in parser.conversation:
            # Apply timestamp filters
            if not self.check_timestamp_filters(message):
                continue

            self.threads[peer_set].append(message)

    def clean_threads(self):
        """Removes empty threads"""

        new_threads = {}
        for peer_set in self.threads:
            if len(self.threads[peer_set]) > 0:
                new_threads[peer_set] = self.threads[peer_set]

        self.threads = new_threads

    def sort_threads(self):
        """Sorts each thread the .threads property according to timestamp"""
        for peer_set in self.threads:
            self.threads[peer_set] = sorted(self.threads[peer_set], key = lambda ts: ts.timestamp)


class FlatSkypeChatHistory(AbstractChatHistory):
    """Represents a complete parsed chat history without threads"""

    # Result: a [] of messages
    messages = []

    def append_history(self, parser):
        """Appends messages in /parser/ to this object. parser: a SkypeChatSyncParser that has had parse() called"""

        #  p.timestamp, p.participants, and p.conversation

        # Find out who we're talking with
        peer_set = set(parser.peers)
        if self.my_username in peer_set:
            peer_set.remove(self.my_username)

        # Apply peer filter list
        if not self.check_username_filter(peer_set):
            return

        for message in parser.conversation:
            # Apply timestamp filters
            if not self.check_timestamp_filters(message):
                continue

            self.messages.append(message)

    def sort_messages(self):
        """Sorts messages according to timestamp"""
        self.messages = sorted(self.messages, key = lambda ts: ts.timestamp)

def walk_dat_files(srcpath):
        """Generator method that retuns all .dat files under srcpath. The argument may point to a directory or a single .dat file"""

        if not os.path.isdir(srcpath):
            yield srcpath
            return

        for root, dirs, files in os.walk(srcpath):
            # Iterate files in directory
            for filename in files:
                # Only consider *.dat files
                if filename[-4:] != ".dat":
                    continue

                # Skip OS X's "._*" metadata files
                if filename[:2] == "._":
                    continue

                yield root + "/" + filename

def parse_chatsync_file(filename):
    '''
    Parses a given chatsync file.
    Throws an exception on any failure (which may happen even if the file is legitimate simply because we do not know all the details of the format).

    If succeeds, returns a SkypChatSyncParser object. Check out its "is_empty", "timestamp", "conversation" and "participants" fields.
    '''
    with open(filename, 'rb') as f:
        s = SkypeChatSyncScanner(f)
        s.scan()
        p = SkypeChatSyncParser(s)
        p.parse()
    return p


def parse_chatsync_profile_dir(dirname):
    '''
    Looks for all *.dat files in a Skype profile's chatsync/ dir,
    returns a list of SkypeChatParser objects for those files that could be parsed successfully.
    '''
    files = glob(os.path.join(dirname, "*", "*.dat"))
    results = []
    for f in files:
        try:
            results.append(parse_chatsync_file(f))
        except Exception, e:
            warnings.warn("Failed to parse file %s. Exception: %s" % (f, e.message))
    return results

