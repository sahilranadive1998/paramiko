# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Server-mode SFTP support.
"""

import os
import time
import errno
import libnfs
import sys
from hashlib import md5, sha1

from paramiko import util
from paramiko.sftp import (
    BaseSFTP,
    Message,
    SFTP_FAILURE,
    SFTP_PERMISSION_DENIED,
    SFTP_NO_SUCH_FILE,
    int64,
)
from paramiko.sftp_si import SFTPServerInterface
from paramiko.sftp_attr import SFTPAttributes
from paramiko.common import DEBUG
from paramiko.server import SubsystemHandler
from paramiko.util import b


# known hash algorithms for the "check-file" extension
from paramiko.sftp import (
    CMD_HANDLE,
    SFTP_DESC,
    CMD_STATUS,
    SFTP_EOF,
    CMD_NAME,
    SFTP_BAD_MESSAGE,
    CMD_EXTENDED_REPLY,
    SFTP_FLAG_READ,
    SFTP_FLAG_WRITE,
    SFTP_FLAG_APPEND,
    SFTP_FLAG_CREATE,
    SFTP_FLAG_TRUNC,
    SFTP_FLAG_EXCL,
    CMD_NAMES,
    CMD_OPEN,
    CMD_CLOSE,
    SFTP_OK,
    CMD_READ,
    CMD_DATA,
    CMD_WRITE,
    CMD_REMOVE,
    CMD_RENAME,
    CMD_MKDIR,
    CMD_RMDIR,
    CMD_OPENDIR,
    CMD_READDIR,
    CMD_STAT,
    CMD_ATTRS,
    CMD_LSTAT,
    CMD_FSTAT,
    CMD_SETSTAT,
    CMD_FSETSTAT,
    CMD_READLINK,
    CMD_SYMLINK,
    CMD_REALPATH,
    CMD_EXTENDED,
    SFTP_OP_UNSUPPORTED,
)

_hash_class = {"sha1": sha1, "md5": md5}


class SFTPServer(BaseSFTP, SubsystemHandler):
    """
    Server-side SFTP subsystem support.  Since this is a `.SubsystemHandler`,
    it can be (and is meant to be) set as the handler for ``"sftp"`` requests.
    Use `.Transport.set_subsystem_handler` to activate this class.
    """

    def __init__(
        self,
        channel,
        name,
        server,
        sftp_si=SFTPServerInterface,
        *args,
        **kwargs
    ):
        """
        The constructor for SFTPServer is meant to be called from within the
        `.Transport` as a subsystem handler.  ``server`` and any additional
        parameters or keyword parameters are passed from the original call to
        `.Transport.set_subsystem_handler`.

        :param .Channel channel: channel passed from the `.Transport`.
        :param str name: name of the requested subsystem.
        :param .ServerInterface server:
            the server object associated with this channel and subsystem
        :param sftp_si:
            a subclass of `.SFTPServerInterface` to use for handling individual
            requests.
        """
        BaseSFTP.__init__(self)
        SubsystemHandler.__init__(self, channel, name, server)
        transport = channel.get_transport()
        self.logger = util.get_logger(transport.get_log_channel() + ".sftp")
        self.ultra_debug = transport.get_hexdump()
        self.next_handle = 1
        # map of handle-string to SFTPHandle for files & folders:
        self.file_table = {}
        self.folder_table = {}
        self.server = sftp_si(server, *args, **kwargs)
        self.nfs_path = None
        self.previous_list_response = None
        # self.nfs_path_to_open = None
        self.nfs = libnfs.NFS('nfs://10.45.129.164/default-container-14151218230332/')
        self.nfs_open_handle = None
        self.write_size_dict = {}
        # self.fname = "caching_coalesced_append"
        # self.cache_debug_file_name = "/home/nutanix/sahil/debug_logs/cache_size.out"
        # self.cache_write_time_file_name = "/home/nutanix/sahil/debug_logs/write_time.out"
        # self.cache_read_time_file_name = "/home/nutanix/sahil/debug_logs/read_time.out"
        # self.cache_debug_file_handle = open( self.cache_debug_file_name, "a+")
        # self.cache_write_time_file_handle = open( self.cache_write_time_file_name, "a+")
        # self.cache_read_time_file_handle = open( self.cache_read_time_file_name, "a+")
        self.cache = {}
        self.cache_offsets = {}
        # self.cache_test_file = open("/home/nutanix/sahil/qemu-traces/qemu_cache_writes.out","a+")
        # Creating file for testbench
        # self.test_file = open("/home/nutanix/sahil/qemu-traces/sftp_full_trace.out","a+")

    def _log(self, level, msg):
        if issubclass(type(msg), list):
            for m in msg:
                super()._log(level, "[chan " + self.sock.get_name() + "] " + m)
        else:
            super()._log(level, "[chan " + self.sock.get_name() + "] " + msg)

    def start_subsystem(self, name, transport, channel):
        self.sock = channel
        self._log(DEBUG, "Started sftp server on channel {!r}".format(channel))
        self._send_server_version()
        self.server.session_started()
        while True:
            try:
                t, data = self._read_packet()
            except EOFError:
                self._log(DEBUG, "EOF -- end of session")
                return
            except Exception as e:
                self._log(DEBUG, "Exception on channel: " + str(e))
                self._log(DEBUG, util.tb_strings())
                return
            msg = Message(data)
            request_number = msg.get_int()
            try:
                self._process(t, request_number, msg)
            except Exception as e:
                self._log(DEBUG, "Exception in server processing: " + str(e))
                self._log(DEBUG, util.tb_strings())
                # send some kind of failure message, at least
                try:
                    self._send_status(request_number, SFTP_FAILURE)
                except:
                    pass

    def finish_subsystem(self):
        self.server.session_ended()
        super().finish_subsystem()
        # close any file handles that were left open
        # (so we can return them to the OS quickly)
        for f in self.file_table.values():
            f.close()
        for f in self.folder_table.values():
            f.close()
        self.file_table = {}
        self.folder_table = {}

    @staticmethod
    def convert_errno(e):
        """
        Convert an errno value (as from an ``OSError`` or ``IOError``) into a
        standard SFTP result code.  This is a convenience function for trapping
        exceptions in server code and returning an appropriate result.

        :param int e: an errno code, as from ``OSError.errno``.
        :return: an `int` SFTP error code like ``SFTP_NO_SUCH_FILE``.
        """
        if e == errno.EACCES:
            # permission denied
            return SFTP_PERMISSION_DENIED
        elif (e == errno.ENOENT) or (e == errno.ENOTDIR):
            # no such file
            return SFTP_NO_SUCH_FILE
        else:
            return SFTP_FAILURE

    @staticmethod
    def set_file_attr(filename, attr):
        """
        Change a file's attributes on the local filesystem.  The contents of
        ``attr`` are used to change the permissions, owner, group ownership,
        and/or modification & access time of the file, depending on which
        attributes are present in ``attr``.

        This is meant to be a handy helper function for translating SFTP file
        requests into local file operations.

        :param str filename:
            name of the file to alter (should usually be an absolute path).
        :param .SFTPAttributes attr: attributes to change.
        """
        if sys.platform != "win32":
            # mode operations are meaningless on win32
            if attr._flags & attr.FLAG_PERMISSIONS:
                os.chmod(filename, attr.st_mode)
            if attr._flags & attr.FLAG_UIDGID:
                os.chown(filename, attr.st_uid, attr.st_gid)
        if attr._flags & attr.FLAG_AMTIME:
            os.utime(filename, (attr.st_atime, attr.st_mtime))
        if attr._flags & attr.FLAG_SIZE:
            with open(filename, "w+") as f:
                f.truncate(attr.st_size)

    # ...internals...

    def _set_sftp_attributes(self, nfs_stat_response):
        dummy_return = SFTPAttributes()
        dummy_return.st_size = nfs_stat_response['size']
        dummy_return.st_uid = nfs_stat_response['uid']
        dummy_return.st_gid = nfs_stat_response['gid']
        dummy_return.st_mode = nfs_stat_response['mode']
        dummy_return.st_atime = nfs_stat_response['atime']['sec'] + nfs_stat_response['atime']['nsec']/1000000000
        dummy_return.st_mtime = nfs_stat_response['mtime']['sec'] + nfs_stat_response['mtime']['nsec']/1000000000
        return dummy_return

    def _response(self, request_number, t, *args):
        msg = Message()
        msg.add_int(request_number)
        for item in args:
            # NOTE: this is a very silly tiny class used for SFTPFile mostly
            if isinstance(item, int64):
                msg.add_int64(item)
            elif isinstance(item, int):
                msg.add_int(item)
            elif isinstance(item, (str, bytes)):
                msg.add_string(item)
            elif type(item) is SFTPAttributes:
                item._pack(msg)
            else:
                raise Exception(
                    "unknown type for {!r} type {!r}".format(item, type(item))
                )
        self._send_packet(t, msg)

    def _send_handle_response(self, request_number, handle, folder=False):
        if not issubclass(type(handle), SFTPHandle):
            # must be error code
            self._send_status(request_number, handle)
            return
        handle._set_name(b("hx{:d}".format(self.next_handle)))
        self.next_handle += 1
        if folder:
            self.folder_table[handle._get_name()] = handle
        else:
            self.file_table[handle._get_name()] = handle
        self._response(request_number, CMD_HANDLE, handle._get_name())

    def _send_status(self, request_number, code, desc=None):
        if desc is None:
            try:
                desc = SFTP_DESC[code]
            except IndexError:
                desc = "Unknown"
        # some clients expect a "language" tag at the end
        # (but don't mind it being blank)
        self._response(request_number, CMD_STATUS, code, desc, "")

    # Need to handle this case later!
    def _open_folder(self, request_number, path):
        resp = self.server.list_folder(path)
        if issubclass(type(resp), list):
            # got an actual list of filenames in the folder
            folder = SFTPHandle()
            folder._set_files(resp)
            self._send_handle_response(request_number, folder, True)
            return
        # must be an error code
        self._send_status(request_number, resp)

    def _read_folder(self, request_number, folder):
        flist = folder._get_next_files()
        if len(flist) == 0:
            self._log(DEBUG, "length of flist is now 0")
            self._send_status(request_number, SFTP_EOF)
            return
        msg = Message()
        msg.add_int(request_number)
        msg.add_int(len(flist))
        # nfs_list_response = self.nfs.listdir('.')
        # self._log(DEBUG, "Read folder response from NFS is {!r}".format(nfs_list_response))
        self._log(DEBUG, "Read folder response from SFTP is {!r}".format(flist))
        for attr in flist:
            self._log(DEBUG, "file name is {!r}".format(attr.filename))
            msg.add_string(attr.filename)
            msg.add_string(attr)
            attr._pack(msg)
        self._send_packet(CMD_NAME, msg)

    def _read_nfs_folder(self, request_number):
        nfs_list_response = self.nfs.listdir(self.nfs_path)
        if self.previous_list_response == nfs_list_response:
            self.previous_list_response = None
            self._log(DEBUG, "Response same as previous. Terminate!")
            self._send_status(request_number, SFTP_EOF)
            return
            
        self.previous_list_response = nfs_list_response

        self._log(DEBUG, "List folder response from NFS is {!r}".format(nfs_list_response))
        self._log(DEBUG, "List folder response length from NFS is {!r}".format(len(nfs_list_response)))
        msg = Message()
        msg.add_int(request_number)
        msg.add_int(len(nfs_list_response))
        for filename in nfs_list_response:
            self._log(DEBUG, "file name is {!r}".format(filename))
            msg.add_string(filename)
            nfs_stat_response = self.nfs.stat(self.nfs_path+'/'+filename)
            attr = self._set_sftp_attributes(nfs_stat_response)
            msg.add_string(attr)
            attr._pack(msg)
        self._send_packet(CMD_NAME, msg)

    def _delete_cache_entries(self, cache_entries_to_delete):
        for start_offset in cache_entries_to_delete:
            del self.cache[start_offset]
            del self.cache_offsets[start_offset]

    def _flush_to_nfs(self, write_offset, data=None):

        self.nfs_open_handle.seek(write_offset, os.SEEK_SET)

        write_length = 0
        if data is None:
            # Flushing cache at the end of all ops
            self.nfs_open_handle.write(self.cache[write_offset])
            write_length = len(self.cache[write_offset])
            # self._log(DEBUG, "Eviction offset is {!r}".format(write_offset))
            # self._log(DEBUG, "Cache eviction length is {!r}".format(write_length))
            del self.cache[write_offset]
            del self.cache_offsets[write_offset]
        else:
            # Dont need to clean cache up anymore
            # self._clean_cache_up(write_offset, len(data))
            # self._log(DEBUG, "Write offset is {!r}".format(write_offset))
            self.nfs_open_handle.write(data)
            write_length = len(data)
        
        # self._log(DEBUG, "Length of Data to be written is {!r}".format(write_length))
        if write_length in self.write_size_dict:
            self.write_size_dict[write_length] += 1
        else:
            self.write_size_dict[write_length] = 1

    
    def _write_to_cache(self, write_offset, data):
        # NOTE: Do not really need cache_offsets. Can be computed 
        # through data and start_offsets.
        # Check if offset can be added to existing cache

        # Coalescing writes here
        overlapping_offsets = 0
        is_cached = False
        cache_offsets_to_clean = []
        for start_offset in self.cache.keys():
            end_offset = self.cache_offsets[start_offset]
            end_write_offset = write_offset + len(data)
            if write_offset >= start_offset and end_write_offset <= end_offset:
                # New write is contained within a cache entry
                old_entry = self.cache[start_offset]
                updated_entry = old_entry[:(write_offset-start_offset)] + data + old_entry[(end_write_offset-start_offset):]
                self.cache[start_offset] = updated_entry
                overlapping_offsets += 1
                is_cached = True
                # We are done with all modifications here
                return overlapping_offsets, is_cached
            elif start_offset >= write_offset and end_offset <= end_write_offset:
                # Get rid of all cache entries contained in the write
                cache_offsets_to_clean.append(start_offset)
                overlapping_offsets += 1
            elif start_offset < write_offset and end_offset >= write_offset and end_offset <= end_write_offset:
                # Modify write data to include old cached values
                # Modify starting point of write 
                data = self.cache[start_offset][:(write_offset-start_offset)] + data
                write_offset = start_offset
                # Clean up old entry
                cache_offsets_to_clean.append(start_offset)
                overlapping_offsets += 1
            elif start_offset >= write_offset and start_offset <= end_write_offset and end_offset > end_write_offset:
                # Modify write data to include old cached values
                # No need to modify write_offset, the increase in the length of data
                # takes care of it 
                data = data + self.cache[start_offset][(end_write_offset-start_offset):]
                # Clean up old entry
                cache_offsets_to_clean.append(start_offset)
                overlapping_offsets += 1
            # else:
            #     # This is the case where we normally create a new cache entry
            #     print("This should not happen!")
        
        self._delete_cache_entries(cache_offsets_to_clean)

        # Start a new cache entry/flush if entry is big
        if len(data) >= 64*1024:
            self._flush_to_nfs(write_offset, data)
        else:
            self.cache[write_offset] = bytearray(data)
            self.cache_offsets[write_offset] = len(data)+write_offset
            is_cached = True
        
        return overlapping_offsets, is_cached
        

    def _replace_read_data(self, read_offset, read_length, read_data):
        overlapping_entries = 0
        for start_offset in self.cache.keys():
            end_read_offset = read_offset + read_length
            end_offset = self.cache_offsets[start_offset]
            if (read_offset <= start_offset and start_offset < read_offset + read_length):
                if (end_offset >= end_read_offset):
                    read_data = (read_data[:(start_offset-read_offset)] + self.cache[start_offset])[:(end_read_offset-start_offset)]
                else:
                    read_data = read_data[:(start_offset-read_offset)] + self.cache[start_offset] + read_data[(end_offset-read_offset):]
                overlapping_entries += 1
            elif (start_offset < read_offset and end_offset > read_offset):
                if end_offset <= end_read_offset:
                    read_data = self.cache[start_offset][(read_offset-start_offset):] + read_data[(end_offset-read_offset):]
                else:
                    read_data = self.cache[start_offset][(read_offset-start_offset):(read_offset-start_offset)+read_length]
                overlapping_entries += 1
        return bytes(read_data), overlapping_entries
 
    # def _check_flush_required(self, offset, length):
    #     offsets_to_flush = []
        
    #     for start_offset in self.cache.keys():
    #         if (offset >= start_offset and offset < self.cache_offsets[start_offset]) or \
    #             (offset + length >= start_offset and offset + length < self.cache_offsets[start_offset]) or \
    #             (offset <= start_offset and offset + length >= self.cache_offsets[start_offset]):
    #             offsets_to_flush.append(start_offset)
    #     for start_offset in offsets_to_flush:    
    #         self._flush_to_nfs(start_offset)

    def _check_file(self, request_number, msg):
        # this extension actually comes from v6 protocol, but since it's an
        # extension, i feel like we can reasonably support it backported.
        # it's very useful for verifying uploaded files or checking for
        # rsync-like differences between local and remote files.
        handle = msg.get_binary()
        alg_list = msg.get_list()
        start = msg.get_int64()
        length = msg.get_int64()
        block_size = msg.get_int()
        if handle not in self.file_table:
            self._send_status(
                request_number, SFTP_BAD_MESSAGE, "Invalid handle"
            )
            return
        f = self.file_table[handle]
        for x in alg_list:
            if x in _hash_class:
                algname = x
                alg = _hash_class[x]
                break
        else:
            self._send_status(
                request_number, SFTP_FAILURE, "No supported hash types found"
            )
            return
        if length == 0:
            st = f.stat()
            if not issubclass(type(st), SFTPAttributes):
                self._send_status(request_number, st, "Unable to stat file")
                return
            length = st.st_size - start
        if block_size == 0:
            block_size = length
        if block_size < 256:
            self._send_status(
                request_number, SFTP_FAILURE, "Block size too small"
            )
            return

        sum_out = bytes()
        offset = start
        while offset < start + length:
            blocklen = min(block_size, start + length - offset)
            # don't try to read more than about 64KB at a time
            chunklen = min(blocklen, 65536)
            count = 0
            hash_obj = alg()
            while count < blocklen:
                data = f.read(offset, chunklen)
                if not isinstance(data, bytes):
                    self._send_status(
                        request_number, data, "Unable to hash file"
                    )
                    return
                hash_obj.update(data)
                count += len(data)
                offset += count
            sum_out += hash_obj.digest()

        msg = Message()
        msg.add_int(request_number)
        msg.add_string("check-file")
        msg.add_string(algname)
        msg.add_bytes(sum_out)
        self._send_packet(CMD_EXTENDED_REPLY, msg)

    def _convert_pflags(self, pflags):
        """convert SFTP-style open() flags to Python's os.open() flags"""
        if (pflags & SFTP_FLAG_READ) and (pflags & SFTP_FLAG_WRITE):
            flags = os.O_RDWR
        elif pflags & SFTP_FLAG_WRITE:
            flags = os.O_WRONLY
        else:
            flags = os.O_RDONLY
        if pflags & SFTP_FLAG_APPEND:
            flags |= os.O_APPEND
        if pflags & SFTP_FLAG_CREATE:
            flags |= os.O_CREAT
        if pflags & SFTP_FLAG_TRUNC:
            flags |= os.O_TRUNC
        if pflags & SFTP_FLAG_EXCL:
            flags |= os.O_EXCL
        return flags

    def _process(self, t, request_number, msg):
        # self._log(DEBUG, "Request: {}".format(CMD_NAMES[t]))
        if t == CMD_OPEN:
            path = msg.get_text()
            flags = self._convert_pflags(msg.get_int())
            attr = SFTPAttributes._from_msg(msg)
            self._log(DEBUG, "SFTP attributes open path are {!r}".format(attr))
            dummyHandle = SFTPHandle(flags=flags)
            self.nfs_path_to_open = path
            self.write_size_dict = {}
            self._log(DEBUG, "Open path is {!r}".format(path))
            try:
                self.nfs_open_handle = self.nfs.open(path, mode='rb+',codec=None)
            except:
                self.nfs_open_handle = self.nfs.open(path, mode='wb+')
            
            # self._log(DEBUG, "Opened nfs handle: {}".format(self.nfs_open_handle))
            # self._log(DEBUG, "Open path is {!r}".format(path))
            self._send_handle_response(
                request_number, dummyHandle)

            # self._send_handle_response(
            #     request_number, self.server.open(path, flags, attr)
            # )
        elif t == CMD_CLOSE:
            handle = msg.get_binary()
            # self.cache_test_file.close()
            if self.nfs_open_handle is not None:
                start = time.time()
                offset_list = []
                for start_offset in self.cache.keys():
                    offset_list.append(start_offset)
                for start_offset in offset_list:
                    self._flush_to_nfs(start_offset)
                end = time.time()
                self._log(DEBUG, "time to flush cache of size: "+str(len(offset_list))+" was "+str(end-start))
                # with open("/home/nutanix/sahil/plot_data/data_"+str(self.fname)+".txt", "a+") as f:
                #     for k, v in self.write_size_dict.items():
                #         f.write('%s:%s\n' % (k, v))
                # self.file_counter += 1    
                # self._log(DEBUG, "Closing NFS handle {!r}".format(self.nfs_open_handle))
                self.nfs_open_handle.close()
                self.nfs_open_handle = None
                # self.cache_debug_file_handle.close()
                # self.cache_write_time_file_handle.close()
                # self.cache_read_time_file_handle.close()
            if handle in self.folder_table:
                del self.folder_table[handle]
                self._send_status(request_number, SFTP_OK)
                return
            if handle in self.file_table:
                self.file_table[handle].close()
                del self.file_table[handle]
                self._send_status(request_number, SFTP_OK)
                return
            self._send_status(
                request_number, SFTP_BAD_MESSAGE, "Invalid handle"
            )
        elif t == CMD_READ:
            handle = msg.get_binary()
            offset = msg.get_int64()
            length = msg.get_int()
            # self._log(DEBUG, "Read offset is {!r}".format(offset))
            # self._log(DEBUG, "Read length is {!r}".format(length))
            if handle not in self.file_table:
                self._send_status(
                    request_number, SFTP_BAD_MESSAGE, "Invalid handle"
                )
                return
            #data = self.file_table[handle].read(offset, length)

            # Create a file for the test bench
            # self.test_file.write("read,"+str(offset)+","+str(length)+"\n")
            start = time.time()

            self.nfs_open_handle.seek(offset, os.SEEK_SET)
            data = self.nfs_open_handle.read(length)

            data, overlap = self._replace_read_data(offset, length, data)

            end = time.time()

            # self.cache_read_time_file_handle.write("time:"+str((end-start)*1000000)+",cache_size:"+str(len(self.cache))+",overlapping_entries:"+str(overlap)+"\n")
            # self._log(DEBUG, "Read data is {!r}".format(data.decode("utf-8")))

            if isinstance(data, (bytes, str)):
                if len(data) == 0:
                    self._send_status(request_number, SFTP_EOF)
                else:
                    self._response(request_number, CMD_DATA, data)
            else:
                self._send_status(request_number, data)
        elif t == CMD_WRITE:
            handle = msg.get_binary()
            offset = msg.get_int64()
            data = msg.get_binary()
            # Create a file for the test bench
            # self.test_file.write("write,"+str(offset)+","+str(len(data))+"\n")
            # if len(data) == 4:
            #     # Currently we assume that 4B writes don't flow into one another
            #     self._write_to_cache(offset, bytearray(data))
            # else:
            #     self._flush_to_nfs(offset, bytearray(data))
            #self.nfs_open_handle.flush()

            # Just keep the write to cache.
            # It will handle which writes to forward and which to cache
            # self.cache_test_file.write(str(len(data))+"\n")

            start = time.time()

            overlap, is_cached = self._write_to_cache(offset, data)
            
            if handle not in self.file_table:
                self._send_status(
                    request_number, SFTP_BAD_MESSAGE, "Invalid handle"
                )
                return
            self._send_status(
                request_number, SFTP_OK
            )
            end = time.time()
            # self.cache_write_time_file_handle.write("time:"+str((end-start)*1000000)+",cache_size:"+str(len(self.cache))+\
                # ",overlapping_entries:"+str(overlap)+",is_cached"+str(is_cached)+"\n")
            # self._send_status(
            #     request_number, self.file_table[handle].write(offset, data)
            # )
        elif t == CMD_REMOVE:
            path = msg.get_text()
            self._send_status(request_number, self.server.remove(path))
        elif t == CMD_RENAME:
            oldpath = msg.get_text()
            newpath = msg.get_text()
            self._send_status(
                request_number, self.server.rename(oldpath, newpath)
            )
        elif t == CMD_MKDIR:
            path = msg.get_text()
            attr = SFTPAttributes._from_msg(msg)
            self._send_status(request_number, self.server.mkdir(path, attr))
        elif t == CMD_RMDIR:
            path = msg.get_text()
            self._send_status(request_number, self.server.rmdir(path))
        elif t == CMD_OPENDIR:
            # Need to figure out flow if SFTP commands reach here
            # No equivalent for opening dir in NFS.
            #path = msg.get_text()
            #self.nfs_path_to_list = msg.get_text()
            # Always open same dummy path
            self._open_folder(request_number, '.')
            return
        elif t == CMD_READDIR:
            handle = msg.get_binary()
            if handle not in self.folder_table:
                self._send_status(
                    request_number, SFTP_BAD_MESSAGE, "Invalid handle"
                )
                return
            folder = self.folder_table[handle]

            # Perform a nfs_ls and return the results
            self._log(DEBUG, "Request number is {!r}".format(request_number))
            self._read_nfs_folder(request_number)

            # self._read_folder(request_number, folder)
        elif t == CMD_STAT:
            path = msg.get_text()

            # resp = self.server.stat(path)
            self._log(DEBUG, "Stat path is {!r}".format(path))
            # self._log(DEBUG, "SFTP Stat response is {!r}".format(resp))

            # We set up nfs client here. The path to be picked and the first container to be mounted
            # needs to be changed. We can do it in Realpath or in any other function!
            
            nfs_stat_response = self.nfs.stat(path)
            
            self._log(DEBUG, "NFS Stat response is {!r}".format(nfs_stat_response))
            
            # NFS stat response type is a dict
            #self._log(DEBUG, "NFS Stat response type is {!r}".format(type(nfs_stat_response))) 
            
            # Debug NFS stat response fields
            #self._log(DEBUG, "NFS Stat response size is {!r}".format(nfs_stat_response['blksize']))

            # Debug SFTP stat response fields
            # self._log(DEBUG, "SFTP Stat response atime is {!r}".format(resp.st_atime))
            # self._log(DEBUG, "SFTP Stat response atime type is {!r}".format(type(resp.st_atime)))


            nfs_stat_return = self._set_sftp_attributes(nfs_stat_response)

            # self._log(DEBUG, "Dummy SFTP Stat response is {!r}".format(nfs_stat_return))
            self._response(request_number, CMD_ATTRS, nfs_stat_return)
            
            # if issubclass(type(resp), SFTPAttributes):
            #     self._response(request_number, CMD_ATTRS, resp)
            # else:
            #     self._send_status(request_number, resp)
        elif t == CMD_LSTAT:
            path = msg.get_text()
            self._log(DEBUG, "lstat path is {!r}".format(path))
            # resp = self.server.lstat(path)
            nfs_lstat_response = self.nfs.lstat(path)
            self._log(DEBUG, "NFS Stat response is {!r}".format(nfs_lstat_response))

            nfs_lstat_return = self._set_sftp_attributes(nfs_lstat_response)

            self._response(request_number, CMD_ATTRS, nfs_lstat_return)
            
            # if issubclass(type(resp), SFTPAttributes):
            #     self._response(request_number, CMD_ATTRS, resp)
            # else:
            #     self._send_status(request_number, resp)
        elif t == CMD_FSTAT:
            handle = msg.get_binary()
            if handle not in self.file_table:
                self._send_status(
                    request_number, SFTP_BAD_MESSAGE, "Invalid handle"
                )
                return
            nfs_fstat_response = self.nfs_open_handle.fstat()
            nfs_fstat_return = self._set_sftp_attributes(nfs_fstat_response)
            
            self._response(request_number, CMD_ATTRS, nfs_fstat_return)
            # resp = self.file_table[handle].stat()
            
            # if issubclass(type(resp), SFTPAttributes):
            #     self._response(request_number, CMD_ATTRS, resp)
            # else:
            #     self._send_status(request_number, resp)
        elif t == CMD_SETSTAT:
            path = msg.get_text()
            attr = SFTPAttributes._from_msg(msg)
            self._send_status(request_number, self.server.chattr(path, attr))
        elif t == CMD_FSETSTAT:
            handle = msg.get_binary()
            attr = SFTPAttributes._from_msg(msg)
            if handle not in self.file_table:
                self._response(
                    request_number, SFTP_BAD_MESSAGE, "Invalid handle"
                )
                return
            self._send_status(
                request_number, self.file_table[handle].chattr(attr)
            )
        elif t == CMD_READLINK:
            path = msg.get_text()
            resp = self.server.readlink(path)
            if isinstance(resp, (bytes, str)):
                self._response(
                    request_number, CMD_NAME, 1, resp, "", SFTPAttributes()
                )
            else:
                self._send_status(request_number, resp)
        elif t == CMD_SYMLINK:
            # the sftp 2 draft is incorrect here!
            # path always follows target_path
            target_path = msg.get_text()
            path = msg.get_text()
            self._send_status(
                request_number, self.server.symlink(target_path, path)
            )
        elif t == CMD_REALPATH:
            path = msg.get_text()
            rpath = self.server.canonicalize(path)
            self._log(DEBUG, "Real path is {!r}".format(rpath))
            
            # Happens on the first call
            if self.nfs == None:
                self.nfs = libnfs.NFS('nfs://10.45.129.164/default-container-14151218230332/')
            self.nfs_path = rpath

            self._response(
                request_number, CMD_NAME, 1, rpath, "", SFTPAttributes()
            )
        elif t == CMD_EXTENDED:
            tag = msg.get_text()
            if tag == "check-file":
                self._check_file(request_number, msg)
            elif tag == "posix-rename@openssh.com":
                oldpath = msg.get_text()
                newpath = msg.get_text()
                self._send_status(
                    request_number, self.server.posix_rename(oldpath, newpath)
                )
            else:
                self._send_status(request_number, SFTP_OP_UNSUPPORTED)
        else:
            self._send_status(request_number, SFTP_OP_UNSUPPORTED)


from paramiko.sftp_handle import SFTPHandle