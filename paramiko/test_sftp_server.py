from sftp_server_2 import SFTPServer
import os
from os import urandom


lines = None
server = SFTPServer()
with open("/home/nutanix/sahil/qemu-traces/sftp_full_trace.out", "r") as f:
    lines = f.readlines()
    for line in lines[11:75]:
        split_line = line.split(',')
        mode = split_line[0]
        offset = int(split_line[1])
        length = int(split_line[2])
        if mode == "read":
            if length == 16384:
                continue
            server._replace_read_data(offset, length, bytearray(length))
        else:
            server._write_to_cache(offset, bytearray([1] * length))
            # if length == 4:
            #     server._write_to_cache(offset, urandom(length))
            # else:
            #     server._flush_to_nfs(offset, urandom(length))
print(server.cache.keys())
cache_dict = {}
for data_item in server.cache.values():
    if len(data_item) in cache_dict:
        cache_dict[len(data_item)] += 1
    else:
        cache_dict[len(data_item)] = 1
sorted_write_size_dict = sorted(server.write_size_dict.items(), key=lambda x: x[0])
for entry in cache_dict.items():
    print(entry)

# for write_size_dict_entry in sorted_write_size_dict:
#     print(write_size_dict_entry)
