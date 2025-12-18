import os
import sys
from argparse import ArgumentParser
import asyncio
import stat
import logging
import errno

import multiprocessing
import time

import pyfuse3
import pyfuse3.asyncio
import dns.resolver

try:
    import faulthandler
except ImportError:
    pass
else:
    faulthandler.enable()

log = logging.getLogger(__name__)
pyfuse3.asyncio.enable()

class TestFs(pyfuse3.Operations):
    def __init__(self, record_type):
        super(TestFs, self).__init__()

        self.supports_dot_lookup = False
        self.enable_writeback_cache = False

        self.name_inode = {}
        self.inode_name = {}
        self.query_answers = {}
        self.record_type = record_type

    def get_query(self, name):
        query = dns.message.make_query(name.decode("utf-8"), self.record_type)
        response = dns.query.tcp(query, "9.9.9.9")
        wire_bytes = response.to_wire()
        self.query_answers[name] = wire_bytes
        return wire_bytes

    async def getattr(self, inode, ctx=None, ttl=0):
        entry = pyfuse3.EntryAttributes()
        if inode in self.inode_name and self.inode_name[inode][-1] == 0x2E: # Dot
            try:
                wire_bytes = self.get_query(self.inode_name[inode])
            except:
                raise pyfuse3.FUSEError(errno.ENOENT)
            entry.st_mode = (stat.S_IFREG | 0o444)
            entry.st_size = len(wire_bytes)
        elif inode == pyfuse3.ROOT_INODE or inode in self.inode_name:
            entry.st_mode = (stat.S_IFDIR | 0o777)
            entry.st_size = 0
        else:
            entry.st_mode = (stat.S_IFREG | 0o444)
            entry.st_size = 0

        stamp = (int(time.time()) + ttl) * 1e9
        entry.st_atime_ns = stamp
        entry.st_ctime_ns = stamp
        entry.st_mtime_ns = stamp
        entry.st_gid = os.getgid()
        entry.st_uid = os.getuid()
        entry.st_ino = inode

        return entry

    async def lookup(self, parent_inode, name, ctx=None):
        if parent_inode != pyfuse3.ROOT_INODE: # and parent_inode not in self.inode_name:
            raise pyfuse3.FUSEError(errno.ENOENT)

        if not name in self.name_inode:
            new_inode = pyfuse3.ROOT_INODE + len(self.name_inode) + 1
            print(name)
            self.name_inode[name] = new_inode
            self.inode_name[new_inode] = name

        return await self.getattr(self.name_inode[name])

    async def access(self, inode, mode, ctx):
        return True

    async def opendir(self, inode, ctx):
        if inode != pyfuse3.ROOT_INODE and inode not in self.inode_name:
            raise pyfuse3.FUSEError(errno.ENOENT)
        return inode

    async def releasedir(self, inode):
        return

    async def forget(self, inode_list):
        return

    async def readdir(self, fh, start_id, token):
        if fh == pyfuse3.ROOT_INODE:
            return

        name = self.inode_name[fh]

        try:
            answers = dns.resolver.resolve(name.decode("utf-8"), self.record_type)
        except:
            answers = []

        if start_id == 0:
            for i, rdata in enumerate(list(answers)):
                pyfuse3.readdir_reply(
                    token, rdata.to_text().replace("/", "／").encode("utf-8"), await self.getattr(2048 + i + 1, ttl=answers.rrset.ttl), 2048 + i + 1)
        return

    async def setxattr(self, inode, name, value, ctx):
        raise pyfuse3.FUSEError(errno.ENOTSUP)

    async def open(self, inode, flags, ctx):
        if flags & os.O_RDWR or flags & os.O_WRONLY:
            raise pyfuse3.FUSEError(errno.EACCES)
        if inode in self.inode_name:
            file_info = pyfuse3.FileInfo(fh=inode, direct_io=True, nonseekable=True)
            return file_info
        raise pyfuse3.FUSEError(errno.EACCES)

    async def read(self, fh, off, size):
        if fh not in self.inode_name:
            raise pyfuse3.FUSEError(errno.EACCES)
        name = self.inode_name[fh]
        try:
            wire_bytes = self.query_answers[name]
        except:
            raise pyfuse3.FUSEError(errno.ENOENT)

        return wire_bytes[off:off+size]

def init_logging(debug=False):
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(threadName)s: '
                                  '[%(name)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    if debug:
        handler.setLevel(logging.DEBUG)
        root_logger.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)
        root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)


def main(record_type="A"):
    init_logging(True)

    path = f"/tmp/dnsfs/{record_type}"
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

    testfs = TestFs(record_type)
    fuse_options = set(pyfuse3.default_options)
    fuse_options.add('allow_other')
    fuse_options.add('fsname=dnsfs')
    fuse_options.add('debug')
    pyfuse3.init(testfs, path, fuse_options)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(pyfuse3.main())
    except:
        pyfuse3.close(unmount=False)
        raise
    finally:
        loop.close()

    pyfuse3.close()


if __name__ == '__main__':
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "PTR"]
    pool = multiprocessing.Pool(len(record_types))
    pool.map(main, record_types)
    pool.join()
