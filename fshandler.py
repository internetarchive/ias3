"""

    Internet archive S3 web connector.
    Copyright 2008-2010 Internet Archive.

    Parts of this are derived from:
    Python WebDAV Server.
    Copyright (C) 1999 Christian Scholz (ruebe@aachen.heimat.de)

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public
    License along with this library; if not, write to the Free
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""

import cgi
import os
import shutil
import re
import sys
import time
import tempfile
import urlparse
import urllib
import xml.etree.ElementTree
import email.parser
import socket
import mimetypes
import hashlib

from string import joinfields, split, lower

#from DAV.constants import COLLECTION, OBJECT
#from DAV.errors import *
#from DAV.s3errors import *
#from DAV.iface import *

# bellow line can go
#from DAV.davcmd import copyone, copytree, moveone, movetree, delone, deltree
from s3errors import *
import s3path
import s3server

class FilesystemHandler():
    """ 
        Store S3 buckets and keys in a simple flat directory structure
    """
    def _log_internal(self, message):
        if self.verbose:
            print >>sys.stderr, '>> (FilesystemHandler) %s' % message


    def __init__(self, directory, uri, log_function=_log_internal, verbose=False):
        self.setDirectory(directory)
        self.setBaseURI(uri)

        self.verbose = verbose
        self._log = log_function
        self.internal_file_extensions = (
            '_meta.txt',
            '_head',
            '_temp',
            '_owner',
            '_files.xml',
            '_meta.xml',
        )


    def setDirectory(self, path):
        """ Sets the directory """
        if not os.path.isdir(path):
            raise Exception, '%s not must be a directory!' % path
        
        self.directory = path


    def setBaseURI(self, uri):
        """ Sets the base uri """

        self.baseuri = uri


    def id_to_filename(self, id):
        """take any s3 bucket or key and make it into a safe directory or filename"""
        s = urllib.quote(id, ' !@#$^&*()={}[]":;<>,?|~')
        if s == '.':
            s = '%2E'
        elif s == '..':
            s = '%2E%2E'
        for e in self.internal_file_extensions:
            if re.search(re.escape(e) + '_*$', s):
                s = s + '_'
                break
        return s

    def filename_to_id(self, id):
        """convert filename back to id"""
        s = urllib.unquote(id)
        for e in self.internal_file_extensions:
            if re.search(re.escape(e) + '_+$', s):
                s = s[:-1]
                break
        return s

    def bucket_to_path(self, bucket):
        """ Convert a bare bucket name to a bucket pathname"""
        bucket = self.id_to_filename(bucket)
        fullpath = os.path.join(self.directory, bucket)
        return fullpath

    def bucket_key_to_path(self, bucket, key):
        """ Convert a bare bucket name to a bucket pathname"""
        bucket = self.bucket_to_path(bucket)
        if (bucket == None):
            return None
        key = self.id_to_filename(key)
        fullpath = os.path.join(bucket, key)
        return fullpath

    def bucket_is_local(self, bucket):
        try:
            FilesystemHandler.assert_bucket_exists(self, bucket)
        except S3_Error:
            return False
        return True

    def get_bucket_host(self, bucket):
        self.assert_bucket_exists(bucket)
        return "%s:%d" % (socket.gethostname(), s3path.s3path().port)

    def assert_bucket_exists(self, bucket):
        path = self.bucket_to_path(bucket)
        if (path == None) or (not os.path.exists(path)):
            raise S3_Error("NoSuchBucket", bucket)
            return False
        return True

    def assert_bucket_key_exists(self, bucket, key):
        if (key == None or key == ''):
            raise S3_Error("NoSuchKey", bucket + '/' + key)
            return False
        path = self.bucket_key_to_path(bucket, key)
        if (path == None) or (not os.path.exists(path)):
            raise S3_Error("NoSuchKey", bucket + '/' + key)
            return False
        return True

    def pp(self, o):
        """quick and easy debug print """
        import pprint
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(o)

    def is_internal_file(self, f):
        """ returns true if a file is an internal bookeeping filename """
        for ext in self.internal_file_extensions:
            if  f.endswith(ext):
                return True
        return False

    def get_entries(self, dir, files_only=False):
        """ directory lister for buckets and keys """

        root = self.directory
        if dir:
            root = dir
        entries = []
        try:
            all_entries = os.listdir(root)
        except OSError:
            raise S3_ListEntriesError
        for e in all_entries:
            if self.is_internal_file(e):
                continue
            full_path = os.path.join(root, e)
            if not os.access(full_path, os.R_OK):
                continue
            if files_only and (not os.path.isfile(full_path)):
                continue
            entries.append(self.filename_to_id(e))
        return entries


    def get_bucket_list(self, accesskey):
        """return a list of buckets at the endpoint"""
        return self.get_entries(None)


    def get_key_list(self, bucket):
        """list the keys in a bucket"""
        try:
            return self.get_entries(self.bucket_to_path(bucket), True)
        except S3_ListEntriesError:
            raise S3_Error("NoSuchBucket")


    def get_bucket_owner(self, bucket):
        """ returns the bucket owner """
        path = os.path.join(self.id_to_filename(bucket), '_owner')
        if not os.isfile(path):
            return "nobody"
        f = open("r", path)
        owner = f.read()
        f.close()
        owner = owner.rstrip("\n")
        return owner


    def assert_can_write_to_bucket(self, accesskey, bucket):
        """ returns true, or raises an access exception if not allowed """
        owner = self.get_bucket_owner(bucket)
        if owner == accesskey:
            return True
        raise S3_Error("AccessDenied", "Only the bucket owner can write to the bucket.")


    def set_bucket_owner(self, bucket, owner):
        """ returns the bucket owner """
        path = os.path.join(self.id_to_filename(bucket), '_owner')
        f = open("w", path)
        owner = f.write(owner)
        f.close()
        
        
    def is_roundtripable_header(self, h):
        header_patterns = (
            '^content-type',
            '^content-disposition',
            '^etag',
            '^x-amz',
            '^x-',
        )
        for p in header_patterns:
            if re.search(p, h, re.IGNORECASE):
                return True
        return False


    def get_head(self, bucket, key):
        headers = {}
        if key:
            self.assert_bucket_key_exists(bucket, key)
            key_file = self.bucket_key_to_path(bucket, key)
            hf = key_file + "_meta.txt"
            if os.path.exists(hf):
                f = open(hf, "r")
                hp = email.parser.HeaderParser()
                headerobj = hp.parse(f)
                for h, v in headerobj.items():
                   if self.is_roundtripable_header(h):
                       headers[h] = v
            else:
                if not mimetypes.inited:
                    mimetypes.init()
                (type, encoding) = mimetypes.guess_type(key_file)
                if type:
                    headers['content-type'] = type
                headers['content-length'] = "%d" % self.get_size(bucket, key)
                headers['ETag'] = self.get_md5(bucket, key)
        return headers
 

    def get_data(self, bucket, key):
        """ return the content of an object """
        self.assert_bucket_key_exists(bucket, key)
        path=self.bucket_key_to_path(bucket, key)
        s=os.stat(path)
        size=s[6]
        fp=open(path,"r")
        f_iter = s3server.file_iter(fp, size)
        self._log('Serving content of %s' % path)
        return f_iter


    def get_mtime(self, bucket, key):
        """ return the last modified date of the object """
        self.assert_bucket_key_exists(bucket, key)
        path=self.bucket_key_to_path(bucket, key)
        s=os.stat(path)
        date=s[8]
        return date


    def get_size(self, bucket, key):
        """ return the size of a key """
        self.assert_bucket_key_exists(bucket, key)
        path=self.bucket_key_to_path(bucket, key)
        s=os.stat(path)
        size=s[6]
        return size

    def get_md5(self, bucket, key):
        """ return the md5 of a key """
        self.assert_bucket_key_exists(bucket, key)
        path=self.bucket_key_to_path(bucket, key)
        m = hashlib.md5()
        f=open(path, "r")
        while True:
            b=f.read(4096)
            if not b:
                break
            m.update(b)
        f.close()
        return m.hexdigest()
           
    def put_head(self, bucket, key, header):
        """ utility function to safe the header metadata """
        self.assert_bucket_exists(bucket)
        key = self.bucket_key_to_path(bucket, key)
        if key:
            f = open(key + "_meta.txt", "w")
            head = self.head_data(header)
            f.write(head)
            f.close()

    def get_owner_accesskey(self, bucket, key):
        path = self.bucket_to_path(bucket)
        f = os.path.join(path, '_owner')
        if not os.path.isfile(f):
            return None
        o = open(f, 'r')
        owner = o.read()
        o.close()
        return owner.rstrip("\n")
        
    def head_data(self, header):
        """ return a string with the headders for storage
            we strip out cookie headers because they can be used
            to steal sessions """

        head = ''
        for k in sorted(header.keys()):
            v = header[k]
            if re.search("^cookie", k, re.IGNORECASE):
                continue
            if re.search("^authorization", k, re.IGNORECASE):
                (access, sep, secret) = v.partition(':')
                v = access + ':REDACTED_BY_IA_S3'
            head = head + k + ': ' + v + "\n"
        if 'date' not in header and 'x-amz-date' not in header :
            head = head + 'x-upload-date: ' + time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()) + "\n"
        return head
        
    def put_key(self,bucket, key,filehandle,header,accesskey,queue_derive,keep_old_version):
        """ Store a key on disk """
        self.assert_bucket_exists(bucket)
        path=self.bucket_key_to_path(bucket, key)
        # put temp files in the bucket
        tempdir=self.bucket_to_path(bucket)
        try:
            (descriptor, temp) = tempfile.mkstemp('_temp', '', tempdir)
            fp=os.fdopen(descriptor, 'w+')
            buffer = ''
            chunk = 32768
            copied = 0
            size = atoi(self.headers['content-length'])
            md5_hash = hashlib.md5()
            while (copied < size and buffer != None):
                toread = min(chunk, (size - copied))
                buffer = filehandle.read(toread)
                md5_hash.update(buffer)
                fp.write(buffer)
                copied = copied + toread
            fp.close()
            header['ETag'] = md5_hash.hexdigest()
            self.put_head(bucket, key, header)
            os.rename(temp, path)
            self._log('put: Created %s' % path)
        except OSError:
            self._log('put: Could not create %s' % path)
            raise S3_Error
        return md5_hash.hexdigest()


    def put_bucket(self,bucket,data,header,accesskey,error_on_preexisting):
        path=self.bucket_to_path(bucket)
        if os.path.isdir(path):
            if error_on_preexisting:
                raise S3_Error(400)
            else:
                return None
        try:
            os.mkdir(path)
            o = open(os.path.join(path, '_owner'), 'w')
            o.write(accesskey + "\n")
            o.close()
        except OSError:
            self._log('put: Could not create %s' % uri)
            raise S3_Error
        return None

  
    def delkey(self, bucket, key, accesskey, cascade,keep_old_version):
        """delete a key from the s3 storage"""
        self.assert_bucket_key_exists(bucket, key)

        path=self.bucket_key_to_path(bucket, key)

        if path and os.path.exists(path):
            os.remove(path)
            head_file = path + '_meta.txt'
            if os.path.exists(head_file):
                os.remove(head_file)
            return 204
        else:
            self._log('put: Could not DELETe %s' % path)
            raise S3_Error # forbidden

        
    def delbucket(self, bucket, accesskey):
        """delete a bucket from the s3 storage"""
        bucket=self.bucket_to_path(bucket)
        if bucket and bucket != '' and os.path.isdir(bucket):
            #print "os.shutil.rmtree: " + bucket
            shutil.rmtree(bucket)
            return 204
        else:
            self._log('put: Could not DELETe %s' % bucket)
            raise S3_Error('AccessDenied')
