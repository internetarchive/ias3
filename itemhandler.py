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
import uuid
import os
import shutil
import re
import string
import sys
import subprocess
import time
import tempfile
import urlparse
import urllib
import xml.etree.ElementTree
import email.parser
import hashlib

from string import joinfields, split, lower

from s3errors import *
import fshandler
import s3db
import s3path

class ItemHandler(fshandler.FilesystemHandler):
    """ 
        Store S3 buckets and keys in a simple flat directory structure
    """
           
    def __init__(self, uri, log_function=fshandler.FilesystemHandler._log_internal, verbose=False):
        self.item_dirs = []
        for n in range(0,23):
            self.item_dirs.append('/%d/items' % n)

        fshandler.FilesystemHandler.__init__(self, self.item_dirs[0], uri, log_function, verbose)
        #for writes, should we sidestep contrib-submit, and write directly to the filesystem
        self.use_fs_directly = False
        p = s3path.s3path()
        self.petabox_path = p.petabox
        self.ias3_path = p.s3
        
    def bucket_to_path(self, bucket):
        """ Convert a bare bucket name to a bucket pathname"""
        bucket_pathname = self.id_to_filename(bucket)
        for d in self.item_dirs:
            p = os.path.join(d, bucket_pathname)
            if os.path.exists(p):
                return p
        raise S3_Error("NoSuchBucket", ("%s not found on local filesystem" % bucket))

    def get_bucket_list(self, accesskey):
        """return a list of buckets at the endpoint"""
        db = s3db.s3db()
        return db.get_buckets(accesskey)

    def assert_bucket_exists(self, bucket):
        return self.get_bucket_host(bucket)

    def get_bucket_host(self, bucket):
        try:
            pipe = subprocess.Popen([
                self.petabox_path + "/sw/bin/find_item.php",
                bucket, 
                ], stdout=subprocess.PIPE)
            output = pipe.communicate()[0]
            if not (pipe.wait() == 0):
                raise S3_Error("NoSuchBucket", ("%s not found by find_item.php" % bucket))
        except OSError:
            raise S3_Error
        locate_out =  output.rstrip("\n")
        (host, path) = locate_out.split(':')
        #iaNNNNNN.us.archive.org
        short_hostname = host.split('.')[0]
        domain = host.split('.')[1:]
        new_name = "%s.s3dns.%s:%d" % (short_hostname, '.'.join(domain), s3path.s3path().port)
        return new_name

    def assert_not_overloaded(self, accesskey):
        """ make sure we are under the outstanding task limit 
            limiting is as follows:
            if total put count exceeds hard_limit we return overloaded
            if total put count exceeds soft_limit than we do per user limiting
            if put_count[accesskey] exceeds user_limit then we return overloaded
            """
        hard_limit = 1299
        soft_limit = 999
        user_limit = 29

        db = s3db.s3db()
        (total) = db.get_running_put_counts() 

        if total > hard_limit:
            time.sleep(2)
            raise S3_Error("SlowDown")
            return False

        if total > soft_limit:
            username = db.get_username(accesskey)
            (put_count) = db.get_running_put_count_for_user(username) 

            if (put_count > user_limit):
                time.sleep(2)
                raise S3_Error("SlowDown")
                return False

        return True

    def put_key(self, bucket, key, filehandle, header, accesskey, queue_derive, keep_old_version):
        """ Store a key on disk """
        if self.use_fs_directly:
            return fshandler.FilesystemHandler.put_key(self, bucket, key, filehandle, header, accesskey)

        self.assert_not_overloaded(accesskey)

        db = s3db.s3db()
        username = db.get_username(accesskey)
        if username == None :
            # db broken? by the time we get here
            # access key was already checked by s3server
            raise S3_Error

        #steps:
        # mkdir /tmp/tmp/uploads/s3-UUID-bucket/
        # write /tmp/tmp/uploads/s3-UUID-bucket/key
        # write /tmp/tmp/uploads/s3-UUID-bucket/key_meta.txt
        # run contrib-submit with delete after submitted

        try:
            holdingdir = "/tmp/tmp/uploads/s3-" + str(uuid.uuid4()) + "-" + self.id_to_filename(bucket)
            key_file = holdingdir + "/" + self.id_to_filename(key)
            head_file = key_file + "_meta.txt"
            if not os.path.isdir(holdingdir):
                os.makedirs(holdingdir)
            k = open(key_file, "w")
            buffer = ''
            chunk = 32768
            copied = 0
            size = string.atoi(header['content-length'])
            md5_hash = hashlib.md5()
            while (copied < size and buffer != None):
                toread = min(chunk, (size - copied))
                buffer = filehandle.read(toread)
                md5_hash.update(buffer)
                k.write(buffer)
                copied = copied + toread
            k.close()
            h = open(head_file, "w")
            header['ETag'] = '"' + md5_hash.hexdigest() + '"'
            h.write(self.head_data(header))
            h.close()
            job = [
                self.ias3_path + '/' + "./uploadItem.py", 
                "--deleteAfter", 
                "--priority",
                "-6",
                "-s", username, 
                "--update", 
                "-d", holdingdir, 
                "-i", bucket, 
                "--comment", 
                "s3-put", 
            ]
            if queue_derive:
                job.append("--derive")
            if keep_old_version:
                job.append("--s3-keep-old-version")
            pipe = subprocess.Popen(job, stdout=subprocess.PIPE)
            output = pipe.communicate()[0]
            if pipe.wait() != 0:
                shutil.rmtree(holdingdir, True)
                raise S3_Error("InternalError", "uploadItem.py: " + output)
 
            self._log('put_key: Created %s' % bucket)
            self._log('put_key: called upload_item: %s' % output)
        except OSError:
            self._log('put_key: Could not create %s' % bucket)
            raise S3_Error
        return md5_hash.hexdigest()

    def get_owner_accesskey(self, bucket, key):
        """ ownership from item's meta.xml + db """
        path = self.bucket_to_path(bucket)
        # bucket must be a safe name, with no slashes
        assert(bucket.find('/') == -1)
        meta = xml.etree.ElementTree.parse(os.path.join(path, bucket + '_meta.xml'))
        username = meta.find('uploader').text
        db = s3db.s3db()
        accesskey = db.get_accesskey(username)
        return accesskey
        
    def assert_can_write_to_bucket(self, accesskey, bucket):
        """ returns true, or raises an access exception if not allowed """
        db = s3db.s3db()

        # shortcut if they made the bucket
        if ((accesskey != None) and (accesskey == db.get_bucket_owner_accesskey(bucket))):
            return True

        username = db.get_username(accesskey)
        if username == None:
            # db broken? by the time we get here
            # access key was already checked by s3server
            raise S3_Error

        pipe = subprocess.Popen([
            'php', '-r', 
            'include "/petabox/setup.inc";  print Auth::usernameCanWriteToItem($argv[1], $argv[2]);',
            '--', 
            username,
            bucket,
            ], stdout=subprocess.PIPE)
        output = pipe.communicate()[0]
        if (pipe.wait() != 0):
            raise S3_Error("InternalError", "Auth::usernameCanWriteToItem: " + output)
        if output == '1' or output == '2':
            return True
        raise S3_Error("AccessDenied", "You lack sufficient privilages to write to this item.")

       
    def is_safe_identifier(self, id):
        """ Ask the petabox code if an identifier is legal """
        pipe = subprocess.Popen([
            'php', '-r', 
            'include "/petabox/setup.inc"; print Util::identifierIsLegal($argv[1]);',
            '--', 
            id,
            ], stdout=subprocess.PIPE)
        output = pipe.communicate()[0]
        assert (pipe.wait() == 0)
        if output == '1' :
            return True
        return False

    def xml_add_key_value(self, root, key, value):
        new = xml.etree.ElementTree.SubElement(root, key)
        new.text = value

    def meta_xml_from_header(self, header, identifier, username):
        #these can be overidden except identifier (see loop)
        defaults = {}
        defaults['uploader'] = username
        defaults['mediatype'] = 'data'
        defaults['collection'] = 'opensource'
        defaults['mediatype'] = 'data'
        defaults['title'] = identifier
        defaults['addeddate'] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        defaults['publicdate'] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

        root = xml.etree.ElementTree.Element("metadata")
        self.xml_add_key_value(root, 'identifier', identifier)

        for key in sorted(header.keys()):
            m = re.search('^x-(amz|archive)-meta(\d*)-(?P<meta_key>.+)', key, re.IGNORECASE)
            if m:
                meta_name = m.group('meta_key')
                meta_value = header[key]
                # hack: in meta name turn -- into _ to overcome forbidden _ in headders.
                meta_name = re.sub('--', '_', meta_name)
                # skip identifier
                #identifier cannot be overridden
                if (meta_name.lower() == 'identifier'):
                    continue
                if meta_name.lower() in defaults:
                    del defaults[meta_name.lower()]
                # do not set publicdate if noindex or neverindex is set
                if (meta_name == 'noindex') and (meta_value == 'true') and ('publicdate' in defaults):
                    del defaults['publicdate']
                if (meta_name == 'neverindex') and (meta_value == 'true') and ('publicdate' in defaults):
                    del defaults['publicdate']
                self.xml_add_key_value(root, meta_name, meta_value)
                
        for key in defaults.keys():
            self.xml_add_key_value(root, key, defaults[key])
        
        return root
        
    def username_can_add_to_collections(self, username, meta_xml_etree):
        """ ask the petabox if a username can can make an item in these collections """
        mediatype_tree = meta_xml_etree.find('mediatype')
        mediatype = str(mediatype_tree.text)

        collections = []
        for c in meta_xml_etree.findall('collection'):
            collections.append(str(c.text))

        cmd = [
            'php', '-r', 
            'include "/petabox/setup.inc"; print Auth::usernameCanAddToCollections($argv[1], $argv[2], array_slice($argv, 3));',
            '--', 
            username,
            mediatype,
            ]

        cmd = cmd + collections
        
        self._log('username_can_add_to_collections: calling %s' % (repr(cmd),))
        pipe = subprocess.Popen(
            cmd, stdout=subprocess.PIPE)
        output = pipe.communicate()[0]
        if (pipe.wait() != 0):
            raise S3_Error("InternalError", "Auth::usernameCanAddToCollections: " + output)
        if output == '1' or output == '2':
            return True
 

    def put_bucket(self, bucket, data, header, accesskey, error_on_preexisting):
        """ Store a bucket """
        if self.use_fs_directly:
            return fshandler.FilesystemHandler.put_bucket(self, bucket, data, header)

        # write /tmp/tmp/uploads/s3-UUID-bucket/bucket_meta.xml
        # write /tmp/tmp/uploads/s3-UUID-bucket/bucket_files.xml
        # run contrib-submit with delete after submitted

        if not self.is_safe_identifier(bucket):
            raise S3_Error("InvalidBucketName", "Bucket names should be valid archive identifiers; try someting matching"
                + ' this regular expression: ^[a-zA-Z0-9][a-zA-Z0-9_.-]{4,100}$' )

        db = s3db.s3db()
        username = db.get_username(accesskey)
        if username == None :
            # db broken? by the time we get here
            # access key was already checked by s3server
            raise S3_Error

        meta_xml_etree = self.meta_xml_from_header(header, bucket, username)
        
        if not self.username_can_add_to_collections(username, meta_xml_etree):
            raise S3_Error("AccessDenied", "You lack sufficient privilages to write to those collections")

        meta_xml = xml.etree.ElementTree.tostring(meta_xml_etree, "UTF-8")

        bucket_exists = True
        try:
            self.get_bucket_host(bucket) 
        except S3_Error, e:
            if e.code == "NoSuchBucket":
                bucket_exists = False

        if error_on_preexisting and bucket_exists:
            raise S3_Error("BucketAlreadyExists")

        if bucket_exists:
            self.assert_can_write_to_bucket(accesskey, bucket)

        self.assert_not_overloaded(accesskey)

        try:
            holdingdir = "/tmp/tmp/uploads/s3-" + str(uuid.uuid4()) + "-" + self.id_to_filename(bucket)
            meta_xml_file = holdingdir + "/%s_meta.xml" % bucket
            files_xml_file = holdingdir + "/%s_files.xml" % bucket
            
            if not os.path.isdir(holdingdir):
                os.makedirs(holdingdir)
            m = open(meta_xml_file, "w")
            m.write(meta_xml)
            m.close()
            if not bucket_exists:
                f = open(files_xml_file, "w")
                f.write("<files />\n")
                f.close()

            job = [
                #'echo',
                self.ias3_path + '/' + "./uploadItem.py", 
                "--deleteAfter", 
                "--priority", "-6",
                "-s", username,
                "-d", holdingdir, 
                "-i", bucket, 
                "--comment", "s3-put", 
                ]
            if bucket_exists and not error_on_preexisting:
                job.append("--update")
            pipe = subprocess.Popen(job, stdout=subprocess.PIPE)
            output = pipe.communicate()[0]
            if pipe.wait() != 0:
                shutil.rmtree(holdingdir, True)
                raise S3_Error("InternalError", "uploadItem.py: " + output)
                
            if not bucket_exists:
                db.add_bucket_to_accesskey(bucket, accesskey)
            self._log('put_bucket: Created %s from %s' % (bucket,holdingdir))
            self._log('put_bucket: called upload_item: %s' % output)
        except OSError:
            self._log('put_bucket: Could not create %s from %s' % (bucket,holdingdir))
            raise S3_Error
        return None


    def delkey(self, bucket, key, accesskey, cascade, keep_old_version):
        """delete a key from the s3 storage"""

        if self.use_fs_directly:
            return fshandler.FilesystemHandler.delkey(self, bucket, key)

        self.assert_bucket_exists(bucket)

        db = s3db.s3db()
        username = db.get_username(accesskey)
        if username == None :
            # db broken? by the time we get here
            # access key was already checked by s3server
            raise S3_Error

        for extension in ('', '_meta.txt'):
            job = [
                self.ias3_path + '/' + "./deleteFromItem.py", 
                "-s", username,
                "--priority",
                "1",
                "-i", bucket, 
                "--comment", "s3-delete",
                "--file-to-delete", 
                self.id_to_filename(key) + extension
                ]

            if cascade:
                job.append("--cascade")
            if keep_old_version:
                job.append("--s3-keep-old-version")

            pipe = subprocess.Popen(job, stdout=subprocess.PIPE)
            output = pipe.communicate()[0]
            assert (pipe.wait() == 0)
            self._log('put: called deleteFromItem.py: %s' % output)
