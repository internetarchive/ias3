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

DEBUG=None

import base64
import cgi
import email.parser
import hashlib
import hmac
import MySQLdb
import os
import posixpath
import random
import re
import sha
import shutil
import socket
import string
import sys
import subprocess
import tempfile
import time
import urllib
import urlparse
import uuid
import wsgiref
import wsgiref.headers
import xml.etree.ElementTree

from string import atoi,split

import itemhandler
import fshandler
import s3log
import s3db
import s3path
from s3errors import *


from string import joinfields, split, lower

class file_iter():

    def __init__(self, filehandle, size, blocksize=1048576):
        self.filehandle = filehandle
        self.size = size
        self.blocksize = blocksize
        self.sent = 0
        self.done = False

    def __iter__(self):
        return self

    def next(self):
        if self.done:
            self.filehandle.close()
            raise StopIteration
        b = self.filehandle.read(self.blocksize)
        if b == None or b == '':
            self.filehandle.close()
            raise StopIteration

        # get this right so range requests can work
        if (len(b) + self.sent) > self.size :
            # last read is done, truncate b, we are done
            left_to_send = self.size - self.sent
            b = b[0:left_to_send]
            self.done = True

        self.sent = self.sent + len(b)
        return b
        


def s3_wsgi_app(env, start_response):

    s3 = S3RequestHandler(env, start_response);

    # check for methods starting with do_
    command = env['REQUEST_METHOD']
    mname = 'do_' + command
    if not hasattr(s3, mname):
        self.send_error(501, "Unsupported method (%s)" % `command`)
        return
    method = getattr(s3, mname)
    method()
    return s3.data


class S3RequestHandler():
    """
        Simple S3 request handler class
        for wsgi api.
    """

    def __init__(self, wsgi_env, wsgi_start_response):
        self.env = wsgi_env
        self.start_response = wsgi_start_response
        self.db = s3db.s3db()

        init_log = []
        init_log.append( "SCRIPT_NAME: [%s] PATH_INFO: [%s] QUERY_STRING: [%s]" % (self.env['SCRIPT_NAME'], self.env['PATH_INFO'], self.env['QUERY_STRING']))
        if self.env.has_key('CONTENT_TYPE'):
            init_log.append( "CONTENT_TYPE: [%s]" % (self.env['CONTENT_TYPE']))
        self.path = ''
        self.path = self.env['REQUEST_URI']
       
        self.command = self.env['REQUEST_METHOD']

        self.data = []
        self.response_headers = []
        self.response_headers_dict = wsgiref.headers.Headers(self.response_headers)
        self.response = '500 Internal error'
        
        self.headers = {}
        init_log.append("\n-- headers:\n")
        for key in sorted(self.env.keys()):
            if not key.startswith('HTTP_'):
                continue
            value = self.env[key]
            newkey = key[5:]
            newkey = string.replace(newkey, '_', '-')
            newkey = string.lower(newkey)
            if newkey == 'cookie':
                value = 'REDACTED_BY_IA_S3'
            self.headers[newkey] = value

            # filter log
            if newkey == 'authorization':
                (access, sep, secret) = value.partition(':')
                init_log.append("%s:[%s] " % (newkey, access + ':REDACTED_BY_IA_S3'))
            if newkey != 'authorization':
                init_log.append("%s:[%s] " % (newkey, value))

        init_log.append("-- end headers\n")

        if self.env.has_key('CONTENT_LENGTH'):
            self.headers['content-length'] = self.env['CONTENT_LENGTH']
        if self.env.has_key('CONTENT_TYPE'):
            self.headers['content-type'] = self.env['CONTENT_TYPE']

        (accesskey, signature) = S3RequestHandler.get_accesskey_signature(self)
        self._log = s3log.S3Log(self.env['wsgi.errors'], "s3accesskey-"+accesskey).log
        self.IFACE_CLASS = itemhandler.ItemHandler("/", self._log)
        for l in init_log:
            self._log(l)


    def send_response(self, code, message):
        self.response = str(code) + ' ' + message

    def send_header(self, name, value):
        # AWS sends etag as ETag: "$md5"
        # boto requires the " around the md5
        # here we fix up etag headers to be good for boto
        if re.match("^etag$", name, re.IGNORECASE):
            name = "ETag"
            if not re.match('^".*"$', value):
                value = '"' + value + '"'
        self.response_headers_dict.add_header(name, value)

    def end_headers(self):
        self.start_response(self.response, self.response_headers)
        
    def send_body(self,DATA,code,msg,desc,ctype='application/octet-stream',headers={}):
        """ send a body in one part """

        self.send_response(code,message=msg)
        self.send_header("Accept-Ranges", "bytes")
        
        ctype_set = False
        for a,v in headers.items():
            if a.lower() == "content-type":
                ctype_set = True

        for a,v in headers.items():
            self.send_header(a,v)
        
        if (type(DATA) is type("")) or DATA is None:
            if DATA:
                self.send_header("Content-Length", str(len(DATA)))
            else:
                self.send_header("Content-Length", "0")
                DATA = ""
            self.end_headers()
            self.data.append(DATA)
            
        else:
            # data is an s3server.file_iter
            self.send_header("Content-Length", str(DATA.size))
            self.end_headers()
            self.data = DATA
            

    def header_update(self, standing, update):
        """Update dictionaries of headers ignoring case"""
        lc_merged = {}
        for k in standing.keys():
           lc_merged[k.lower()] = standing[k]
        for k in update.keys():
           lc_merged[k.lower()] = update[k]
        return lc_merged

    def send_location_redirect(self):
        self._log("doing send_location_redirect")
        (bucket, key) = self.get_bucket_key()
        dc=self.IFACE_CLASS
        host = dc.get_bucket_host(bucket)
        self._log("send_location_redirect got %s for %s" % (host, bucket))
        self._log("send_location_redirect got %s for %s" % (host, bucket))
        # make a new request path with only the hostname changed .. prevent signature invalidation
        #newpath = re.sub('^(.+?://)[^/]+(.*)$', '\g<1>'+host+'\g<2>', self.path)
        if self.bucket_in_host_header():
            newpath = "http://%s.%s%s" % (bucket, host, self.path)
            endpoint_host = "%s.%s" % (bucket, host)
        else:
            newpath = "http://%s%s" % (host, self.path)
            endpoint_host = host
        headers = {}
        headers['location'] = newpath
        self._log("redir location: " + newpath)
        root = xml.etree.ElementTree.Element("Error")
        root.set('xmlns', "http://s3.amazonaws.com/doc/2006-03-01/")
        code = xml.etree.ElementTree.SubElement(root, "Code")
        code.text = "TemporaryRedirect"
        message = xml.etree.ElementTree.SubElement(root, "Message")
        message.text = """Please re-send this request to the specified temporary endpoint. 
                          Continue to use the original request endpoint for future requests."""
        endpoint = xml.etree.ElementTree.SubElement(root, "Endpoint")
        endpoint.text = endpoint_host
        bucket_elment = xml.etree.ElementTree.SubElement(root, "Bucket")
        bucket_elment.text = bucket
        data = xml.etree.ElementTree.tostring(root, "UTF-8")
        self._log("redir data: " + data)
        headers['content-type'] = 'application/xml'
        self.send_body(data,"307","Temporary Redirect","Temporary Redirect",'',headers)

        
    ### HTTP METHODS called by the server

    def _init_locks(self):
        if not hasattr(self, '_lock_table'):
            self._lock_table = {}

        return self._lock_table

    def do_GET(self):
        """Serve a GET request."""

        dc=self.IFACE_CLASS

        lm="Sun, 01 Dec 2014 00:00:00 GMT"  # dummy!
        headers={"Last-Modified":lm}
        data_head = {};

        query = urlparse.urlparse(self.path)[4]
        try:
            if not self.is_local_request():
                return self.send_location_redirect()

            (bucket, key) = self.get_bucket_key()
            (accesskey, signature) = self.get_accesskey_signature()
            if query == 'acl':
                data = self.get_acl_xml()
                headers['content-type'] = 'application/xml'
            elif query == 'log':
                p = s3path.s3path()
                data = subprocess.Popen([p.s3+"/dumplog", "s3accesskey-"+accesskey], stdout=subprocess.PIPE).communicate()[0]
            elif key:
                data_head=dc.get_head(bucket, key)
                data=dc.get_data(bucket, key)
            elif bucket:
                key_list = dc.get_key_list(bucket)
                #dc.pp(key_list)
                data=self.get_keys_xml(bucket, key_list)
                data_head=dc.get_head(bucket, key)
                headers['content-type'] = 'application/xml'
            else:
                bucket_list = dc.get_bucket_list(accesskey)
                data = self.gen_bucket_list_xml(bucket_list)
                data_head=dc.get_head(bucket, key)
                headers['content-type'] = 'application/xml'
        except S3_Error, err:
            self.send_error(err)
            return 

        # send the data
        headers = self.header_update(headers, data_head)
        #dc.pp(headers)
        self.send_body(data,"200","OK","OK",'',headers)


    def do_HEAD(self):
        """ Send a HEAD response """

        dc=self.IFACE_CLASS
        try:
            if not self.is_local_request():
                return self.send_location_redirect()

            (bucket, key) = self.get_bucket_key()
            # get the last modified date
            try:
                lm=time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(dc.get_mtime(bucket, key)))
            except:
                lm="Sun, 01 Dec 2034 00:00:00 GMT"  # dummy!

            headers={"Last-Modified":lm}
            headers['Etag'] = lm

            ct="application/octet-stream"
            headers['Content-Type'] = ct

            data_head=dc.get_head(bucket, key)
            headers["Content-Length"]=str(dc.get_size(bucket, key))
        except S3_Error, err:
            self.send_error(err)
            return 

        headers = self.header_update(headers, data_head)
        self._log(repr(headers))
        # body needs to be \n for apache to properly send the content-length header
        # on to the client
        self.send_body("\n","200","OK","OK",ct,headers)


    def do_POST(self):
        # maybe support in s3
        self.send_error(404,"File not found")
        try:
            self.check_signature();
            raise S3_Error("NotImplemented")
        except S3_Error, err:
            self.send_error(err)
            return 


    def do_DELETE(self):
        """ delete a resource """
        dc=self.IFACE_CLASS
        try:
            (bucket, key) = self.get_bucket_key()
            #if not self.is_local_request():
            #    return self.send_location_redirect()
            self.check_signature();
            (accesskey, signature) = self.get_accesskey_signature()
            if key:
                self.assert_has_write_permission()

                if self.get_header_extension_value('cascade-delete') == '1':
                    cascade = True
                else:
                    cascade = False

                if self.get_header_extension_value('keep-old-version') == '1':
                    keep_old_version = True
                else:
                    keep_old_version = False

                res=dc.delkey(bucket, key, accesskey, cascade, keep_old_version)
            else:
                res=dc.delbucket(bucket, accesskey)

            if res:
                #self.send_status(207,body=res)
                self.send_status(207)
            else:
                self.send_status(204)
        except S3_Error, err:
            self.send_error(err)
            return 

    def do_PUT(self):
        dc=self.IFACE_CLASS
        try:
            (bucket, key) = self.get_bucket_key()
            
            auto_make_bucket = False
            if self.get_header_extension_value('auto-make-bucket') == '1':
                auto_make_bucket = True

            error_on_preexisting_bucket = True
            if self.get_header_extension_value('ignore-preexisting-bucket') == '1':
                error_on_preexisting_bucket = False

            queue_derive = True
            if self.get_header_extension_value('queue-derive') == '0':
                queue_derive = False
            
            keep_old_version = False
            if self.get_header_extension_value('keep-old-version') == '1':
                keep_old_version = True

            body=''

            md5=None
            return_headers = {}
            self.check_signature();
            (accesskey, signature) = self.get_accesskey_signature()
            if key != None and key != '':
                if not auto_make_bucket:
                    dc.assert_bucket_exists(bucket)
                    self.assert_has_write_permission()
                if auto_make_bucket:
                    dc.put_bucket(bucket,body,self.headers,accesskey,False)
                md5 = dc.put_key(bucket,key,self.env['wsgi.input'],self.headers,accesskey,queue_derive,keep_old_version)
                return_headers['ETag'] = md5
            else:
                dc.put_bucket(bucket,body,self.headers,accesskey,error_on_preexisting_bucket)
        except S3_Error, err:
            self.send_error(err)
            return 
        self.send_status(201, 'text/xml;  charset="utf-8"', None, None, return_headers)


    def get_header_extension_value(self, name, default=None):
        """
        get an extension header value by name, supporting 
        both the x-amz and x-archive schemes
        """
        for key in self.headers.keys():
            m = re.search('^x-(amz|archive)-(?P<s3_head_key>.+)', key, re.IGNORECASE)
            if m:
                s3_head_key = m.group('s3_head_key')
                if s3_head_key.lower() == name.lower():
                    return self.headers[key]
        return default

    def send_error(self, exc):
        """ Return an s3 error message  to the client given an s3 exception """    
        root = xml.etree.ElementTree.Element("Error")
        code_el = xml.etree.ElementTree.SubElement(root, "Code")
        code_el.text = str(exc.code)
        message = xml.etree.ElementTree.SubElement(root, "Message")
        message.text = str(exc.message)
        resource_el = xml.etree.ElementTree.SubElement(root, "Resource")
        resource_el.text = str(exc.resource)
        requestid = xml.etree.ElementTree.SubElement(root, "RequestId")
        requestid.text = str(uuid.uuid4())
        r = str(xml.etree.ElementTree.tostring(root, "UTF-8"))
        self._log(r)
        return self.send_body(r, exc.http_code, exc.http_message, '', 'application/xml')


    def send_status(self,code=200,mediatype='text/xml;  charset="utf-8"', \
                                msg=None,body=None, headers={}):
        if not msg: msg=STATUS_CODES[code]
        self.send_body(body,code,STATUS_CODES[code],msg,mediatype,headers)


    def get_bucket_key(self):
        """get the bucket and optional key for the current request"""
        bucket = self.bucket_in_host_header()

        uparts=urlparse.urlparse(self.path)
        fileloc=urllib.unquote(uparts[2][1:])
        parts = split(fileloc,"/")
        if bucket != '':
            key = fileloc
        else:
            bucket = parts[0]
            key = None
            if len(parts) > 1:
                key = '/'.join(parts[1:])

        if key == '':
            key = None

        self._log("command:[%s] path:[%s] bucket:[%s] key:[%s]" % (self.command, self.path, bucket, key))

        return (bucket, key)

    def bucket_in_host_header(self):
        if self.headers.has_key('host'):
            host = self.headers['host']
            for regex in s3path.s3path().dns_bucket_regexs:
                m = re.match(regex, host)
                if m:
                    return m.group('bucket')
        return ''
    

    def is_local_request(self):
        (bucket, key) = self.get_bucket_key()
        if not bucket:
            return True
        return self.IFACE_CLASS.bucket_is_local(bucket)

    def get_keys_xml(self, bucket, keylist):
        """list the keys in a bucket"""
        dc=self.IFACE_CLASS

        query = cgi.parse_qs(urlparse.urlparse(self.path)[4])
        s3keys = []
        filenames = {}
        common_prefixes = {}
        for s3key in keylist:
            if "prefix" in query:
                # filter by prefix
                if not s3key.startswith(query["prefix"][0]):
                    continue
                if "delimiter" in query:
                    # handle roll-up of common prefix elements
                    # to get the max-keys counts right this is done by creating one entry in s3keys
                    # for each CommonPrefixes prefix and then skipping those keys at bucket list time, and later displaying the
                    # common prefixes. this way the max-keys behavior and paging behavior will both be correct.
                    d = re.escape(query["delimiter"][0])
                    p = re.escape(query["prefix"][0])
                    match = re.match(p + '(.*?)' + d, s3key) 
                    if match:
                        common = p + match.group(1) + d
                        if common not in common_prefixes:
                            common_prefixes[common] = 1
                            s3keys.append(common)
                        continue
            s3keys.append(s3key)
            
        # filter to after the marker
        # fixx not efficient
        s3keys.sort()
        if "marker" in query:
            while (len(s3keys) >0 ) and (cmp(query["marker"][0], s3keys[0]) >= 0):
               del s3keys[0]

        # limit result to max-keys
        truncated = False
        if "max-keys" in query:
            maxkeys = int(query["max-keys"][0])
            if len(s3keys) > int(maxkeys):
                s3keys = s3keys[:maxkeys]
                truncated = True

        root = xml.etree.ElementTree.Element("ListBucketResult")
        name = xml.etree.ElementTree.SubElement(root, "Name")
        name.text = bucket
        
        if "prefix" in query:
            prefix_ele = xml.etree.ElementTree.SubElement(root, "Prefix")
            prefix_ele.text = query["prefix"][0]

        if "marker" in query:
            marker_ele = xml.etree.ElementTree.SubElement(root, "Marker")
            marker_ele.text = query["marker"][0]

        if "max-keys" in query:
            maxkeys_ele = xml.etree.ElementTree.SubElement(root, "MaxKeys")
            maxkeys_ele.text = query["max-keys"][0]
            truncated_ele = xml.etree.ElementTree.SubElement(root, "IsTruncated")
            if truncated:
                truncated_ele.text = 'true'
            else:
                truncated_ele.text = 'false'

        if "delimiter" in query:
            delimiter_ele = xml.etree.ElementTree.SubElement(root, "Delimiter")
            delimiter_ele.text = query["delimiter"][0]
        
        for s3key in s3keys:
            if s3key in common_prefixes:
                continue
            contents = xml.etree.ElementTree.SubElement(root, "Contents")
            s3key_ele = xml.etree.ElementTree.SubElement(contents, "Key")
            s3key_ele.text = s3key
            lastmodified = xml.etree.ElementTree.SubElement(contents, "LastModified")
            lastmodified.text = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(dc.get_mtime(bucket, s3key)))
            etag = xml.etree.ElementTree.SubElement(contents, "ETag")
            etag.text = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(dc.get_mtime(bucket, s3key)))
            size = xml.etree.ElementTree.SubElement(contents, "Size")
            size.text = "%d" % (dc.get_size(bucket, s3key))
            storageclass = xml.etree.ElementTree.SubElement(contents, "StorageClass")
            storageclass.text = "STANDARD"
            owner = xml.etree.ElementTree.SubElement(contents, "Owner")
            id = xml.etree.ElementTree.SubElement(owner, "ID")
            id.text = "OpaqueIDStringGoesHere"
            display_name = xml.etree.ElementTree.SubElement(owner, "DisplayName")
            display_name.text = "Readable ID Goes Here"
        
        if len(common_prefixes) > 0:
            common_prefixes_ele = xml.etree.ElementTree.SubElement(root, "CommonPrefixes")
            for prefix in s3keys:
                if prefix not in common_prefixes:
                    continue
                prefix_ele = xml.etree.ElementTree.SubElement(common_prefixes_ele, "Prefix")
                prefix_ele.text = prefix
            
        return xml.etree.ElementTree.tostring(root, "UTF-8")


    def get_acl_xml(self):
        root = xml.etree.ElementTree.Element("AccessControlPolicy")
        root.set('xmlns', "http://s3.amazonaws.com/doc/2006-03-01/")
        owner = xml.etree.ElementTree.SubElement(root, "Owner")
        id = xml.etree.ElementTree.SubElement(owner, "ID")
        id.text = "OpaqueIDStringGoesHere"
        display_name = xml.etree.ElementTree.SubElement(owner, "DisplayName")
        display_name.text = "Readable ID Goes Here"        
        grant = xml.etree.ElementTree.SubElement(root, "Grant")
        grantee = xml.etree.ElementTree.SubElement(grant, "Grantee")
        grantee.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        grantee.set('xsi:type', 'CanonicalUser')
        grantee_id = xml.etree.ElementTree.SubElement(grantee, "ID")
        grantee_id.text = "OpaqueIDStringGoesHere"
        grantee_display_name = xml.etree.ElementTree.SubElement(grantee, "DisplayName")
        grantee_display_name.text = "Readable ID Goes Here"
        permission = xml.etree.ElementTree.SubElement(grant, "Permission")
        permission.text = 'FULL_CONTROL'
        return xml.etree.ElementTree.tostring(root, "UTF-8")


    def gen_bucket_list_xml(self, bucketlist):
        """Takes a list of paths and makes them out to buckets in S3 xml style"""
        root = xml.etree.ElementTree.Element("ListAllMyBucketsResult")
        owner = xml.etree.ElementTree.SubElement(root, "Owner")
        id = xml.etree.ElementTree.SubElement(owner, "ID")
        id.text = "OpaqueIDStringGoesHere"
        display_name = xml.etree.ElementTree.SubElement(owner, "DisplayName")
        display_name.text = "Readable ID Goes Here"
        buckets = xml.etree.ElementTree.SubElement(root, "Buckets")
        for bucket_name in bucketlist:
            bucket = xml.etree.ElementTree.SubElement(buckets, "Bucket")
            name = xml.etree.ElementTree.SubElement(bucket, "Name")
            name.text = bucket_name
            #FIX unix fs has no creation time .. use 0 for now
            created = xml.etree.ElementTree.SubElement(bucket, "CreationDate")
            created.text = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(0))
        return xml.etree.ElementTree.tostring(root, "UTF-8")


    def compute_signature(self, secret, add_bucket=False, ignore_content_type=False):
        """ 
            This code suports different signing scenerios
            to support easy modification of and S3 client library
            and buggy middleware which modifies headers
            
        """
        subcommands = ('location', 'acl', 'torrent')
        (bucket, key) = self.get_bucket_key()
        h  = self.command + "\n"
        h += self.headers.get("content-md5", "")+"\n"
        # sometimes if the client does not provide
        # content-type and wsgi adds one (the wsgiref standalone server is guilty if this)
        # .. this requires a woraround where
        # the bogus added content-type header is ignored.
        if ignore_content_type:
            h += "\n"
        else:
            h += self.headers.get("content-type", "")+"\n"
        if self.headers.has_key('x-amz-date'):
            h += "\n"
        else:
            h += self.headers.get("date", "")+"\n"
        for header in sorted(self.headers.keys()):
            if header.startswith("x-amz-"):
                h += header+":"+str(self.headers[header])+"\n"
        if bucket and add_bucket:
            h += "/" + bucket
        parse = urlparse.urlparse(self.path)
        path_for_signing = parse[2]
        h += path_for_signing
        query = parse[4]
        if query in subcommands:
            h += '?' + query
        self._log("SignHeaders: " + repr(h))
        return (base64.encodestring(hmac.new(secret, h, sha).digest()).strip(), repr(h))

    def get_accesskey_signature(self):
        signature = self.headers.get('authorization')
        if signature:
            (user, signature) = signature.split(':')
            #strip off 'AWS '
            (junk, accesskey) = user.split(' ')
        else:
            (accesskey, signature) = ('', '')

        return (accesskey, signature)


    def check_signature(self):
        """ Check if the request signature is valid 
            Raises error if signature fails """
        (accesskey, signature) = self.get_accesskey_signature()
        secret = self.db.get_secret(accesskey)
        if signature == secret:
            # brewster suggested very-low security mode
            return True
        (comp_sig, string_to_sign) = self.compute_signature(secret, True, False)
        if comp_sig == signature:
            return True
        #try with the spurious bucket in the path
        (comp_sig, string_to_sign) = self.compute_signature(secret, False, False)
        if comp_sig == signature:
            return True
        (comp_sig, string_to_sign) = self.compute_signature(secret, True, True)
        if comp_sig == signature:
            return True
        #try with the spurious bucket in the path
        (comp_sig, string_to_sign) = self.compute_signature(secret, False, True)
        if comp_sig == signature:
            return True
         # should raise auth error
        raise S3_Error("SignatureDoesNotMatch", string_to_sign)
        return False
        #return True

    def assert_has_write_permission(self):
        """ Returns true if user can write to a bucket
            else, throws access denied exception """
        self.check_signature()
        (accesskey, signature) = self.get_accesskey_signature()
        (bucket, key) = self.get_bucket_key()
        
        #shortcut .. only works for bucket redirection tho
        #owner = self.IFACE_CLASS.get_owner_accesskey(bucket, key)
        #if (owner == accesskey):
        #    return True
        
        #this is a very recource heavy check, do it last
        self.IFACE_CLASS.assert_can_write_to_bucket(accesskey, bucket)
        return True


        

STATUS_CODES={
        102:    "Processing",
        200:    "Ok",
        201:    "Created",
        204:    "No Content",
        207:    "Multi-Status",
        201:    "Created",
        400:    "Bad Request",
        403:    "Forbidden",
        404:    "Not Found",
        405:    "Method Not Allowed",
        409:    "Conflict",
        412:    "Precondition failed",
        423:    "Locked",
        415:    "Unsupported Media Type",
        507:    "Insufficient Storage",
        422:    "Unprocessable Entity",
        423:    "Locked",
        424:    "Failed Dependency",
        502:    "Bad Gateway",
        507:    "Insufficient Storage"
}

