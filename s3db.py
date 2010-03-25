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

import subprocess
import MySQLdb
import s3path
import xml.etree.ElementTree


from s3errors import *

class s3db():

    def __init__(self):
        pass

    def connect(self):
        config_xml = s3path.s3path().pbconfig
        config = xml.etree.ElementTree.parse(config_xml)
        host = config.find('database-hostname').text
        db = config.find('database-name').text
        user = config.find('database-username').text

        passwd = 'dummypassword'

        # retry the connect because mysql server at IA sometimes causes this
        # exception:
        # OperationalError: (2013, 
        #     "Lost connection to MySQL server at 'reading authorization packet',system error: 0")
        #
        # this appears to be related to a config problem with mysqld and a loaded web server.
        # see: http://bugs.mysql.com/bug.php?id=28359

        try_count = 1
        max_tries = 5
        self.conn = None
        while (not self.conn) and (try_count <= max_tries):
            try:
                try_count = try_count + 1
                self.conn =  MySQLdb.connect(
                    host=host,
                    db=db,
                    user=user,
                    passwd=passwd,
                    )
            except MySQLdb.OperationalError, e:
                if try_count > max_tries:
                    raise e

    def close(self):
        self.conn.close()

    def get_secret(self, accesskey):
        """ figure out the accesskey secret key """
        self.connect()
        c = self.conn.cursor()
        q = "SELECT s3secretkey FROM archive.s3users WHERE s3accesskey=%s"
        c.execute(q, (accesskey,) )
        r = c.fetchone()
        c.close()
        self.close()
        if r == None:
            raise S3_Error("InvalidAccessKeyId")
        return r[0]

    def get_buckets(self, accesskey):
        """ return the list if s3 buckets a user has """
        self.connect()
        c = self.conn.cursor()
        q = "SELECT s3bucket FROM archive.s3buckets WHERE s3accesskey=%s"
        c.execute(q, (accesskey,) )
        buckets = []
        r = c.fetchone()
        while r != None:
            buckets.append(r[0])
            r = c.fetchone()
        c.close()
        self.close()
        return buckets

    def get_username(self, accesskey):
        self.connect()
        c = self.conn.cursor()
        q = "SELECT username FROM archive.s3users WHERE s3accesskey=%s"
        c.execute(q, (accesskey,) )
        r = c.fetchone()
        c.close()
        self.close()
        if r == None:
            return None
        return r[0]

    def get_accesskey(self, username):
        self.connect()
        c = self.conn.cursor()
        q = "SELECT s3accesskey FROM archive.s3users WHERE username=%s"
        c.execute(q, (username,) )
        r = c.fetchone()
        c.close()
        self.close()
        if r == None:
            return None
        return r[0]

    def get_bucket_owner_accesskey(self, bucket):
        """ Return the owner of a bucket; will return None if no record is found """
        self.connect()
        c = self.conn.cursor()
        q = "SELECT s3accesskey FROM archive.s3buckets WHERE s3bucket=%s"
        c.execute(q, (bucket,) )
        r = c.fetchone()
        c.close()
        self.close()
        if r == None:
            return None
        return r[0]

    def add_bucket_to_accesskey(self, bucket, accesskey):
        self.connect()
        c = self.conn.cursor()
        q = "INSERT INTO s3buckets (s3bucket, s3accesskey) VALUES (%s, %s)"
        c.execute(q, (bucket, accesskey) )
        self.conn.commit()
        c.close()
        self.close()
        return True

    def get_running_put_count_for_user(self, username):
        """ return the current count of pending puts in the CMS for user -- itemhandler.py specific """
        self.connect()
        c = self.conn.cursor()
        q = "SELECT COUNT(catalog.cmd) FROM archive.catalog WHERE submitter=%s AND cmd='archive.php' AND args RLIKE 's3-put'"
        c.execute(q, (username,) )
        put_count = 0
        r = c.fetchone()
        while r != None:
            put_count = r[0]
            break
        c.close()
        self.close()
        return (put_count)

    def get_running_put_counts(self):
        """ return the current count of pending puts in the CMS -- itemhandler.py specific """
        self.connect()
        c = self.conn.cursor()
        q = """
            SELECT COUNT(catalog.cmd) 
                FROM archive.catalog 
                WHERE cmd='archive.php' 
                    AND args LIKE '%s3-put%' 
            """
        c.execute(q)
        total = 0
        r = c.fetchone()
        while r != None:
            total = r[0]
            break
        c.close()
        self.close()
        return (total)

