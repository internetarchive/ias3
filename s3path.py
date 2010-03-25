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


class s3path():
    """ 
        paths
    """
    def __init__(self):
        self.petabox = "/petabox"
        self.s3 = self.petabox + "/sw/ias3/deploy"
        self.dns_bucket_regexs = (
            r'(?P<bucket>.+)\.s3\.us\.archive\.org(:\d+)?$',
            r'(?P<bucket>.+)\.[^.]+\.s3dns\.us\.archive\.org(:\d+)?$',
        )
        self.port = 82
        self.pbconfig = self.petabox + "/etc/petabox-sw-config-us.xml"
