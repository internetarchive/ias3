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

import sys

class S3Log():
    """ 
        Logging class
    """
    def log(self, message):
        if self.verbose:
            print >>self.stream, '%s %s' % (self.prefix, message)

    def __init__(self, stream=sys.stderr, prefix="", verbose=True):
        self.stream = stream 
        self.prefix = prefix 
        self.verbose = verbose 
