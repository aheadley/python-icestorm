# -*- coding: utf-8 -*-

# Copyright (C) 2015  Alex Headley  <aheadley@waysaboutstuff.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import os
import logging

from icestorm.util import NullHandler, LOG_FORMAT

__title__           = 'icestorm'
__version__         = '0.0.1'
__author__          = 'Alex Headley'
__author_email__    = 'aheadley@waysaboutstuff.com'
__license__         = 'GNU Public License v2 (GPLv2)'
__copyright__       = 'Copyright 2015 Alex Headley'
__url__             = 'https://github.com/aheadley/python-icestorm'
__description__     = """
Library for Blizzard's game file formats
""".strip()

logger = logging.getLogger(__title__)

if os.environ.get('IS_DEBUG', False):
    _log_handler = logging.StreamHandler()
    _log_handler.setFormatter(LOG_FORMAT)
    _log_level = logging.DEBUG
else:
    _log_handler = NullHandler()
    _log_level = logging.WARN

logger.setLevel(_log_level)
logger.addHandler(_log_handler)
