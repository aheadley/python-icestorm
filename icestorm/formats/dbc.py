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

from construct import *

DBC_Header = Struct('dbc_header',
    Magic('WDBC'),
    ULInt32('row_count'),
    ULInt32('column_count'),
    ULInt32('row_size'),
    ULInt32('string_block_size'),

    Pass
)

def DBC_Format(row_struct):
    return Struct('dbc_' + row_struct.name,
        DBC_Header,

        Array(lambda ctx: ctx.dbc_header.row_count,
            row_struct
        ),

        Pass
    )

DBCFormat = Struct('dbc',
    Magic('WDBC'),

    Pass
)
