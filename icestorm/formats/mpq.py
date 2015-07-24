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

MD5_DIGEST_SIZE = 16

MPQ_HI_SHIFT    = 32

MPQ_VERSION_1   = 0x00
MPQ_VERSION_2   = 0x01
MPQ_VERSION_3   = 0x02
MPQ_VERSION_4   = 0x03

MPQ_HASH_ENTRY_EMPTY_CONTINUE   = 0xFFFFFFFE
MPQ_HASH_ENTRY_EMPTY_TERMINATE  = 0xFFFFFFFF

MPQ_FILE_IMPLODE        = 0x00000100
MPQ_FILE_COMPRESS       = 0x00000200
MPQ_FILE_ENCRYPTED      = 0x00010000
MPQ_FILE_FIX_KEY        = 0x00020000
MPQ_FILE_PATCH_FILE     = 0x00100000
MPQ_FILE_SINGLE_UNIT    = 0x01000000
MPQ_FILE_DELETE_MARKER  = 0x02000000
MPQ_FILE_SECTOR_CRC     = 0x04000000
MPQ_FILE_EXISTS         = 0x80000000

MPQ_LOCALE_DEFAULT      = 0x0000
MPQ_LOCALE_CHINESE      = 0x0404
MPQ_LOCALE_CZECH        = 0x0405
MPQ_LOCALE_GERMAN       = 0x0407
MPQ_LOCALE_ENGLISH      = 0x0409
MPQ_LOCALE_SPANISH      = 0x040A
MPQ_LOCALE_FRENCH       = 0x040C
MPQ_LOCALE_ITALIAN      = 0x0410
MPQ_LOCALE_JAPANESE     = 0x0411
MPQ_LOCALE_KOREAN       = 0x0412
MPQ_LOCALE_POLISH       = 0x0415
MPQ_LOCALE_PORTUGUESE   = 0x0416
MPQ_LOCALE_RUSSIAN      = 0x0419
MPQ_LOCALE_ENGLISH_UK   = 0x0809

MPQ_UserData = Struct('mpq_userdata',
    Anchor('a_start'),
    Magic('MPQ\x1B'),

    ULInt32('userdata_size'),
    ULInt32('header_offset'),
    ULInt32('userdata_header_size'),

    Pass
)

MPQ_Header = Struct('mpq_header',
    Anchor('a_start'),
    Magic('MPQ\x1A'),

    ULInt32('header_size'),
    # deprecated in tBC
    ULInt32('archive_size'),
    ULInt16('format_version'),
    ULInt16('block_size'),
    ULInt32('hash_table_offset'),
    ULInt32('block_table_offset'),
    ULInt32('hash_table_entry_count'),
    ULInt32('block_table_entry_count'),

    # tBC and newer
    If(lambda ctx: ctx.format_version >= MPQ_VERSION_2,
        Embedded(Struct('v2_data',
            ULInt64('hi_block_table_offsets_offset'),
            ULInt16('hi_hash_table_offset'),
            ULInt16('hi_block_table_offset'),

            Pass
        ))
    ),

    Value('v_hash_table_offset',
        lambda ctx: (ctx.hash_table_offset + (ctx.hi_hash_table_offset << MPQ_HI_SHIFT)) \
            if ctx.format_version >= MPQ_VERSION_2 else \
            ctx.hash_table_offset
    ),
    Value('v_block_table_offset',
        lambda ctx: (ctx.block_table_offset + (ctx.hi_block_table_offset << MPQ_HI_SHIFT)) \
            if ctx.format_version >= MPQ_VERSION_2 else \
            ctx.block_table_offset
    ),

    # Cataclysm (beta) and newer
    If(lambda ctx: ctx.format_version >= MPQ_VERSION_3,
        Embedded(Struct('v3_data',
            ULInt64('archive_size_64'),
            ULInt64('bet_table_offset'),
            ULInt64('het_table_offset'),

            Pass
        ))
    ),

    # Cataclysm (beta) and newer
    If(lambda ctx: ctx.format_version >= MPQ_VERSION_4,
        Embedded(Struct('v4_data',
            ULInt64('hash_table_size'),
            ULInt64('block_table_size'),
            ULInt64('hi_block_table_size'),
            ULInt64('het_table_size'),
            ULInt64('bet_table_size'),

            ULInt32('raw_chunk_size'),

            String('block_table_md5', MD5_DIGEST_SIZE),
            String('hash_table_md5', MD5_DIGEST_SIZE),
            String('hi_block_table_md5', MD5_DIGEST_SIZE),
            String('bet_table_md5', MD5_DIGEST_SIZE),
            String('het_table_md5', MD5_DIGEST_SIZE),
            String('mpq_header_md5', MD5_DIGEST_SIZE),

            Pass
        ))
    ),

    Pass
)

MPQ_HETTable = Struct('mpq_het_table',
    Magic('HET\x1A'),

    ULInt32('version'),
    ULInt32('data_size'),
    ULInt32('section_size'),

    ULInt32('max_file_count'),
    ULInt32('entry_count'),
    ULInt32('entry_size'),
    ULInt32('total_index_size'),
    ULInt32('index_size_extra'),
    ULInt32('index_size'),
    ULInt32('block_table_size'),

    Array(
        lambda ctx: ctx.entry_count,
        ULInt8('hash_table')
    ),

    # TODO: array of file indexes

    Pass
)

MPQ_BETTable = Struct('mpq_bet_table',
    Magic('BET\x1A'),

    ULInt32('version'),
    ULInt32('data_size'),
    ULInt32('section_size'),

    ULInt32('entry_count'),
    Const(ULInt32('unknown_00'), 0x10),
    ULInt32('entry_size'),

    ULInt32('file_offset_idx'),
    ULInt32('file_real_size_idx'),
    ULInt32('file_stored_size_idx'),
    ULInt32('file_flag_idx'),
    ULInt32('file_unknown_idx'),

    ULInt32('file_offset_len'),
    ULInt32('file_real_size_len'),
    ULInt32('file_stored_size_len'),
    ULInt32('file_flag_len'),
    ULInt32('file_unknown_len'),

    ULInt32('total_hash_size'),
    ULInt32('hash_size_extra'),
    ULInt32('hash_size'),
    ULInt32('hash_table_size'),
    ULInt32('flag_count'),

    Array(
        lambda ctx: ctx.flag_count,
        ULInt32('flags')
    ),

    # TODO: file table
    # TODO: bet hash array

    Pass
)

MPQ_HashTable = Array(
    lambda ctx: ctx.mpq_header.hash_table_entry_count,
    Struct('mpq_hash_table',
        ULInt32('name_a'),
        ULInt32('name_b'),

        ULInt16('locale'),
        ULInt16('platform'),

        ULInt32('block_idx'),

        Pass
    )
)

MPQ_BlockTable = Array(
    lambda ctx: ctx.mpq_header.block_table_entry_count,
    Struct('mpq_block_table',
        ULInt32('data_offset'),
        ULInt32('data_stored_size'),
        ULInt32('data_real_size'),
        ULInt32('flags'),

        Pass
    )
)

MPQ_HiBlockTable = Array(
    lambda ctx: ctx.mpq_header.block_table_entry_count,
    ULInt16('mpq_hi_block_table')
)

MPQ_Format = Struct('mpq',
    MPQ_Header,

    If(lambda ctx: ctx.mpq_header.format_version >= MPQ_VERSION_3 and \
            ctx.mpq_header.het_table_offset != 0,
        Pointer(lambda ctx: ctx.mpq_header.het_table_offset,
            MPQ_HETTable
        )
    ),

    If(lambda ctx: ctx.mpq_header.format_version >= MPQ_VERSION_3 and \
            ctx.mpq_header.bet_table_offset != 0,
        Pointer(lambda ctx: ctx.mpq_header.bet_table_offset,
            MPQ_BETTable
        )
    ),

    If(lambda ctx: ctx.mpq_header.v_hash_table_offset != 0,
        Pointer(lambda ctx: ctx.mpq_header.v_hash_table_offset,
            MPQ_HashTable
        )
    ),

    If(lambda ctx: ctx.mpq_header.v_block_table_offset != 0,
        Pointer(lambda ctx: ctx.mpq_header.v_block_table_offset,
            MPQ_BlockTable
        )
    ),

    If(lambda ctx: ctx.mpq_header.format_version >= MPQ_VERSION_2 and \
            ctx.mpq_header.hi_block_table_offsets_offset != 0,
        Pointer(lambda ctx: ctx.mpq_header.hi_block_table_offsets_offset,
            MPQ_HiBlockTable
        )
    ),

    Pass
)
