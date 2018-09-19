#!/usr/bin/env python
# -*- coding: utf-8 -*-

from struct import unpack


class MessageHeader(object):

    def __init__(self, payload):
        """
        typedef struct {
            BYTE cBinType;    // fix 0x03
            BYTE cIdentifier; // 8-Bit Unsigned Integer (little endian)
            BYTE cInfo;       // Info
            BYTE cReserved;   // reserved
            UINT nLen;        // 32-Bit Unsigned Integer (little endian)
        } PACKED WsBinHdr;
        """
        self.bin_type, \
        self.identifier, \
        self.info, \
        self.reserved, \
        self.payload_length = unpack('<cBccI', payload)