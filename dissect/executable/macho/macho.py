from __future__ import annotations

import io
from typing import BinaryIO

from dissect.cstruct import cstruct
from dissect.cstruct.utils import u32

from dissect.executable.exception import InvalidSignatureError
from dissect.executable.macho.c_macho import c_common_macho, c_macho_32, c_macho_64


class MACHO:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        offset = fh.tell()
        # self.e_ident = fh.read(0x4)
        self.e_ident = u32(fh.read(0x4), "<")
        fh.seek(offset)  # This resets the progress back to zero(?)

        match self.e_ident:
            case c_common_macho.MAGIC.MACHO_32:
                self.e_ident = c_common_macho.MAGIC.MACHO_32
            case c_common_macho.MAGIC.MACHO_64:
                self.e_ident = c_common_macho.MAGIC.MACHO_64
            case c_common_macho.MAGIC.UNIVERSAL:
                self.e_ident = c_common_macho.MAGIC.UNIVERSAL
            case _:
                raise InvalidSignatureError("Invalid header magic")

        c_macho_version = c_macho_64
        if self.e_ident == c_macho_version.MAGIC.MACHO_32:
            c_macho_version = c_macho_32
        self.c_macho = c_macho_version
        self.c_macho.endian = "<"

        self.header = self.c_macho.MACHO_HEADER(fh)
        self.header.magic = self.e_ident

        """
        Match CPU sub type to CPU type from already parsed header
        """
        match self.header.cputype:
            case c_common_macho.CPU_TYPE_T.ARM64 | c_common_macho.CPU_TYPE_T.ARM | c_common_macho.CPU_TYPE_T.ARM64_32:
                self.header.cputype = c_common_macho.CPU_SUBTYPE_ARM(self.header.cpusubtype)
            case c_common_macho.CPU_TYPE_T.X86_64:
                self.header.cputype = c_common_macho.CPU_SUBTYPE_X86(self.header.cpusubtype)
