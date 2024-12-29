from __future__ import annotations

import io
from typing import BinaryIO, Generic, Iterator, Optional, TypeVar

from dissect.cstruct import cstruct
from dissect.cstruct.utils import u32

from dissect.executable.exception import InvalidSignatureError
from dissect.executable.macho.c_macho import c_common_macho, c_macho_32, c_macho_64


class MACHO:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        offset = fh.tell()
        self.e_ident = u32(fh.read(0x4), "<")
        fh.seek(offset)  # This resets the progress back to zero(?)

        c_macho_version = c_macho_64
        match self.e_ident:
            case c_common_macho.MAGIC.MACHO_32:
                self.e_ident = c_common_macho.MAGIC.MACHO_32
                c_macho_version = c_macho_32
            case c_common_macho.MAGIC.MACHO_64:
                self.e_ident = c_common_macho.MAGIC.MACHO_64
            case c_common_macho.MAGIC.UNIVERSAL:
                self.e_ident = c_common_macho.MAGIC.UNIVERSAL
            case _:
                raise InvalidSignatureError("Invalid header magic")

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

        self.commands = CommandTable.from_macho(self)

    def __repr__(self) -> str:
        return str(self.header)


T = TypeVar("T")


class Table(Generic[T]):
    def __init__(self, entries: int) -> None:
        self.entries = entries
        self.items: list[T] = [None] * entries

    def __iter__(self) -> Iterator[T]:
        for idx in range(self.entries):
            yield self[idx]

    def __getitem__(self, idx: int) -> T:
        if self.items[idx] is None:
            self.items[idx] = self._create_item(idx)
        return self.items[idx]

    def _create_item(self, idx: int) -> T:
        raise NotImplementedError()


class LoadCommand:
    def __init__(self, fh: BinaryIO, idx: Optional[int] = None, c_macho: cstruct = c_macho_64):
        self.fh = fh
        self.idx = idx
        self.c_macho = c_macho

        self.load_command = c_macho.load_command(fh)

    def __repr__(self) -> str:
        return repr(self.load_command)

    @classmethod
    def from_command_table(cls, command_table: CommandTable, idx: int) -> LoadCommand:
        result = cls(command_table.fh, idx=idx, c_macho=command_table.c_macho)
        return result


class CommandTable(Table[LoadCommand]):
    def __init__(self, fh: BinaryIO, ncmds: int, size: int, c_macho: cstruct = c_macho_64):
        super().__init__(ncmds)
        self.fh = fh
        self.size = size
        self.ncmds = ncmds
        self.c_macho = c_macho

    def __repr__(self) -> str:
        return f"<CommandTable offset=0x{self.offset:x} size=0x{self.size:x}>"

    def _create_item(self, idx: int) -> LoadCommand:
        cmd, cmdsize = self.c_macho.uint32[2](self.fh.read(16))
        self.fh.seek(-16, io.SEEK_CUR)

        return_class = LoadCommand
        return return_class.from_command_table(self, idx)

    @classmethod
    def from_macho(cls, macho: MACHO) -> CommandTable:
        header = macho.header
        ncmds = header.ncmds
        size = header.size
        return cls(fh=macho.fh, ncmds=ncmds, size=size, c_macho=macho.c_macho)
