from __future__ import annotations

import io
from typing import BinaryIO, Generic, Iterator, Optional, TypeVar

from dissect.cstruct import cstruct, swap32
from dissect.cstruct import dumpstruct
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
            case c_common_macho.MAGIC.UNIVERSAL | c_common_macho.MAGIC.LASREVINU:
                self.e_ident = c_common_macho.MAGIC.UNIVERSAL
            case _:
                raise InvalidSignatureError("Invalid header magic")

        self.c_macho = c_macho_version
        self.c_macho.endian = ">"

        if self.e_ident in (c_common_macho.MAGIC.UNIVERSAL, c_common_macho.MAGIC.LASREVINU):
            # Change endian to big as Fat header is parsed as big endian
            self.c_macho.endian = ">"
            self.fat_header = self.c_macho.FAT_HEADER(fh)
            self.fat_archs = []
            for _ in range(swap32(self.fat_header.nfat_arch)):
                self.fat_archs.append(self.c_macho.fat_arch(fh))
                self.fat_archs[_].cputype = c_common_macho.CPU_TYPE_T(swap32(self.fat_archs[_].cputype))

            # Restore endian setting as remainder will be little endian
            self.c_macho.endian = "<"
            print()

        if self.fat_archs:
            self.macho_binary = {}
            for i in self.fat_archs:
                # Stored as BE in binary
                fh.seek(swap32(i.offset))
                # self.macho_binary[str(i.cputype).split(".")[1]] = self.c_macho.MACHO_HEADER(fh)
                self.macho_binary[str(i.cputype).split(".")[1]] = self.c_macho.MACHO_HEADER(fh)
                self.commands = CommandTable.from_macho(self)

                # self.macho_binary[str(i.cputype).split(".")[1]] = [_binary, _commands]

        else:
            self.header = self.c_macho.MACHO_HEADER(fh)

        self.header.magic = self.e_ident

        """
        Match CPU sub type to CPU type from already parsed header
        """
        match self.header.cputype:
            case c_common_macho.CPU_TYPE_T.ARM64 | c_common_macho.CPU_TYPE_T.ARM | c_common_macho.CPU_TYPE_T.ARM64_32:
                self.header.cpusubtype = c_common_macho.CPU_SUBTYPE_ARM(self.header.cpusubtype)
            case c_common_macho.CPU_TYPE_T.X86_64:
                self.header.cpusubtype = c_common_macho.CPU_SUBTYPE_X86(self.header.cpusubtype)

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

    def __repr__(self) -> str:
        return repr(self.data)

    @classmethod
    def from_command_table(cls, command_table: CommandTable, idx: int) -> LoadCommand:
        result = cls(command_table.fh, idx=idx, c_macho=command_table.c_macho)

        cmd, cmdsize = result.c_macho.uint32[2](result.fh.read(16))
        result.fh.seek(-16, io.SEEK_CUR)
        data = result.fh.read(cmdsize)

        match cmd:
            case result.c_macho.COMMAND.UUID:
                load_command = result.c_macho.uuid_command(data)
            case result.c_macho.COMMAND.SEGMENT:
                load_command = result.c_macho.segment_command(data)
            case result.c_macho.COMMAND.SEGMENT_64:
                load_command = result.c_macho.segment_command_64(data)
            case result.c_macho.COMMAND.DYLD_INFO_ONLY:
                load_command = result.c_macho.dyld_info_command(data)
            case result.c_macho.COMMAND.SYMTAB:
                load_command = result.c_macho.symtab_command(data)
            case result.c_macho.COMMAND.DYSYMTAB:
                load_command = result.c_macho.dysymtab_command(data)
            case result.c_macho.COMMAND.LOAD_DYLINKER:
                load_command = result.c_macho.dylinker_command(data)
            case result.c_macho.COMMAND.BUILD_VERSION:
                load_command = result.c_macho.build_version_command(data)
            case result.c_macho.COMMAND.SOURCE_VERSION:
                load_command = result.c_macho.source_version_command(data)
            case result.c_macho.COMMAND.MAIN:
                load_command = result.c_macho.entry_point_command(data)
            case (
                result.c_macho.COMMAND.CODE_SIGNATURE
                | result.c_macho.COMMAND.SEGMENT_SPLIT_INFO
                | result.c_macho.COMMAND.DYLIB_CODE_SIGN_DRS
                | result.c_macho.COMMAND.LINKER_OPTIMIZATION_HINT
                | result.c_macho.COMMAND.DYLD_EXPORTS_TRIE
                | result.c_macho.COMMAND.DYLD_CHAINED_FIXUPS
                | result.c_macho.COMMAND.FUNCTION_STARTS
                | result.c_macho.COMMAND.DATA_IN_CODE
            ):
                load_command = result.c_macho.linkedit_data_command(data)
            case result.c_macho.COMMAND.ENCRYPTION_INFO:
                load_command = result.c_macho.encryption_info_command(data)
            case result.c_macho.COMMAND.ENCRYPTION_INFO_64:
                load_command = result.c_macho.encryption_info_command_64(data)
            case result.c_macho.COMMAND.LOAD_DYLIB:
                load_command = result.c_macho.dylib_command(data)
            case _:
                load_command = result.c_macho.load_command(data)

        result.data = load_command

        return result


class CommandTable(Table[LoadCommand]):
    def __init__(self, fh: BinaryIO, ncmds: int, size: int, c_macho: cstruct = c_macho_64):
        super().__init__(ncmds)
        self.fh = fh
        self.size = size
        self.ncmds = ncmds
        self.c_macho = c_macho

    def __repr__(self) -> str:
        return f"<CommandTable ncmds={self.ncmds} size=0x{self.size:x}>"

    def _create_item(self, idx: int) -> LoadCommand:
        return_class = LoadCommand

        return return_class.from_command_table(self, idx)

    @classmethod
    def from_macho(cls, macho: MACHO) -> CommandTable:
        header = macho.header
        ncmds = header.ncmds
        size = header.sizeofcmds
        return cls(fh=macho.fh, ncmds=ncmds, size=size, c_macho=macho.c_macho)
