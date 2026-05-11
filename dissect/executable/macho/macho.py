from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO, Generic, TypeVar

from dissect.cstruct import dumpstruct

from dissect.executable.exception import InvalidSignatureError
from dissect.executable.macho.c_macho import c_common_macho, c_macho_32, c_macho_64

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from dissect.cstruct import cstruct


class MachO:
    def __init__(self, fh: BinaryIO):
        self.fh = fh

        fh.seek(0)
        file_magic = fh.read(0x4)
        fh.seek(0)

        match int.from_bytes(bytes=file_magic, byteorder="little"):
            case c_common_macho.MACHO_MAGIC.MACHO_32:
                self.macho_type = c_common_macho.MACHO_MAGIC.MACHO_32
                self.c_macho = c_macho_32
                print("type is Mach-O 32")
            case c_common_macho.MACHO_MAGIC.MACHO_64:
                self.macho_type = c_common_macho.MACHO_MAGIC.MACHO_64
                self.c_macho = c_macho_64
                print("type is Mach-O 64")
            case c_common_macho.MACHO_MAGIC.FAT_MAGIC | c_common_macho.MACHO_MAGIC.FAT_CIGAM:
                # TODO: implement proper handling of Fat/universal Mach-Os
                self.c_macho = c_common_macho
                # Fat header is parsed as big endian
                self.c_macho.endian = ">"

                self.fat_header = self.c_macho.fat_header(fh)
                # dumpstruct(self.fat_header)
                if int.from_bytes(bytes=file_magic, byteorder="little") == c_common_macho.MACHO_MAGIC.FAT_CIGAM:
                    # self.macho_type = c_common_macho.MACHO_MAGIC.UNIVERSAL
                    print("Fat header & arch headers need to be swapped!")

                # for _ in range(self.fat_header.nfat_arch):
                #     self.fat_archs.append(self.c_macho.fat_arch(fh))
                # self.c_macho.endian = "<"

            case _:
                raise InvalidSignatureError("Invalid header magic")

        self.macho_header = self.c_macho.macho_header(fh)
        dumpstruct(self.macho_header)
        self.load_commands = LoadCommandTable.from_macho(self)
        # self.load_commands = [LoadCommand.from_fh(self, self.fh) for _ in range(self.macho_header.ncmds)]
        print()


T = TypeVar("T")


class Table(Generic[T]):
    def __init__(self, num: int) -> None:
        self.num = num
        self.items: list[T] = [None] * num

    def __iter__(self) -> Iterator[T]:
        for idx in range(self.num):
            yield self[idx]

    def __getitem__(self, idx: int) -> T:
        if self.items[idx] is None:
            self.items[idx] = self._create_item(idx)
        return self.items[idx]

    def _create_item(self, idx: int) -> T:
        raise NotImplementedError

    def find(self, condition: Callable[[T], bool], **kwargs) -> list[T]:
        return [item for item in self if condition(item, **kwargs)]


class LoadCommand:
    # TODO: clean this up and add proper typing
    def __init__(self, table, header, offset: int, data: bytes) -> None:
        self.table = table
        self.header = header
        self.cmd_type = header.cmd.name
        self.cmd_size = header.cmdsize
        self.offset = offset
        self.data = data

    def __repr__(self) -> str:
        return f"<LoadCommand {self.header.cmd.name} at offset=0x{self.offset:x} size=0x{self.cmd_size:x}>"

    @classmethod
    def from_load_command_table(cls, table: LoadCommandTable, offset: int) -> LoadCommand:
        fh = table.fh
        c_macho = table.c_macho

        fh.seek(offset)
        header = c_macho.load_command(fh)
        data = fh.read(header.cmdsize - 8)  # 2 x uint32_t

        return cls(table, header, fh.tell(), data)


class LoadCommandTable(Table[LoadCommand]):
    def __init__(self, fh: BinaryIO, entries: int, offset: int, c_macho: cstruct = c_macho_64):
        super().__init__(entries)
        self.fh = fh
        self.entries = entries
        self.offset = offset
        self.c_macho = c_macho

        # populate self.items so we can iter over them
        self._parse()

    def __repr__(self) -> str:
        return f"<LoadCommandTable offset=0x{self.offset:x} size=0x{self.size:x}>"

    def _parse(self) -> None:
        """Iterate and parse Mach-O load command.
        In order to iterate over the load commands self.items needs to be populated.

        Returns: None.
        """
        current_offset = self.offset
        for i in range(self.entries):
            item = self._create_item(current_offset)
            if not item:
                break
            self.items[i] = item
            current_offset += item.cmd_size

    def _create_item(self, idx: int) -> LoadCommand:
        return LoadCommand.from_load_command_table(self, idx)

    @classmethod
    def from_macho(cls, macho: MachO) -> LoadCommandTable:
        return cls(macho.fh, macho.macho_header.ncmds, macho.macho_header.size)
