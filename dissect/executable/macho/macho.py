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
        # self.load_commands = LoadCommandTable.from_macho(self)

        self.load_commands = [LoadCommand.from_fh(self, self.fh) for _ in range(self.macho_header.ncmds)]
        # self.lc_offset = fh.tell()
        # self.load_commands = LoadCommandTable.from_macho(self)

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
    def __init__(self, macho: MachO, header: c_macho_64.load_command) -> None:
        self.macho = macho
        self.header = header
        self.data = header.data

    def __repr__(self) -> str:
        return repr(self.header)

    @classmethod
    def from_fh(cls, macho: MachO, fh: BinaryIO) -> None:
        header = c_macho_64.load_command(fh)
        header.data = fh.read(header.cmdsize - 8)
        return cls(macho, header)

    @classmethod
    def from_load_command_table(cls, table: LoadCommandTable, idx: int | None = None) -> LoadCommand:
        fh = table.fh
        return cls(fh, idx, table.c_macho)


class LoadCommandTable(Table[LoadCommand]):
    def __init__(self, fh: BinaryIO, offset: int, entries: int, size: int, c_macho: cstruct = c_macho_64):
        super().__init__(entries)
        self.fh = fh
        self.offset = offset
        self.size = size
        self.c_macho = c_macho

    def __repr__(self) -> str:
        return f"<SegmentTable offset=0x{self.offset:x} size=0x{self.size:x}>"

    @classmethod
    def from_macho(cls, macho: MachO) -> LoadCommandTable:
        header = macho.macho_header
        load_commands = header.ncmds
        size_of_commands = header.sizeofcmds
        # TODO: handle offsets and sizes better; currently reaches EOF as load command sizes are not fixed
        offset = macho.lc_offset

        return cls(
            fh=macho.fh,
            offset=offset,
            entries=load_commands,
            size=size_of_commands,
            c_macho=macho.c_macho,
        )

    def _create_item(self, idx: int) -> LoadCommand:
        self.fh.seek(self.offset + self.size * idx)
        return LoadCommand.from_load_command_table(self, idx)
