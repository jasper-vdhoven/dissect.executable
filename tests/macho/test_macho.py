from __future__ import annotations

from io import BytesIO

import pytest

from dissect.executable.exception import InvalidSignatureError
from dissect.executable.macho.macho import MachO


def test_macho_invalid_signature() -> None:
    with pytest.raises(InvalidSignatureError):
        MachO(BytesIO(b"\x00\xfa\xed\xfe" + b"\x00" * 0x40))


def test_macho_32_valid_signature() -> None:
    MachO(BytesIO(b"\xce\xfa\xed\xfe" + b"\x00" * 0x40))


def test_macho_64_valid_signature() -> None:
    MachO(BytesIO(b"\xcf\xfa\xed\xfe" + b"\x00" * 0x40))


# TODO: tests for FAT Mach-Os
# def test_macho_fat_valid_signature() -> None:
#     MachO(BytesIO(b"\xbe\xba\xfe\xca" + b"\x00" * 0x40))
#
#
# def test_macho_fat_64_valid_signature() -> None:
#     MachO(BytesIO(b"\xbe\xba\xfe\xca" + b"\x00" * 0x40))
