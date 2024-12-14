from enum import Flag, IntEnum

from dissect.cstruct import cstruct
from dissect.executable.elf.c_elf import copy_cstruct

macho_32_def = """
typedef struct {
    uint32      magic;
    CPU_TYPE_T  cputype;
    uint32      cpusubtype;
    FILE_TYPE   file_type;
    uint32      n_load_commands;
    uint32      s_load_commands;
    flags       flags;
} MACHO_HEADER;

"""


macho_64_def = """
typedef struct {
    uint32      magic;
    CPU_TYPE_T  cputype;
    uint32      cpusubtype;
    FILE_TYPE   file_type;
    uint32      ncmds;
    uint32      sizeofcmds;
    flags       flags;
    uint32      reserved;
} MACHO_HEADER;

"""

macho_def = """
#define NT_SIGINFO          b"0x53494749"

enum MAGIC : uint32 {
    MACHO_32    = 0xFEEDFACE,
    MACHO_64    = 0xFEEDFACF,
    UNIVERSAL   = 0xCAFEBABE,
};

enum COMMAND : uint32 {
    REQ_DYLD                        = 0x80000000,
    SEGMENT                         = 0x1,
    SYMTAB                          = 0x2,
    SYSMEG                          = 0x3,
    THREAD                          = 0x4,
    UNIXTHREAD                      = 0x5,
    LOADFVMLIB                      = 0x6,
    IDFVMLIB                        = 0x7,
    IDENT                           = 0x8,
    FVMFILE                         = 0x9,
    PREPAGE                         = 0xa,
    DYSYMTAB                        = 0xb,
    LOAD_DYLIB                      = 0xc,
    ID_DYLIB                        = 0xd,
    LOAD_DYLINKER                   = 0xe,
    ID_DYLINKER                     = 0xf,
    PRBOUND_DYLIB                   = 0x10,
    ROUTINES                        = 0x11,
    SUB_FRAMEWORK                   = 0x12,
    SUB_UMBRELLA                    = 0x13,
    SUB_CLIENT                      = 0x14,
    SUB_LIBRARY                     = 0x15,
    TWOLEVEL_HINTS                  = 0x16,
    PREBIND_CKSUM                   = 0x17,
    LOAD_WEAK_DyLB                  = 0x80000018,
    SEGMENT_64                      = 0x19,
    ROUTINES_64                     = 0x1a,
    UUID                            = 0x1b,
    RPATH                           = 0x8000001C,
    CODE_SIGNATURE                  = 0x1d,
    SEGMENT_SPLIT_INFO              = 0x1e,
    REEXPORT_DYLIB                  = 0x8000001f,
    LAZY_LOAD_DYLIB                 = 0x20,
    ENCRYPTION_INFO                 = 0x21
    DYLD_INFO                       = 0x22,
    DYLD_INFO_ONLY                  = 0x80000022,
    LOAD_UPWARD_DYLIB               = 0x80000023,
    VERSION_MIN_MACOSX              = 0x24,
    VERSION_MIN_IPHONEOS            = 0x25,
    FUNCTION_STARTS                 = 0x26,
    DYLD_ENVIRONMENT                = 0x27,
    MAIN                            = 0x80000028,
    DATA_IN_CODE                    = 0x29,
    SOURCE_VERSION                  = 0x2a,
    DYLIB_CODE_SIGN_DRS             = 0x2b,
    ENCRYPTION_INFO_64              = 0x2c,
    LINKER_OPTION                   = 0x2d,
    LINKER_OPTION_OPTIMIZATION_HINT = 0x2e,
    VERSION_MIN_TVOS                = 0x30,
    NOTE                            = 0x31,
    BUILD_VERSION                   = 0x32,
    DYLD_EXPORTS_TRIE               = 0x80000033,
    DYLD_CHAINED_FIXUPS             = 0x80000034,
    FILESET_ENTRY                   = 0x35,
};


typedef struct {
    COMMAND     cmd;
    uint32      cmdsize;
} load_command;


enum CPU_TYPE_T : uint32 {
    ANY         = 0,
    VAX         = 1,
    ROMP        = 2,
    NS32032     = 4,
    NS32332     = 5,
    MC680x0     = 6,
    X86         = 7,
    X86_64      = 16777223,
    MIPS        = 8,
    NS32352     = 9,
    MC98000     = 10,
    HP-PA       = 11,
    ARM         = 12,
    ARM64       = 16777228,
    ARM64_32    = 33554444,
    MC88000     = 13,
    SPARC       = 14,
    I860LE      = 15,
    I860BE      = 16,
    RS6000      = 17,
    POWERPC     = 18,
    POWERPC64   = 16777234,
    VEO         = 255
};

enum CPU_SUBTYPE_ARM : uint32 {
    ALLARM          = 0,
    ARMA500ARCH     = 1,
    ARMA500         = 2,
    ARMA440         = 3,
    ARMM4           = 4,
    ARMV4T          = 5,
    ARMV6           = 6,
    ARMV5TEJ        = 7,
    ARMXSCALE       = 8,
    ARMV7           = 9,
    ARMV7F          = 10,
    ARMV7S          = 11,
    ARMV7K          = 12,
    ARMV8           = 13,
    ARMV6M          = 14,
    ARMV7M          = 15,
    ARMV7EM         = 16,
};

enum CPU_SUBTYPE_X86 : uint32 {
    ALLX86          = 3,
    486             = 4,
    PENTIUM3        = 8,
    PENTIUM4        = 0xA,
    ITANIUM         = 0xB,
    XEON            = 0xC,
    486SX           = 0x84,
    PENTIUMM5       = 0x56,
    CELERON         = 0x67,
    CELERONMOBILE   = 0x77,
    PENTIUM3M       = 0x18,
    PENTIUM3XEON    = 0x28,
    ITANIUM2        = 0x1B,
    XEONMP          = 0x1C,
};

enum FILE_TYPE : uint32 {
    OBJECT          = 1,
    EXECUTE         = 2,
    FVMLIB          = 3,
    CORE            = 4,
    PRELOAD         = 5,
    DYLIB           = 6,
    DYLINKER        = 7,
    BUNDLE          = 8,
    DYLIB_STUB      = 9,
    DYSM            = 10,
    KEXT_BUNDLE     = 11,
    FILESET         = 12,
};

typedef struct {
    uint32          noUndefs: 1;
    uint32          incrLink: 1;
    uint32          dydLink: 1;
    uint32          BindAtLoad: 1;
    uint32          prebound: 1;
    uint32          splitSegs: 1;
    uint32          lazyInit: 1;
    uint32          twoLevel: 1;
    uint32          forceFlat: 1;
    uint32          noMultiDefs: 1;
    uint32          noFixPrebinding: 1;
    uint32          prebindable: 1;
    uint32          alModsBound: 1;
    uint32          subSectionsViaSymbols: 1;
    uint32          canonical: 1;
    uint32          weakDefines: 1;
    uint32          bindsToWeak: 1;
    uint32          allowStackExecution: 1;
    uint32          rootSafe: 1;
    uint32          setuidSafe: 1;
    uint32          noReexportedDylab: 1;
    uint32          pie: 1;
    uint32          deadStrippableDylib: 1;
    uint32          hasTlvDescriptors: 1;
    uint32          noHeapExecution: 1;
    uint32          appExtensionsSafe: 1;
    uint32          nlistOutofSyncWithDyldinfo: 1;
    uint32          simSupport: 1;
    uint32          dylibInCache: 1;
} flags;
"""

c_common_macho = cstruct().load(macho_def)
c_macho_32 = copy_cstruct(c_common_macho).load(macho_32_def)
c_macho_64 = copy_cstruct(c_common_macho).load(macho_64_def)
