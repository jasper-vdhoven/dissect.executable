from enum import IntEnum

from dissect.cstruct import cstruct
from dissect.executable.elf.c_elf import copy_cstruct

macho_32_def = """
typedef struct {
    uint32      magic;
    CPU_TYPE_T  cputype;
    uint32      cpusubtype;
    FILE_TYPE   file_type;
    uint32      ncmds;
    uint32      sizeofcmds;
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
enum MAGIC : uint32 {
    MACHO_32    = 0xFEEDFACE,
    MACHO_64    = 0xFEEDFACF,
    UNIVERSAL   = 0xCAFEBABE, /*Might not be relevant; clashes with JAVA*/
    LASREVINU   = 0xBEBAFECA
};

typedef int     vm_prot_t;

union lc_str {
    uint32_t    offset;
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
    LINKER_OPTIMIZATION_HINT        = 0x2e,
    VERSION_MIN_TVOS                = 0x30,
    NOTE                            = 0x31,
    BUILD_VERSION                   = 0x32,
    DYLD_EXPORTS_TRIE               = 0x80000033,
    DYLD_CHAINED_FIXUPS             = 0x80000034,
    FILESET_ENTRY                   = 0x80000035,
};

enum PLATFORM : uint32 {
    PLATFORM_MACOS                  = 1,
    PLATFORM_IOS                    = 2,
    PLATFORM_TVOS                   = 3,
    PLATFORM_WATCHOS                = 4,
    PLATFORM_BRIDGEOS               = 5,
    PLATFORM_MACCATALYST            = 6,
    PLATFORM_IOSSIMULATOR           = 7,
    PLATFORM_TVOSSIMULATOR          = 8,
    PLATFORM_WATCHOSSIMULATOR       = 9,
    PLATFORM_DRIVERKIT              = 10,
    PLATFORM_MAX                    = PLATFORM_DRIVERKIT
};

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
    HP_PA       = 11,
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
    ALLARM          = 0x0,
    ARMA500ARCH     = 0x1,
    ARMA500         = 0x2,
    ARMA440         = 0x3,
    ARMM4           = 0x4,
    ARMV4T          = 0x5,
    ARMV6           = 0x6,
    ARMV5TEJ        = 0x7,
    ARMXSCALE       = 0x8,
    ARMV7           = 0x9,
    ARMV7F          = 0xa,
    ARMV7S          = 0xb,
    ARMV7K          = 0xc,
    ARMV8           = 0xd,
    ARMV6M          = 0xe,
    ARMV7M          = 0xf,
    ARMV7EM         = 0x10,
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

enum VM_PROT : vm_prot_t {
    VM_PROT_NONE        = 0x00,
    VM_PROT_READ        = 0x01,
    VM_PROT_WRITE       = 0x02,
    VM_PROT_EXECUTE     = 0x04,
    VM_PROT_EXEC_READ   = VM_PROT_READ|VM_PROT_EXECUTE,
    VM_PROT_DEFAULT     = VM_PROT_READ|VM_PROT_WRITE,
    VM_PROT_ALL         = VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE,
};

typedef struct {
    CPU_TYPE_T     cputype;
    int32           cpusubtype;
    uint32_t        offset;
    uint32_t        size;
    uint32_t        align;
} fat_arch;

typedef struct {
    uint32_t    magic;
    uint32_t    nfat_arch; /* Number of architectures embedded within fat binary */
} FAT_HEADER;

typedef struct {
    COMMAND     cmd;
    uint32      cmdsize;
    uint8       data[cmdsize-8];
} load_command;


typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    uint32_t    rebase_off;
    uint32_t    rebase_size;
    uint32_t    bind_off;
    uint32_t    bind_size;
    uint32_t    lazy_bind_off;
    uint32_t    lazy_bind_size;
    uint32_t    export_off;
    uint32_t    export_size;
} dyld_info_command;

typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    uint32_t    symoff;
    uint32_t    nysms;
    uint32_t    stroff;
    uint32_t    strsize;
} symtab_command;

typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    uint32_t    ilocalsym;
    uint32_t    nlocalsym;
    uint32_t    iextdefsym;
    uint32_t    nextdefsym;
    uint32_t    iundefsym;
    uint32_t    nundefsym;
    uint32_t    tocoff;
    uint32_t    ntoc;
    uint32_t    modtaboff;
    uint32_t    nmodtab;
    uint32_t    extrefsymoff;
    uint32_t    nextrefsyms;
    uint32_t    indirectsymoff;
    uint32_t    nindirectsyms;
    uint32_t    extreloff;
    uint32_t    nextrel;
    uint32_t    locreloff;
    uint32_t    nlocrel;
} dysymtab_command;

typedef struct {
    COMMAND         cmd;
    uint32_t        cmdsize;
    union lc_str    name;
} dylinker_command;

typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    PLATFORM    platform;
    uint32_t    minos;
    uint32_t    sdk;
    uint32_t    ntools;
} build_version_command;

typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    uint64_t    version;
} source_version_command;

typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    uint64_t    entryoff;
    uint64_t    stacksize;
} entry_point_command;

typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    uint32_t    dataoff;
    uint32_t    datasize;
} linkedit_data_command;

typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    uint32_t    cryptoff;
    uint32_t    cryptsize;
    uint32_t    cryptid;
} encryption_info_command;

typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    uint32_t    cryptoff;
    uint32_t    cryptsize;
    uint32_t    cryptid;
    uint32_t    pad;
} encryption_info_command_64;

typedef struct {
    union lc_str    name;
    uint32_t        timestamp;
    uint32_t        current_version;
    uint32_t        compatibility_version;
} dylib;

typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    dylib       dylib;
} dylib_command;

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

typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    char        segname[16];
    uint64_t    vmaddr;
    uint64_t    vmsize;
    uint64_t    fileoff;
    uint64_t    filesize;
    VM_PROT     maxprot;
    VM_PROT     initprot;
    uint32_t    nsects;
    uint32_t    flags;
} segment_command;


typedef struct {
    COMMAND     cmd;
    uint32_t    cmdsize;
    char        segname[16];
    uint64_t    vmaddr;
    uint64_t    vmsize;
    uint64_t    fileoff;
    uint64_t    filesize;
    VM_PROT     maxprot;
    VM_PROT     initprot;
    uint32_t    nsects;
    uint32_t    flags;
} segment_command_64;


typedef struct {
    uint32_t    SG_HIGHVM: 1;
    uint32_t    SG_FVMLIB: 1;
    uint32_t    SG_NORELOC: 1;
    uint32_t    SG_PROTECTED_VERSION_1: 1;
    uint32_t    SG_READ_ONLY: 1;
} sg_flags;


typedef struct {
    char        sectname[16];
    char        segname[16];
    uint32_t    addr;
    uint32_t    size;
    uint32_t    offset;
    uint32_t    align;
    uint32_t    reloff;
    uint32_t    nreloc;
    uint32_t    flags;
    uint32_t    reserved1;
    uint32_t    reserved2;
} section;

typedef struct {
    char        sectname[16];
    char        segname[16];
    uint64_t    addr;
    uint64_t    size;
    uint32_t    offset;
    uint32_t    align;
    uint32_t    reloff;
    uint32_t    nreloc;
    uint32_t    flags;
    uint32_t    reserved1;
    uint32_t    reserved2;
    uint32_t    reserved3;
} section_64;


typedef struct {
    uint32_t    cmd;
    uint32_t    cmdsize;
    uint8_t     uuid[16];
} uuid_command;

"""

c_common_macho = cstruct().load(macho_def)
c_macho_32 = copy_cstruct(c_common_macho).load(macho_32_def)
c_macho_64 = copy_cstruct(c_common_macho).load(macho_64_def)

COMMAND: IntEnum = c_common_macho.COMMAND
