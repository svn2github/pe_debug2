#include "StdInc.h"
#include "peloader.h"

#include <sdk/MemoryRaw.h>
#include <sdk/MemoryUtils.h>

#define NOMINMAX
#include <Windows.h>

PEFile::PEFile( void ) : resourceRoot( std::wstring() )
{
    this->is64Bit = false;
}

PEFile::~PEFile( void )
{
    return;
}

struct IMAGE_PE_HEADER
{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    // Rest is machine dependent.
};

inline std::string ReadCString( const char*& stringStream )
{
    std::string outString;

    while ( true )
    {
        char c = *stringStream++;

        if ( c == 0 )
            break;

        outString += c;
    }

    return outString;
}

void PEFile::LoadFromDisk( CFile *peStream )
{
    // We read the DOS stub.
    // It's data is expected to have no complicated things
    IMAGE_DOS_HEADER dosHeader;

    bool couldReadDOS = peStream->ReadStruct( dosHeader );

    if ( !couldReadDOS )
        throw std::exception( "cannot read MSDOS header" );

    // Verify DOS header (light).
    bool isValidDOSHeader =
        ( dosHeader.e_magic == 'ZM' );

    if ( !isValidDOSHeader )
        throw std::exception( "invalid MSDOS checksum" );

    // Save all information about the DOS stub.
    DOSStub dos;
    dos.cblp = dosHeader.e_cblp;
    dos.cp = dosHeader.e_cp;
    dos.crlc = dosHeader.e_crlc;
    dos.cparhdr = dosHeader.e_cparhdr;
    dos.minalloc = dosHeader.e_minalloc;
    dos.maxalloc = dosHeader.e_maxalloc;
    dos.ss = dosHeader.e_ss;
    dos.sp = dosHeader.e_sp;
    dos.csum = dosHeader.e_csum;
    dos.ip = dosHeader.e_ip;
    dos.cs = dosHeader.e_cs;
    dos.lfarlc = dosHeader.e_lfarlc;
    dos.ovno = dosHeader.e_ovno;
    memcpy( dos.reserved1, dosHeader.e_res, sizeof( dos.reserved1 ) );
    dos.oemid = dosHeader.e_oemid;
    dos.oeminfo = dosHeader.e_oeminfo;
    memcpy( dos.reserved2, dosHeader.e_res2, sizeof( dos.reserved2 ) );

    // We need the program data aswell.
    // Assumption is that the data directly follows the header and ends in the new data ptr.
    {
        LONG newDataOffset = dosHeader.e_lfanew;

        LONG sizeOfStubData = ( newDataOffset - sizeof( dosHeader ) );

        assert( sizeOfStubData >= 0 );

        std::vector <unsigned char> progData( sizeOfStubData );
        {
            size_t progReadCount = peStream->Read( progData.data(), 1, sizeOfStubData );

            if ( progReadCount != sizeOfStubData )
            {
                throw std::exception( "invalid MSDOS stub" );
            }
        }

        dos.progData = std::move( progData );
    }

    // Go on to the PE header.
    int seekSuccess = peStream->SeekNative( dosHeader.e_lfanew, SEEK_SET );

    assert( seekSuccess == 0 );

    // Read PE information.
    IMAGE_PE_HEADER peHeader;

    bool couldReadPE = peStream->ReadStruct( peHeader );

    if ( couldReadPE == false )
        throw std::exception( "failed to read PE NT headers" );

    // Validate some things.
    if ( peHeader.Signature != 'EP' )
        throw std::exception( "invalid PE header signature" );

    // We only support machine types we know.
    WORD machineType = peHeader.FileHeader.Machine;

    bool is64Bit;
    {
        if ( machineType == IMAGE_FILE_MACHINE_I386 )
        {
            is64Bit = false;
        }
        else if ( machineType == IMAGE_FILE_MACHINE_AMD64 )
        {
            is64Bit = true;
        }
        else
        {
            throw std::exception( "unsupported PE file machine type" );
        }
    }

    // Store stuff.
    PEFileInfo peInfo;
    peInfo.machine_id = machineType;
    peInfo.timeDateStamp = peHeader.FileHeader.TimeDateStamp;
    
    // Flags that matter.
    WORD chars = peHeader.FileHeader.Characteristics;

    peInfo.isExecutableImage = ( chars & IMAGE_FILE_EXECUTABLE_IMAGE ) != 0;
    peInfo.hasLocalSymbols = ( chars & IMAGE_FILE_LOCAL_SYMS_STRIPPED ) == 0;
    peInfo.hasAggressiveTrim = ( chars & IMAGE_FILE_AGGRESIVE_WS_TRIM ) != 0;
    peInfo.largeAddressAware = ( chars & IMAGE_FILE_LARGE_ADDRESS_AWARE ) != 0;
    peInfo.bytesReversedLO = ( chars & IMAGE_FILE_BYTES_REVERSED_LO ) != 0;
    peInfo.removableRunFromSwap = ( chars & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP ) != 0;
    peInfo.netRunFromSwap = ( chars & IMAGE_FILE_NET_RUN_FROM_SWAP ) != 0;
    peInfo.isSystemFile = ( chars & IMAGE_FILE_SYSTEM ) != 0;
    peInfo.isDLL = ( chars & IMAGE_FILE_DLL ) != 0;
    peInfo.upSystemOnly = ( chars & IMAGE_FILE_UP_SYSTEM_ONLY ) != 0;
    peInfo.bytesReversedHI = ( chars & IMAGE_FILE_BYTES_REVERSED_HI ) != 0;

    // Other properties should be respected during parsing.
    bool hasRelocsStripped = ( chars & IMAGE_FILE_RELOCS_STRIPPED ) != 0;
    bool hasLineNumsStripped = ( chars & IMAGE_FILE_LINE_NUMS_STRIPPED ) != 0;
    bool hasLocalSymsStripped = ( chars & IMAGE_FILE_LOCAL_SYMS_STRIPPED ) != 0;
    bool hasDebugStripped = ( chars & IMAGE_FILE_DEBUG_STRIPPED ) != 0;
    
    // Check if the 32bit flag matches what we know.
    {
        bool flag_is32bit = ( chars & IMAGE_FILE_32BIT_MACHINE ) != 0;

        if ( flag_is32bit && is64Bit )
        {
            throw std::exception( "charactersitics define 32bit PE file while machine type says otherwise" );
        }
    }

    // Remember that we were here.
    fsOffsetNumber_t optionalHeaderOffset = peStream->TellNative();

    // We should definately try reading symbol information.
    DWORD symbolOffset = peHeader.FileHeader.PointerToSymbolTable;
    DWORD numOfSymbols = peHeader.FileHeader.NumberOfSymbols;

    if ( symbolOffset != 0 && numOfSymbols != 0 )
    {
        // Try locating the symbols and read them!
        peStream->SeekNative( symbolOffset, SEEK_SET );

        // Do it meow.
        throw std::exception( "unsupported COFF debug information format" );

        // Move back to the optional header we should read next.
        peStream->SeekNative( optionalHeaderOffset, SEEK_SET );
    }

    WORD numSections = peHeader.FileHeader.NumberOfSections;

    // Verify that we have a proper optional header size.
    WORD optHeaderSize = peHeader.FileHeader.SizeOfOptionalHeader;

    bool hasValidOptionalHeaderSize;

    if ( is64Bit )
    {
        hasValidOptionalHeaderSize = ( optHeaderSize == sizeof(IMAGE_OPTIONAL_HEADER64) );
    }
    else
    {
        hasValidOptionalHeaderSize = ( optHeaderSize == sizeof(IMAGE_OPTIONAL_HEADER32) );
    }

    if ( !hasValidOptionalHeaderSize )
    {
        throw std::exception( "invalid optional header size" );
    }

    // Let's read our optional header!
    PEOptHeader peOpt;
    
    // We have to extract this.
    IMAGE_DATA_DIRECTORY dataDirs[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

    WORD dllChars;

    if ( is64Bit )
    {
        IMAGE_OPTIONAL_HEADER64 optHeader;

        bool readOptHeader = peStream->ReadStruct( optHeader );

        if ( !readOptHeader )
            throw std::exception( "reading optional header failed" );

        // Verify magic number.
        if ( optHeader.Magic != 0x010B )
            throw std::exception( "invalid optional header magic number" );

        // Fetch the information.
        // We will store the pointers in 64bit format regardless of the machine type.
        // This is to keep a simple data layout.
        peOpt.majorLinkerVersion = optHeader.MajorLinkerVersion;
        peOpt.minorLinkerVersion = optHeader.MinorLinkerVersion;
        peOpt.sizeOfCode = optHeader.SizeOfCode;
        peOpt.sizeOfInitializedData = optHeader.SizeOfInitializedData;
        peOpt.sizeOfUninitializedData = optHeader.SizeOfUninitializedData;
        peOpt.addressOfEntryPoint = optHeader.AddressOfEntryPoint;
        peOpt.baseOfCode = optHeader.BaseOfCode;
        peOpt.baseOfData = 0;   // not available.
        peOpt.imageBase = optHeader.ImageBase;
        peOpt.sectionAlignment = optHeader.SectionAlignment;
        peOpt.fileAlignment = optHeader.FileAlignment;
        peOpt.majorOSVersion = optHeader.MajorOperatingSystemVersion;
        peOpt.minorOSVersion = optHeader.MinorOperatingSystemVersion;
        peOpt.majorImageVersion = optHeader.MajorImageVersion;
        peOpt.minorImageVersion = optHeader.MinorImageVersion;
        peOpt.majorSubsysVersion = optHeader.MajorSubsystemVersion;
        peOpt.minorSubsysVersion = optHeader.MinorSubsystemVersion;
        peOpt.win32VersionValue = optHeader.Win32VersionValue;
        peOpt.sizeOfImage = optHeader.SizeOfImage;
        peOpt.sizeOfHeaders = optHeader.SizeOfHeaders;
        peOpt.checkSum = optHeader.CheckSum;
        peOpt.subsys = optHeader.Subsystem;
        dllChars = optHeader.DllCharacteristics;
        peOpt.sizeOfStackReserve = optHeader.SizeOfStackReserve;
        peOpt.sizeOfStackCommit = optHeader.SizeOfStackCommit;
        peOpt.sizeOfHeapReserve = optHeader.SizeOfHeapReserve;
        peOpt.sizeOfHeapCommit = optHeader.SizeOfHeapCommit;
        peOpt.loaderFlags = optHeader.LoaderFlags;

        // Extract the data directory information.
        DWORD numDataDirs = optHeader.NumberOfRvaAndSizes;

        if ( numDataDirs != IMAGE_NUMBEROF_DIRECTORY_ENTRIES )
            throw std::exception( "invalid number of PE directory entries" );

        memcpy( dataDirs, optHeader.DataDirectory, sizeof( dataDirs ) );
    }
    else
    {
        IMAGE_OPTIONAL_HEADER32 optHeader;

        bool readOptHeader = peStream->ReadStruct( optHeader );

        if ( !readOptHeader )
            throw std::exception( "reading optional header failed" );

        // Verify magic number.
        if ( optHeader.Magic != 0x010B )
            throw std::exception( "invalid optional header magic number" );

        // Fetch the information.
        // We will store the pointers in 64bit format regardless of the machine type.
        // This is to keep a simple data layout.
        peOpt.majorLinkerVersion = optHeader.MajorLinkerVersion;
        peOpt.minorLinkerVersion = optHeader.MinorLinkerVersion;
        peOpt.sizeOfCode = optHeader.SizeOfCode;
        peOpt.sizeOfInitializedData = optHeader.SizeOfInitializedData;
        peOpt.sizeOfUninitializedData = optHeader.SizeOfUninitializedData;
        peOpt.addressOfEntryPoint = optHeader.AddressOfEntryPoint;
        peOpt.baseOfCode = optHeader.BaseOfCode;
        peOpt.baseOfData = optHeader.BaseOfData;
        peOpt.imageBase = optHeader.ImageBase;
        peOpt.sectionAlignment = optHeader.SectionAlignment;
        peOpt.fileAlignment = optHeader.FileAlignment;
        peOpt.majorOSVersion = optHeader.MajorOperatingSystemVersion;
        peOpt.minorOSVersion = optHeader.MinorOperatingSystemVersion;
        peOpt.majorImageVersion = optHeader.MajorImageVersion;
        peOpt.minorImageVersion = optHeader.MinorImageVersion;
        peOpt.majorSubsysVersion = optHeader.MajorSubsystemVersion;
        peOpt.minorSubsysVersion = optHeader.MinorSubsystemVersion;
        peOpt.win32VersionValue = optHeader.Win32VersionValue;
        peOpt.sizeOfImage = optHeader.SizeOfImage;
        peOpt.sizeOfHeaders = optHeader.SizeOfHeaders;
        peOpt.checkSum = optHeader.CheckSum;
        peOpt.subsys = optHeader.Subsystem;
        dllChars = optHeader.DllCharacteristics;
        peOpt.sizeOfStackReserve = optHeader.SizeOfStackReserve;
        peOpt.sizeOfStackCommit = optHeader.SizeOfStackCommit;
        peOpt.sizeOfHeapReserve = optHeader.SizeOfHeapReserve;
        peOpt.sizeOfHeapCommit = optHeader.SizeOfHeapCommit;
        peOpt.loaderFlags = optHeader.LoaderFlags;

        // Extract the data directory information.
        DWORD numDataDirs = optHeader.NumberOfRvaAndSizes;

        if ( numDataDirs != IMAGE_NUMBEROF_DIRECTORY_ENTRIES )
            throw std::exception( "invalid number of PE directory entries" );

        // Extract the data directory information.
        memcpy( dataDirs, optHeader.DataDirectory, sizeof( dataDirs ) );
    }

    // Process the DLL flags and store them sensibly.
    peOpt.dll_supportsHighEntropy = ( dllChars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA ) != 0;
    peOpt.dll_hasDynamicBase = ( dllChars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ) != 0;
    peOpt.dll_forceIntegrity = ( dllChars & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY ) != 0;
    peOpt.dll_nxCompat = ( dllChars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT ) != 0;
    peOpt.dll_noIsolation = ( dllChars & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ) != 0;
    peOpt.dll_noSEH = ( dllChars & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ) != 0;
    peOpt.dll_noBind = ( dllChars & IMAGE_DLLCHARACTERISTICS_NO_BIND ) != 0;
    peOpt.dll_appContainer = ( dllChars & IMAGE_DLLCHARACTERISTICS_APPCONTAINER ) != 0;
    peOpt.dll_wdmDriver = ( dllChars & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER ) != 0;
    peOpt.dll_guardCF = ( dllChars & IMAGE_DLLCHARACTERISTICS_GUARD_CF ) != 0;
    peOpt.dll_termServAware = ( dllChars & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE ) != 0;

    // Should handle data sections first because data directories depend on them.
    for ( size_t n = 0; n < numSections; n++ )
    {
        IMAGE_SECTION_HEADER sectHeader;

        bool readSection = peStream->ReadStruct( sectHeader );

        if ( !readSection )
            throw std::exception( "failed to read PE section header" );

        fsOffsetNumber_t sectHeaderOff = peStream->TellNative();

        PESection section;
        section.shortName = std::string( (const char*)sectHeader.Name, strnlen( (const char*)sectHeader.Name, IMAGE_SIZEOF_SHORT_NAME ) );
        section.physAddr = sectHeader.Misc.PhysicalAddress;
        section.virtualAddr = sectHeader.VirtualAddress;
        
        // Save characteristics flags.
        DWORD schars = sectHeader.Characteristics;

        section.sect_hasNoPadding = ( schars & IMAGE_SCN_TYPE_NO_PAD ) != 0;
        section.sect_containsCode = ( schars & IMAGE_SCN_CNT_CODE ) != 0;
        section.sect_containsInitData = ( schars & IMAGE_SCN_CNT_INITIALIZED_DATA ) != 0;
        section.sect_containsUninitData = ( schars & IMAGE_SCN_CNT_UNINITIALIZED_DATA ) != 0;
        section.sect_link_other = ( schars & IMAGE_SCN_LNK_OTHER ) != 0;
        section.sect_link_info = ( schars & IMAGE_SCN_LNK_INFO ) != 0;
        section.sect_link_remove = ( schars & IMAGE_SCN_LNK_REMOVE ) != 0;
        section.sect_link_comdat = ( schars & IMAGE_SCN_LNK_COMDAT ) != 0;
        section.sect_noDeferSpecExcepts = ( schars & IMAGE_SCN_NO_DEFER_SPEC_EXC ) != 0;
        section.sect_gprel = ( schars & IMAGE_SCN_GPREL ) != 0;
        section.sect_mem_farData = ( schars & IMAGE_SCN_MEM_FARDATA ) != 0;
        section.sect_mem_purgeable = ( schars & IMAGE_SCN_MEM_PURGEABLE ) != 0;
        section.sect_mem_16bit = ( schars & IMAGE_SCN_MEM_16BIT ) != 0;
        section.sect_mem_locked = ( schars & IMAGE_SCN_MEM_LOCKED ) != 0;
        section.sect_mem_preload = ( schars & IMAGE_SCN_MEM_PRELOAD ) != 0;
        
        // Parse the alignment information out of the chars.
        PESection::eAlignment alignNum = (PESection::eAlignment)( ( schars & 0x00F00000 ) >> 20 );
        section.sect_alignment = alignNum;

        section.sect_link_nreloc_ovfl = ( schars & IMAGE_SCN_LNK_NRELOC_OVFL ) != 0;
        section.sect_mem_discardable = ( schars & IMAGE_SCN_MEM_DISCARDABLE ) != 0;
        section.sect_mem_not_cached = ( schars & IMAGE_SCN_MEM_NOT_CACHED ) != 0;
        section.sect_mem_not_paged = ( schars & IMAGE_SCN_MEM_NOT_PAGED ) != 0;
        section.sect_mem_shared = ( schars & IMAGE_SCN_MEM_SHARED ) != 0;
        section.sect_mem_execute = ( schars & IMAGE_SCN_MEM_EXECUTE ) != 0;
        section.sect_mem_read = ( schars & IMAGE_SCN_MEM_READ ) != 0;
        section.sect_mem_write = ( schars & IMAGE_SCN_MEM_WRITE ) != 0;

        // Read raw data.
        {
            peStream->SeekNative( sectHeader.PointerToRawData, SEEK_SET );

            std::vector <unsigned char> rawdata( sectHeader.SizeOfRawData );

            size_t actualReadCount = peStream->Read( rawdata.data(), 1, sectHeader.SizeOfRawData );

            if ( actualReadCount != sectHeader.SizeOfRawData )
                throw std::exception( "failed to read PE section raw data" );

            section.rawdata = std::move( rawdata );
        }

        // Read relocation information.
        {
            peStream->SeekNative( sectHeader.PointerToRelocations, SEEK_SET );

            std::vector <PERelocation> relocs;
            relocs.reserve( sectHeader.NumberOfRelocations );

            for ( DWORD n = 0; n < sectHeader.NumberOfRelocations; n++ )
            {
                IMAGE_RELOCATION relocEntry;

                bool readReloc = peStream->ReadStruct( relocEntry );

                if ( !readReloc )
                    throw std::exception( "failed to read PE section relocation information" );

                // Store it.
                PERelocation data;
                data.virtAddr = relocEntry.VirtualAddress;
                data.symbolTableIndex = relocEntry.SymbolTableIndex;
                data.type = relocEntry.Type;

                relocs.push_back( std::move( data ) );
            }

            section.relocations = std::move( relocs );
        }

        // Read linenumber information.
        {
            peStream->SeekNative( sectHeader.PointerToLinenumbers, SEEK_SET );

            std::vector <PELinenumber> linenums;
            linenums.reserve( sectHeader.NumberOfLinenumbers );

            for ( size_t n = 0; n < sectHeader.NumberOfLinenumbers; n++ )
            {
                IMAGE_LINENUMBER lineInfo;

                bool gotLinenum = peStream->ReadStruct( lineInfo );

                if ( !gotLinenum )
                    throw std::exception( "failed to read PE linenumber info" );

                PELinenumber line;
                line.symTableIndex = lineInfo.Type.SymbolTableIndex;
                line.number = lineInfo.Linenumber;

                linenums.push_back( std::move( line ) );
            }

            section.linenumbers = std::move( linenums );
        }

        // Setup the meta-data.
        section.isFinal = true;     // sections on-file are important to the program integrity.

        // We need to set our stream back on track.
        peStream->SeekNative( sectHeaderOff, SEEK_SET );

        // Remember this section.
        sections.push_back( std::move( section ) );
    }

    // That is the end of the executable data reading.
    // Now we dispatch onto the data directories, which base on things found inside the sections.

    // Load directory information now.
    // We decide to create meta-data structs out of them.
    // If possible, delete the section that contains the meta-data.
    // * EXPORT INFORMATION.
    PEExportDir expInfo;
    {
        const IMAGE_DATA_DIRECTORY& expDirEntry = dataDirs[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

        if ( expDirEntry.VirtualAddress != 0 )
        {
            const IMAGE_EXPORT_DIRECTORY *expDirPtr = (const IMAGE_EXPORT_DIRECTORY*)GetPEDataPointer( sections, expDirEntry.VirtualAddress, expDirEntry.Size );

            if ( !expDirPtr )
                throw std::exception( "invalid PE export directory" );

            const IMAGE_EXPORT_DIRECTORY& expEntry = *expDirPtr;

            // Store the usual tidbits.
            expInfo.chars = expEntry.Characteristics;
            expInfo.timeDateStamp = expEntry.TimeDateStamp;
            expInfo.majorVersion = expEntry.MajorVersion;
            expInfo.minorVersion = expEntry.MinorVersion;
            expInfo.base = expEntry.Base;

            // Read the name.
            const char *nameOffset = (const char*)GetPEDataPointer( sections, expEntry.Name, 1 );

            if ( !nameOffset )
                throw std::exception( "failed to read PE export directory name" );

            expInfo.name = nameOffset;

            // Allocate functions.
            if ( expEntry.AddressOfFunctions != 0 )
            {
                std::vector <PEExportDir::func> funcs;
                funcs.reserve( expEntry.NumberOfFunctions );

                std::uint64_t tabSize;

                if ( is64Bit )
                {
                    tabSize = ( sizeof( ULONGLONG ) * expEntry.NumberOfFunctions );
                }
                else
                {
                    tabSize = ( sizeof( DWORD ) * expEntry.NumberOfFunctions );
                }

                const void *addrPtr =
                    GetPEDataPointer(
                        sections,
                        expEntry.AddressOfFunctions, tabSize
                    );

                if ( !addrPtr )
                {
                    throw std::exception( "failed to get PE export info function entries" );
                }

                for ( DWORD n = 0; n < expEntry.NumberOfFunctions; n++ )
                {
                    PEExportDir::func fentry;
                    fentry.hasOrdinal = false;
                    fentry.ordinal = 0;
                    {
                        const DWORD *funcEntry = ( (const DWORD*)addrPtr + n );

                        fentry.address = *funcEntry;
                    }

                    funcs.push_back( std::move( fentry ) );
                }

                // Read names and ordinals, if available.
                if ( expEntry.AddressOfNames != 0 )
                {
                    const DWORD *namePtrs = (const DWORD*)GetPEDataPointer( sections, expEntry.AddressOfNames, expEntry.NumberOfNames * sizeof(DWORD) );

                    if ( !namePtrs )
                        throw std::exception( "failed to get PE export directory function name list" );

                    for ( DWORD n = 0; n < expEntry.NumberOfNames && n < expEntry.NumberOfFunctions; n++ )
                    {
                        // Retrieve the real name ptr.
                        const char *realNamePtr = (const char*)GetPEDataPointer( sections, namePtrs[ n ], 1 );

                        if ( !realNamePtr )
                            throw std::exception( "failed to get PE export directory function name ptr" );

                        PEExportDir::func& fentry = funcs[ n ];

                        fentry.name = realNamePtr;
                    }
                }

                if ( expEntry.AddressOfNameOrdinals != 0 )
                {
                    const WORD *ordPtr = (const WORD*)GetPEDataPointer( sections, expEntry.AddressOfNameOrdinals, expEntry.NumberOfNames * sizeof(WORD) );

                    if ( !ordPtr )
                        throw std::exception( "failed to get PE export directory function ordinals" );

                    for ( DWORD n = 0; n < expEntry.NumberOfNames && n < expEntry.NumberOfFunctions; n++ )
                    {
                        PEExportDir::func& fentry = funcs[ n ];

                        fentry.ordinal = ordPtr[ n ];
                        fentry.hasOrdinal = true;
                    }
                }

                expInfo.functions = std::move( funcs );
            }

            // We got the export directory! :)
        }
    }

    // * IMPORT directory.
    std::vector <PEImportDesc> impDescs;
    {
        const IMAGE_DATA_DIRECTORY& impDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

        if ( impDir.VirtualAddress != 0 )
        {
            const IMAGE_IMPORT_DESCRIPTOR *importDescs = (const IMAGE_IMPORT_DESCRIPTOR*)GetPEDataPointer( sections, impDir.VirtualAddress, impDir.Size );

            if ( !importDescs )
                throw std::exception( "failed to read PE import descriptors" );

            // Read all the descriptors.
            const DWORD numDescriptors = ( impDir.Size / sizeof( IMAGE_IMPORT_DESCRIPTOR ) );

            impDescs.reserve( numDescriptors );

            for ( DWORD n = 0; n < numDescriptors; n++ )
            {
                const IMAGE_IMPORT_DESCRIPTOR& importInfo = importDescs[ n ];

                // TODO: allow secure bounded parsing of PE files, so we check for
                // violations of PE rules and reject those files.

                // By definition, an IMAGE_IMPORT_DESCRIPTOR with all entries zero
                // is the end of the table.
                if ( importInfo.Characteristics == 0 &&
                     importInfo.TimeDateStamp == 0 &&
                     importInfo.ForwarderChain == 0 &&
                     importInfo.Name == 0 && 
                     importInfo.FirstThunk == 0 )
                {
                    break;
                }

                PEImportDesc impDesc;

                // Get the function names (with their ordinals).
                if ( importInfo.Characteristics != 0 )
                {
                    const DWORD *importNameArray =
                        (const DWORD*)GetPEDataPointer( sections, importInfo.Characteristics, 1 );

                    if ( !importNameArray )
                        throw std::exception( "failed to read PE import function name array" );

                    // The array goes on until a terminating NULL.
                    decltype( impDesc.funcs ) funcs;

                    while ( true )
                    {
                        // TODO: in PE32+ images, we need to read 64bit numbers here.

                        const DWORD importNameRVA = *importNameArray++;

                        if ( !importNameRVA )
                            break;

                        PEImportDesc::importFunc funcInfo;

                        // Check if this is an ordinal import or a named import.
                        bool isOrdinalImport = ( importNameRVA & 0x80000000 ) != 0;

                        if ( isOrdinalImport )
                        {
                            funcInfo.ordinal_hint = ( importNameRVA & 0x7FFFFFFF );
                        }
                        else
                        {
                            const IMAGE_IMPORT_BY_NAME *importName = (const IMAGE_IMPORT_BY_NAME*)GetPEDataPointer( sections, importNameRVA, sizeof( IMAGE_IMPORT_BY_NAME ) );

                            if ( !importName )
                                throw std::exception( "failed to read PE import function name entry" );

                            funcInfo.ordinal_hint = importName->Hint;
                            funcInfo.name = importName->Name;
                        }
                        funcInfo.isOrdinalImport = isOrdinalImport;

                        funcs.push_back( std::move( funcInfo ) );
                    }

                    impDesc.funcs = std::move( funcs );
                }

                // Store the DLL name we import from.
                {
                    const char *dllNamePtr = (const char*)GetPEDataPointer( sections, importInfo.Name, 1 );

                    if ( !dllNamePtr )
                        throw std::exception( "failed to read PE import desc DLL name" );

                    impDesc.DLLName = dllNamePtr;
                }

                impDesc.firstThunkOffset = importInfo.FirstThunk;

                // Store this import desc.
                impDescs.push_back( std::move( impDesc ) );

                // Done with this import desc!
            }

            // Done with all imports.
        }
    }

    // * Resources.
    PEResourceDir resourceRoot( L"" );
    {
        const IMAGE_DATA_DIRECTORY& resDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_RESOURCE ];

        if ( resDir.VirtualAddress != 0 )
        {
            const PEStructures::IMAGE_RESOURCE_DIRECTORY *resRootDir = (const PEStructures::IMAGE_RESOURCE_DIRECTORY*)GetPEDataPointer( sections, resDir.VirtualAddress, resDir.Size );

            if ( !resRootDir )
                throw std::exception( "invalid PE resource root" );

            resourceRoot = LoadResourceDirectory( resRootDir, sections, std::wstring(), resRootDir );
        }
    }

    // * Exception Information.
    std::vector <PERuntimeFunction> exceptRFs;
    {
        const IMAGE_DATA_DIRECTORY& rtDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ];

        if ( rtDir.VirtualAddress != 0 )
        {
            // TODO: apparently exception data is machine dependent, so we should
            // deserialize this in a special way depending on machine_id.
            // (currently we specialize on x86/AMD64)

            const IMAGE_RUNTIME_FUNCTION_ENTRY *rtFuncs = (const IMAGE_RUNTIME_FUNCTION_ENTRY*)GetPEDataPointer( sections, rtDir.VirtualAddress, rtDir.Size );

            if ( !rtFuncs )
                throw std::exception( "invalid PE exception directory" );

            const DWORD numFuncs = ( rtDir.Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY ) );

            exceptRFs.reserve( numFuncs );

            for ( size_t n = 0; n < numFuncs; n++ )
            {
                const IMAGE_RUNTIME_FUNCTION_ENTRY& func = rtFuncs[ n ];

                PERuntimeFunction funcInfo;
                funcInfo.beginAddr = func.BeginAddress;
                funcInfo.endAddr = func.EndAddress;
                funcInfo.unwindInfo = func.UnwindData;

                exceptRFs.push_back( std::move( funcInfo ) );
            }
        }
    }

    // * Security cookie.
    PESecurity security;
    {
        const IMAGE_DATA_DIRECTORY& secDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_SECURITY ];

        security.secDataOffset = secDir.VirtualAddress;
        security.secDataSize = secDir.Size;
        // For now we trust that it is valid.
    }

    // * BASE RELOC.
    std::vector <PEBaseReloc> baseRelocs;
    {
        const IMAGE_DATA_DIRECTORY& baserelocDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

        if ( baserelocDir.VirtualAddress != 0 )
        {
            const DWORD sizeRelocations = baserelocDir.Size;

            const char *baseRelocDescs = (const char*)GetPEDataPointer( sections, baserelocDir.VirtualAddress, sizeRelocations );

            if ( !baseRelocDescs )
                throw std::exception( "invalid PE base relocation directory" );

            // We read relocation data until we are at the end of the directory.
            size_t currentRelocOffset = 0;

            while ( currentRelocOffset < sizeRelocations )
            {
                // Get current relocation.
                const IMAGE_BASE_RELOCATION *baseReloc = (const IMAGE_BASE_RELOCATION*)( baseRelocDescs + currentRelocOffset );

                // Store it.
                const size_t blockSize = baseReloc->SizeOfBlock;

                // Validate the blockSize.
                if ( blockSize < sizeof(IMAGE_BASE_RELOCATION) )
                    throw std::exception( "malformed PE base relocation sub block" );

                // Subtract the meta-data size.
                const size_t entryBlockSize = ( blockSize - sizeof(IMAGE_BASE_RELOCATION) );
                {
                    PEBaseReloc info;
                    info.offsetOfReloc = baseReloc->VirtualAddress;

                    // Read all relocations.
                    const DWORD numRelocItems = ( entryBlockSize / sizeof( PEStructures::IMAGE_BASE_RELOC_TYPE_ITEM ) );

                    info.items.reserve( numRelocItems );

                    const PEStructures::IMAGE_BASE_RELOC_TYPE_ITEM *relocItems =
                        (PEStructures::IMAGE_BASE_RELOC_TYPE_ITEM*)( baseReloc + 1 );

                    for ( size_t n = 0; n < numRelocItems; n++ )
                    {
                        const PEStructures::IMAGE_BASE_RELOC_TYPE_ITEM& reloc = relocItems[ n ];

                        PEBaseReloc::item itemInfo;
                        itemInfo.type = reloc.type;
                        itemInfo.offset = reloc.offset;

                        info.items.push_back( std::move( itemInfo ) );
                    }

                    // Remember us.
                    baseRelocs.push_back( std::move( info ) );
                }

                // Jump to next relocation.
                currentRelocOffset += blockSize;
            }

            // Done reading all base relocations.
        }
    }

    // * DEBUG.
    PEDebug debugInfo;
    {
        const IMAGE_DATA_DIRECTORY& debugDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_DEBUG ];

        if ( debugDir.VirtualAddress != 0 )
        {
            const IMAGE_DEBUG_DIRECTORY *debugEntry = (const IMAGE_DEBUG_DIRECTORY*)GetPEDataPointer( sections, debugDir.VirtualAddress, debugDir.Size );

            if ( !debugEntry )
                throw std::exception( "invalid PE debug directory" );

            // We store this debug information entry.
            // Debug information can be of many types and we cannot ever handle all of them!
            debugInfo.characteristics = debugEntry->Characteristics;
            debugInfo.timeDateStamp = debugEntry->TimeDateStamp;
            debugInfo.majorVer = debugEntry->MajorVersion;
            debugInfo.minorVer = debugEntry->MinorVersion;
            debugInfo.type = debugEntry->Type;
            debugInfo.sizeOfData = debugEntry->SizeOfData;
            debugInfo.addrOfRawData = debugEntry->AddressOfRawData;
            debugInfo.ptrToRawData = debugEntry->PointerToRawData;

            // TODO: think of a way to parse this information.
        }
    }

    // * ARCHITECTURE.
    {
        // Reserved. Must be zero.
    }

    // * GLOBAL PTR.
    PEGlobalPtr globalPtr;
    {
        const IMAGE_DATA_DIRECTORY& globptrData = dataDirs[ IMAGE_DIRECTORY_ENTRY_GLOBALPTR ];

        globalPtr.ptrOffset = globptrData.VirtualAddress;
    }

    // * THREAD LOCAL STORAGE.
    PEThreadLocalStorage tlsInfo;
    {
        const IMAGE_DATA_DIRECTORY& tlsDataDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_TLS ];

        if ( tlsDataDir.VirtualAddress != 0 )
        {
            // It depends on the architecture what directory type we encounter here.
            if ( is64Bit )
            {
                const IMAGE_TLS_DIRECTORY64 *tlsDir = (const IMAGE_TLS_DIRECTORY64*)GetPEDataPointer( sections, tlsDataDir.VirtualAddress, tlsDataDir.Size );

                if ( !tlsDir )
                    throw std::exception( "invalid PE thread-local-storage directory" );

                tlsInfo.startOfRawData = tlsDir->StartAddressOfRawData;
                tlsInfo.endOfRawData = tlsDir->EndAddressOfRawData;
                tlsInfo.addressOfIndices = tlsDir->AddressOfIndex;
                tlsInfo.addressOfCallbacks = tlsDir->AddressOfCallBacks;
                tlsInfo.sizeOfZeroFill = tlsDir->SizeOfZeroFill;
                tlsInfo.characteristics = tlsDir->Characteristics;
            }
            else
            {
                const IMAGE_TLS_DIRECTORY32 *tlsDir = (const IMAGE_TLS_DIRECTORY32*)GetPEDataPointer( sections, tlsDataDir.VirtualAddress, tlsDataDir.Size );

                if ( !tlsDir )
                    throw std::exception( "invalid PE thread-local-storage directory" );

                tlsInfo.startOfRawData = tlsDir->StartAddressOfRawData;
                tlsInfo.endOfRawData = tlsDir->EndAddressOfRawData;
                tlsInfo.addressOfIndices = tlsDir->AddressOfIndex;
                tlsInfo.addressOfCallbacks = tlsDir->AddressOfCallBacks;
                tlsInfo.sizeOfZeroFill = tlsDir->SizeOfZeroFill;
                tlsInfo.characteristics = tlsDir->Characteristics;
            }
        }
    }

    // * LOAD CONFIG.
    PELoadConfig loadConfig;
    {
        const IMAGE_DATA_DIRECTORY& lcfgDataDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG ];

        if ( lcfgDataDir.VirtualAddress != 0 )
        {
            if ( is64Bit )
            {
                const IMAGE_LOAD_CONFIG_DIRECTORY64 *lcfgDir = (const IMAGE_LOAD_CONFIG_DIRECTORY64*)GetPEDataPointer( sections, lcfgDataDir.VirtualAddress, lcfgDataDir.Size );

                if ( !lcfgDir )
                    throw std::exception( "invalid PE load config directory" );

                loadConfig.timeDateStamp = lcfgDir->TimeDateStamp;
                loadConfig.majorVersion = lcfgDir->MajorVersion;
                loadConfig.minorVersion = lcfgDir->MinorVersion;
                loadConfig.globFlagsClear = lcfgDir->GlobalFlagsClear;
                loadConfig.globFlagsSet = lcfgDir->GlobalFlagsSet;
                loadConfig.critSecDefTimeOut = lcfgDir->CriticalSectionDefaultTimeout;
                loadConfig.deCommitFreeBlockThreshold = lcfgDir->DeCommitFreeBlockThreshold;
                loadConfig.deCommitTotalFreeThreshold = lcfgDir->DeCommitTotalFreeThreshold;
                loadConfig.lockPrefixTable = lcfgDir->LockPrefixTable;
                loadConfig.maxAllocSize = lcfgDir->MaximumAllocationSize;
                loadConfig.virtualMemoryThreshold = lcfgDir->VirtualMemoryThreshold;
                loadConfig.processAffinityMask = lcfgDir->ProcessAffinityMask;
                loadConfig.processHeapFlags = lcfgDir->ProcessHeapFlags;
                loadConfig.CSDVersion = lcfgDir->CSDVersion;
                loadConfig.reserved1 = lcfgDir->Reserved1;
                loadConfig.editList = lcfgDir->EditList;
                loadConfig.securityCookie = lcfgDir->SecurityCookie;
                loadConfig.SEHandlerTable = lcfgDir->SEHandlerTable;
                loadConfig.SEHandlerCount = lcfgDir->SEHandlerCount;
                loadConfig.guardCFCheckFunctionPtr = lcfgDir->GuardCFCheckFunctionPointer;
                loadConfig.reserved2 = lcfgDir->Reserved2;
                loadConfig.guardCFFunctionTable = lcfgDir->GuardCFFunctionTable;
                loadConfig.guardCFFunctionCount = lcfgDir->GuardCFFunctionCount;
                loadConfig.guardFlags = lcfgDir->GuardFlags;
            }
            else
            {
                const IMAGE_LOAD_CONFIG_DIRECTORY32 *lcfgDir = (const IMAGE_LOAD_CONFIG_DIRECTORY32*)GetPEDataPointer( sections, lcfgDataDir.VirtualAddress, lcfgDataDir.Size );

                if ( !lcfgDir )
                    throw std::exception( "invalid PE load config directory" );

                loadConfig.timeDateStamp = lcfgDir->TimeDateStamp;
                loadConfig.majorVersion = lcfgDir->MajorVersion;
                loadConfig.minorVersion = lcfgDir->MinorVersion;
                loadConfig.globFlagsClear = lcfgDir->GlobalFlagsClear;
                loadConfig.globFlagsSet = lcfgDir->GlobalFlagsSet;
                loadConfig.critSecDefTimeOut = lcfgDir->CriticalSectionDefaultTimeout;
                loadConfig.deCommitFreeBlockThreshold = lcfgDir->DeCommitFreeBlockThreshold;
                loadConfig.deCommitTotalFreeThreshold = lcfgDir->DeCommitTotalFreeThreshold;
                loadConfig.lockPrefixTable = lcfgDir->LockPrefixTable;
                loadConfig.maxAllocSize = lcfgDir->MaximumAllocationSize;
                loadConfig.virtualMemoryThreshold = lcfgDir->VirtualMemoryThreshold;
                loadConfig.processAffinityMask = lcfgDir->ProcessAffinityMask;
                loadConfig.processHeapFlags = lcfgDir->ProcessHeapFlags;
                loadConfig.CSDVersion = lcfgDir->CSDVersion;
                loadConfig.reserved1 = lcfgDir->Reserved1;
                loadConfig.editList = lcfgDir->EditList;
                loadConfig.securityCookie = lcfgDir->SecurityCookie;
                loadConfig.SEHandlerTable = lcfgDir->SEHandlerTable;
                loadConfig.SEHandlerCount = lcfgDir->SEHandlerCount;
                loadConfig.guardCFCheckFunctionPtr = lcfgDir->GuardCFCheckFunctionPointer;
                loadConfig.reserved2 = lcfgDir->Reserved2;
                loadConfig.guardCFFunctionTable = lcfgDir->GuardCFFunctionTable;
                loadConfig.guardCFFunctionCount = lcfgDir->GuardCFFunctionCount;
                loadConfig.guardFlags = lcfgDir->GuardFlags;
            }
        }
    }

    // * BOUND IMPORT DIR.
    std::vector <PEBoundImports> boundImports;
    {
        const IMAGE_DATA_DIRECTORY& boundDataDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ];

        if ( boundDataDir.VirtualAddress != 0 )
        {
            const DWORD numDescs = ( boundDataDir.Size / sizeof( DWORD ) );

            const DWORD *boundImportDescsOffsets = (const DWORD*)GetPEDataPointer( sections, boundDataDir.VirtualAddress, boundDataDir.Size );

            if ( !boundImportDescsOffsets )
                throw std::exception( "invalid PE bound imports directory" );

            // Read all bound import descriptors.
            for ( size_t n = 0; n < numDescs; n++ )
            {
                DWORD boundImportDescOffset = boundImportDescsOffsets[ n ];

                if ( boundImportDescOffset == NULL )
                    continue;

                const IMAGE_BOUND_IMPORT_DESCRIPTOR *desc = (const IMAGE_BOUND_IMPORT_DESCRIPTOR*)GetPEDataPointer( sections, boundImportDescOffset, sizeof( IMAGE_BOUND_IMPORT_DESCRIPTOR ) );

                if ( !desc )
                    throw std::exception( "failed to read PE bound imports directory entries" );

                PEBoundImports boundImport;
                boundImport.timeDateStamp = desc->TimeDateStamp;
                
                // Read the name.
                {
                    const char *namePtr = (const char*)( (const char*)desc + desc->OffsetModuleName );

                    boundImport.DLLName = namePtr;
                }

                // Get all modules that are bindings.
                {
                    const IMAGE_BOUND_FORWARDER_REF *boundRefs = (const IMAGE_BOUND_FORWARDER_REF*)( desc + 1 );

                    const size_t numForwarders = desc->NumberOfModuleForwarderRefs;

                    boundImport.bindings.reserve( numForwarders );

                    for ( size_t n = 0; n < numForwarders; n++ )
                    {
                        const IMAGE_BOUND_FORWARDER_REF& ref = boundRefs[ n ];

                        PEBoundImports::binding bindInfo;
                        bindInfo.timeDateStamp = ref.TimeDateStamp;
                        
                        // Read the name.
                        {
                            const char *modName = (const char*)( (const char*)&ref + ref.OffsetModuleName );

                            bindInfo.DLLName = modName;
                        }

                        bindInfo.reserved = ref.Reserved;

                        boundImport.bindings.push_back( std::move( bindInfo ) );
                    }
                }

                boundImports.push_back( std::move( boundImport ) );
            }

            // OK.
        }
    }

    // * IMPORT ADDRESS TABLE.
    // This is a pointer to the entire THUNK IAT array that is used in the IMPORTS DIRECTORY.
    // All thunks have to be contiguously allocated inside of this directory.
    PEThunkIATStore thunkIAT;
    {
        const IMAGE_DATA_DIRECTORY& iatDataDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_IAT ];

        thunkIAT.thunkDataStart = iatDataDir.VirtualAddress;
        thunkIAT.thunkDataSize = iatDataDir.Size;
    }

    // * DELAY LOAD IMPORTS.
    std::vector <PEDelayLoadDesc> delayLoads;
    {
        const IMAGE_DATA_DIRECTORY& delayDataDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT ];

        if ( delayDataDir.VirtualAddress != 0 )
        {
            const IMAGE_DELAYLOAD_DESCRIPTOR *delayLoadDescs = (const IMAGE_DELAYLOAD_DESCRIPTOR*)GetPEDataPointer( sections, delayDataDir.VirtualAddress, delayDataDir.Size );

            if ( !delayLoadDescs )
                throw std::exception( "invalid PE delay loads directory" );

            const DWORD numDelayLoads = ( delayDataDir.Size / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) );

            delayLoads.reserve( numDelayLoads );

            // Store all of the details.
            for ( size_t n = 0; n < numDelayLoads; n++ )
            {
                const IMAGE_DELAYLOAD_DESCRIPTOR& delayLoad = delayLoadDescs[ n ];

                PEDelayLoadDesc desc;
                desc.attrib = delayLoad.Attributes.AllAttributes;
                
                // Read DLL name.
                if ( delayLoad.DllNameRVA != 0 )
                {
                    const char *dllNamePtr = (const char*)GetPEDataPointer( sections, delayLoad.DllNameRVA, 1 );

                    if ( !dllNamePtr )
                        throw std::exception( "failed to read PE delay load desc DLL name" );

                    desc.DLLName = dllNamePtr;
                }

                desc.DLLHandleOffset = delayLoad.ModuleHandleRVA;
                desc.IATOffset = delayLoad.ImportAddressTableRVA;
                desc.importNameTableOffset = delayLoad.ImportNameTableRVA;
                desc.boundImportAddrTableOffset = delayLoad.BoundImportAddressTableRVA;
                desc.unloadInfoTableOffset = delayLoad.UnloadInformationTableRVA;
                desc.timeDateStamp = delayLoad.TimeDateStamp;

                // Store it.
                delayLoads.push_back( std::move( desc ) );
            }
        }
    }

    // * COMMON LANGUAGE RUNTIME INFO.
    PECommonLanguageRuntimeInfo clrInfo;
    {
        const IMAGE_DATA_DIRECTORY& clrDataDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ];

        clrInfo.dataOffset = clrDataDir.VirtualAddress;
        clrInfo.dataSize = clrDataDir.Size;
    }

    // TODO: maybe validate all structures more explicitly in context now.
    
    // Successfully loaded!
    // Store everything inside ourselves.
    this->dos_data = std::move( dos );
    this->pe_finfo = std::move( peInfo );
    this->peOptHeader = std::move( peOpt );
    this->sections = std::move( sections );
    
    // Data directories.
    this->exportDir = std::move( expInfo );
    this->imports = std::move( impDescs );
    this->resourceRoot = std::move( resourceRoot );
    this->exceptRFs = std::move( exceptRFs );
    this->security = std::move( security );
    this->baseRelocs = std::move( baseRelocs );
    this->debugInfo = std::move( debugInfo );
    this->globalPtr = std::move( globalPtr );
    this->tlsInfo = std::move( tlsInfo );
    this->loadConfig = std::move( loadConfig );
    this->boundImports = std::move( boundImports );
    this->iatThunkAll = std::move( thunkIAT );
    this->delayLoads = std::move( delayLoads );
    this->clrInfo = std::move( clrInfo );

    // Store some meta-data.
    this->is64Bit = is64Bit;        // important for casting certain offsets.

    // Next thing we would need is writing support.
}

struct PEAllocFileAllocProxy
{
    template <typename sliceType>
    AINLINE bool IsInAllocationRange( const sliceType& slice )
    {
        // TODO: add limit checking for 32bit allocatability here (if required).
        return true;
    }
};

// Writing helpers.
typedef InfiniteCollisionlessBlockAllocator <DWORD> peFileAlloc;

AINLINE void PEWrite( CFile *peStream, DWORD peOff, DWORD peSize, const void *dataPtr )
{
    // Seek to the right offset.
    {
        int seekSuccess = peStream->SeekNative( peOff, SEEK_SET );

        if ( seekSuccess != 0 )
        {
            throw std::exception( "failed to seek to PE offset" );
        }
    }

    size_t actualWriteCount = peStream->Write( dataPtr, 1, peSize );

    if ( actualWriteCount != peSize )
    {
        throw std::exception( "failed to write PE data to file" );
    }
}

AINLINE void writeContentAt( peFileAlloc& fileSpaceAlloc, CFile *peStream, peFileAlloc::block_t& allocBlock, DWORD peOff, DWORD peSize, const void *dataPtr )
{
    peFileAlloc::allocInfo alloc_data;

    if ( fileSpaceAlloc.ObtainSpaceAt( peOff, peSize, alloc_data ) == false )
    {
        throw std::exception( "failed to write PE data" );
    }
    
    fileSpaceAlloc.PutBlock( &allocBlock, alloc_data );

    // Actually write things.
    PEWrite( peStream, peOff, peSize, dataPtr );
}

AINLINE DWORD allocContentSpace( peFileAlloc& fileSpaceAlloc, peFileAlloc::block_t& allocBlock, DWORD peSize )
{
    peFileAlloc::allocInfo alloc_data;

    if ( !fileSpaceAlloc.FindSpace( peSize, alloc_data, sizeof(DWORD) ) )
    {
        throw std::exception( "failed to find allocation space for PE data" );
    }

    fileSpaceAlloc.PutBlock( &allocBlock, alloc_data );

    return alloc_data.slice.GetSliceStartPoint();
}

AINLINE void writeContent( peFileAlloc& fileSpaceAlloc, CFile *peStream, peFileAlloc::block_t& allocBlock, DWORD peSize, const void *dataPtr )
{
    DWORD dataPos = allocContentSpace( fileSpaceAlloc, allocBlock, peSize );

    // Write things.
    PEWrite( peStream, dataPos, peSize, dataPtr );
}

struct FileSpaceAllocMan
{
    inline FileSpaceAllocMan( void )
    {
        return;
    }

    inline ~FileSpaceAllocMan( void )
    {
        // Free all allocations that have not yet been freed (which is every alloc).
        while ( !LIST_EMPTY( this->internalAlloc.blockList.root ) )
        {
            peFileAlloc::block_t *item = LIST_GETITEM( peFileAlloc::block_t, this->internalAlloc.blockList.root.next, node );

            alloc_block_t *allocBlock = LIST_GETITEM( alloc_block_t, item, allocatorEntry );

            // Remove us from registration.
            this->internalAlloc.RemoveBlock( item );

            // Delete us.
            delete allocBlock;
        }
    }

    inline DWORD AllocateAny( DWORD peSize )
    {
        peFileAlloc::allocInfo alloc_data;

        if ( internalAlloc.FindSpace( peSize, alloc_data, sizeof( DWORD ) ) == false )
        {
            throw std::exception( "failed to find PE file space for allocation" );
        }

        alloc_block_t *alloc_savior = new alloc_block_t();
        
        internalAlloc.PutBlock( &alloc_savior->allocatorEntry, alloc_data );

        return alloc_savior->allocatorEntry.slice.GetSliceStartPoint();
    }

    inline void AllocateAt( DWORD peOff, DWORD peSize )
    {
        peFileAlloc::allocInfo alloc_data;

        if ( internalAlloc.ObtainSpaceAt( peOff, peSize, alloc_data ) == false )
        {
            throw std::exception( "failed to obtain PE file space at presignated offset" );
        }

        alloc_block_t *alloc_savior = new alloc_block_t();

        internalAlloc.PutBlock( &alloc_savior->allocatorEntry, alloc_data );
    }

private:
    peFileAlloc internalAlloc;

    struct alloc_block_t
    {
        peFileAlloc::block_t allocatorEntry;
    };
};

std::uint16_t PEFile::GetPENativeFileFlags( void )
{
    std::uint16_t chars = 0;

    // Are relocations stripped?
    if ( this->HasRelocationInfo() == false )
    {
        chars |= IMAGE_FILE_RELOCS_STRIPPED;
    }

    if ( this->pe_finfo.isExecutableImage )
    {
        chars |= IMAGE_FILE_EXECUTABLE_IMAGE;
    }

    if ( this->HasLinenumberInfo() == false )
    {
        chars |= IMAGE_FILE_LINE_NUMS_STRIPPED;
    }

    if ( !this->pe_finfo.hasLocalSymbols )
    {
        chars |= IMAGE_FILE_LOCAL_SYMS_STRIPPED;
    }

    if ( this->pe_finfo.hasAggressiveTrim )
    {
        chars |= IMAGE_FILE_AGGRESIVE_WS_TRIM;
    }

    if ( this->pe_finfo.largeAddressAware )
    {
        chars |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
    }

    if ( this->pe_finfo.bytesReversedLO )
    {
        chars |= IMAGE_FILE_BYTES_REVERSED_LO;
    }

    if ( this->is64Bit == false )
    {
        chars |= IMAGE_FILE_32BIT_MACHINE;
    }

    if ( this->HasDebugInfo() == false )
    {
        chars |= IMAGE_FILE_DEBUG_STRIPPED;
    }

    if ( this->pe_finfo.removableRunFromSwap )
    {
        chars |= IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP;
    }

    if ( this->pe_finfo.netRunFromSwap )
    {
        chars |= IMAGE_FILE_NET_RUN_FROM_SWAP;
    }

    if ( this->pe_finfo.isSystemFile )
    {
        chars |= IMAGE_FILE_SYSTEM;
    }

    if ( this->pe_finfo.isDLL )
    {
        chars |= IMAGE_FILE_DLL;
    }

    if ( this->pe_finfo.upSystemOnly )
    {
        chars |= IMAGE_FILE_UP_SYSTEM_ONLY;
    }

    if ( this->pe_finfo.bytesReversedHI )
    {
        chars |= IMAGE_FILE_BYTES_REVERSED_HI;
    }

    return chars;
}

std::uint16_t PEFile::GetPENativeDLLOptFlags( void )
{
    std::uint16_t chars = 0;

    if ( this->peOptHeader.dll_supportsHighEntropy )
    {
        chars |= IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    }

    if ( this->peOptHeader.dll_hasDynamicBase )
    {
        chars |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    }

    if ( this->peOptHeader.dll_forceIntegrity )
    {
        chars |= IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
    }

    if ( this->peOptHeader.dll_nxCompat )
    {
        chars |= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    }

    if ( this->peOptHeader.dll_noIsolation )
    {
        chars |= IMAGE_DLLCHARACTERISTICS_NO_ISOLATION;
    }

    if ( this->peOptHeader.dll_noSEH )
    {
        chars |= IMAGE_DLLCHARACTERISTICS_NO_SEH;
    }

    if ( this->peOptHeader.dll_noBind )
    {
        chars |= IMAGE_DLLCHARACTERISTICS_NO_BIND;
    }

    if ( this->peOptHeader.dll_appContainer )
    {
        chars |= IMAGE_DLLCHARACTERISTICS_APPCONTAINER;
    }

    if ( this->peOptHeader.dll_wdmDriver )
    {
        chars |= IMAGE_DLLCHARACTERISTICS_WDM_DRIVER;
    }

    if ( this->peOptHeader.dll_guardCF )
    {
        chars |= IMAGE_DLLCHARACTERISTICS_GUARD_CF;
    }

    if ( this->peOptHeader.dll_termServAware )
    {
        chars |= IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    }

    return chars;
}

void PEFile::WriteToStream( CFile *peStream )
{
    // TODO: ensure that data has been properly committed to data sections which had to be.
    // First allocate a new section that should serve as allocation target.
    PESection newSect;
    newSect.shortName = ".the_gta";

    // We need to perform allocations onto directory structures for all meta-data.
    FileSpaceAllocMan newMetaAlloc;
    {
        // We first have to allocate everything.

        // * EXPORT DIRECTORY.
        if ( this->exportDir.functions.empty() == false ||
             this->exportDir.name.empty() == false ||
             this->exportDir.base != 0 )
        {
            //todo.

            //exportDirAlloc.theSection = &newSect;
            //exportDirAlloc.sectOffset = newMetaAlloc.AllocateAny( sizeof( IMAGE_EXPORT_DIRECTORY ) );

            // Now the tables.
        }
    }

    // TODO: properly write the PE file onto disk.
    
    FileSpaceAllocMan allocMan;

    // Allocate and write the DOS header.
    allocMan.AllocateAt( 0, sizeof( IMAGE_DOS_HEADER ) + this->dos_data.progData.size() );

    IMAGE_DOS_HEADER dos_header;
    dos_header.e_magic = 'ZM';
    dos_header.e_cblp = this->dos_data.cblp;
    dos_header.e_cp = this->dos_data.cp;
    dos_header.e_crlc = this->dos_data.crlc;
    dos_header.e_cparhdr = this->dos_data.cparhdr;
    dos_header.e_minalloc = this->dos_data.minalloc;
    dos_header.e_maxalloc = this->dos_data.maxalloc;
    dos_header.e_ss = this->dos_data.ss;
    dos_header.e_sp = this->dos_data.sp;
    dos_header.e_csum = this->dos_data.csum;
    dos_header.e_ip = this->dos_data.ip;
    dos_header.e_cs = this->dos_data.cs;
    dos_header.e_lfarlc = this->dos_data.lfarlc;
    dos_header.e_ovno = this->dos_data.ovno;
    memcpy( dos_header.e_res, this->dos_data.reserved1, sizeof( dos_header.e_res ) );
    dos_header.e_oemid = this->dos_data.oemid;
    dos_header.e_oeminfo = this->dos_data.oeminfo;
    memcpy( dos_header.e_res2, this->dos_data.reserved2, sizeof( dos_header.e_res2 ) );

    // Allocate and write PE information next.
    // This has to be the PE header, the optional header (32bit or 64bit), the data directory info
    // and the section info.
    {
        bool is64Bit = this->is64Bit;

        // Determine the size of data to-be-written.
        size_t peDataSize = sizeof( IMAGE_PE_HEADER );

        // The optional header.
        size_t peOptHeaderSize;

        if ( is64Bit )
        {
            // TODO: if directory entries support turns dynamic we need to adjust this.
            peOptHeaderSize = sizeof( IMAGE_OPTIONAL_HEADER64 );
        }
        else
        {
            peOptHeaderSize = sizeof( IMAGE_OPTIONAL_HEADER32 );
        }
        peDataSize += peOptHeaderSize;

        // Add the size of section headers.
        peDataSize += ( this->sections.size() * sizeof( IMAGE_SECTION_HEADER ) );

        // TODO: there is "deprecated" information like lineinfo and native relocation
        // info allowed. should we add support? this would mean adding even more size to
        // peDataSize.

        DWORD peDataPos = allocMan.AllocateAny( peDataSize );
            
        IMAGE_PE_HEADER pe_data;
        pe_data.Signature = 'EP';
        pe_data.FileHeader.Machine = this->pe_finfo.machine_id;
        pe_data.FileHeader.NumberOfSections = this->sections.size();
        pe_data.FileHeader.TimeDateStamp = this->pe_finfo.timeDateStamp;
        pe_data.FileHeader.PointerToSymbolTable = NULL;     // not supported yet.
        pe_data.FileHeader.NumberOfSymbols = 0;
        pe_data.FileHeader.SizeOfOptionalHeader = ( is64Bit ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32) );
            
        // Set up the flags.
        pe_data.FileHeader.Characteristics = GetPENativeFileFlags();

        // Time for the optional header.
        // Once again a complicated construct that depends on data before and after.
        // For that reason we allocate here and fill out the structure afterward.
        DWORD peOptHeaderOffset = ( peDataPos + sizeof(IMAGE_PE_HEADER) );

        // Write the data directories.
        // Remember that we must not do allocations about the data directories here anymore.

        // Write the section headers with all the meta-data surrounding them.

        // Write PE data.
        // First the header
        PEWrite( peStream, peDataPos, sizeof( pe_data ), &pe_data );

        // Now we need to write the optional header.
        if ( is64Bit )
        {
            IMAGE_OPTIONAL_HEADER64 optHeader;
            optHeader.Magic = 0x020B;   // todo: think about this, and 64bit support. (PE32+)
            optHeader.MajorLinkerVersion = this->peOptHeader.majorLinkerVersion;
            optHeader.MinorLinkerVersion = this->peOptHeader.minorLinkerVersion;
            optHeader.SizeOfCode = this->peOptHeader.sizeOfCode;
            optHeader.SizeOfInitializedData = this->peOptHeader.sizeOfInitializedData;
            optHeader.SizeOfInitializedData = this->peOptHeader.sizeOfUninitializedData;
            optHeader.AddressOfEntryPoint = this->peOptHeader.addressOfEntryPoint;
            optHeader.BaseOfCode = this->peOptHeader.baseOfCode;
            optHeader.ImageBase = this->peOptHeader.imageBase;
            optHeader.SectionAlignment = this->peOptHeader.sectionAlignment;
            optHeader.FileAlignment = this->peOptHeader.fileAlignment;
            optHeader.MajorOperatingSystemVersion = this->peOptHeader.majorOSVersion;
            optHeader.MinorOperatingSystemVersion = this->peOptHeader.minorOSVersion;
            optHeader.MajorImageVersion = this->peOptHeader.majorImageVersion;
            optHeader.MinorImageVersion = this->peOptHeader.minorImageVersion;
            optHeader.MajorSubsystemVersion = this->peOptHeader.majorSubsysVersion;
            optHeader.MinorSubsystemVersion = this->peOptHeader.minorSubsysVersion;
            optHeader.Win32VersionValue = this->peOptHeader.win32VersionValue;
            optHeader.SizeOfImage = 0;      // TODO: should be calculated here.
            optHeader.SizeOfHeaders = ALIGN_SIZE( peDataSize, this->peOptHeader.fileAlignment );
            optHeader.CheckSum = this->peOptHeader.checkSum;    // TODO: Windows Critical components need to update this.
            optHeader.Subsystem = this->peOptHeader.subsys;
            optHeader.DllCharacteristics = this->GetPENativeDLLOptFlags();
            optHeader.SizeOfStackReserve = this->peOptHeader.sizeOfStackReserve;
            optHeader.SizeOfStackCommit = this->peOptHeader.sizeOfStackCommit;
            optHeader.SizeOfHeapReserve = this->peOptHeader.sizeOfHeapReserve;
            optHeader.SizeOfHeapCommit = this->peOptHeader.sizeOfHeapCommit;
            optHeader.LoaderFlags = this->peOptHeader.loaderFlags;
            optHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;   // TODO: maybe make this dynamic.

            // TODO: fill out directory entries.

            PEWrite( peStream, peOptHeaderOffset, sizeof(optHeader), &optHeader );
        }
        else
        {
            IMAGE_OPTIONAL_HEADER32 optHeader;
            optHeader.Magic = 0x020B;   // todo: think about this, and 64bit support. (PE32+)
            optHeader.MajorLinkerVersion = this->peOptHeader.majorLinkerVersion;
            optHeader.MinorLinkerVersion = this->peOptHeader.minorLinkerVersion;
            optHeader.SizeOfCode = this->peOptHeader.sizeOfCode;
            optHeader.SizeOfInitializedData = this->peOptHeader.sizeOfInitializedData;
            optHeader.SizeOfInitializedData = this->peOptHeader.sizeOfUninitializedData;
            optHeader.AddressOfEntryPoint = this->peOptHeader.addressOfEntryPoint;
            optHeader.BaseOfCode = this->peOptHeader.baseOfCode;
            optHeader.BaseOfData = this->peOptHeader.baseOfData;    // TODO: maybe this needs updating if we change from 32bit to 64bit.
            optHeader.ImageBase = this->peOptHeader.imageBase;
            optHeader.SectionAlignment = this->peOptHeader.sectionAlignment;
            optHeader.FileAlignment = this->peOptHeader.fileAlignment;
            optHeader.MajorOperatingSystemVersion = this->peOptHeader.majorOSVersion;
            optHeader.MinorOperatingSystemVersion = this->peOptHeader.minorOSVersion;
            optHeader.MajorImageVersion = this->peOptHeader.majorImageVersion;
            optHeader.MinorImageVersion = this->peOptHeader.minorImageVersion;
            optHeader.MajorSubsystemVersion = this->peOptHeader.majorSubsysVersion;
            optHeader.MinorSubsystemVersion = this->peOptHeader.minorSubsysVersion;
            optHeader.Win32VersionValue = this->peOptHeader.win32VersionValue;
            optHeader.SizeOfImage = 0;      // TODO: should be calculated here.
            optHeader.SizeOfHeaders = ALIGN_SIZE( peDataSize, this->peOptHeader.fileAlignment );
            optHeader.CheckSum = this->peOptHeader.checkSum;    // TODO: Windows Critical components need to update this.
            optHeader.Subsystem = this->peOptHeader.subsys;
            optHeader.DllCharacteristics = this->GetPENativeDLLOptFlags();
            optHeader.SizeOfStackReserve = this->peOptHeader.sizeOfStackReserve;
            optHeader.SizeOfStackCommit = this->peOptHeader.sizeOfStackCommit;
            optHeader.SizeOfHeapReserve = this->peOptHeader.sizeOfHeapReserve;
            optHeader.SizeOfHeapCommit = this->peOptHeader.sizeOfHeapCommit;
            optHeader.LoaderFlags = this->peOptHeader.loaderFlags;
            optHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;   // TODO: maybe make this dynamic.

            // TODO: fill out directory entries.

            PEWrite( peStream, peOptHeaderOffset, sizeof(optHeader), &optHeader );
        }

        // TODO: update section headers and stuff with offsets of sections and other data.

        // We need to know where PE data starts at.
        dos_header.e_lfanew = (LONG)peDataPos;
    }

    peStream->SeekNative( 0, SEEK_SET );
    peStream->Write( &dos_header, 1, sizeof( dos_header ) );
    peStream->Write( this->dos_data.progData.data(), 1, this->dos_data.progData.size() );
}

bool PEFile::HasRelocationInfo( void ) const
{
    // Check any sections.
    for ( const PESection& sect : this->sections )
    {
        if ( sect.relocations.size() != 0 )
            return true;
    }

    // Check the relocation data.
    if ( this->baseRelocs.size() != 0 )
        return true;

    // Nothing found.
    return false;
}

bool PEFile::HasLinenumberInfo( void ) const
{
    // Check sections.
    for ( const PESection& sect : this->sections )
    {
        if ( sect.linenumbers.size() != 0 )
            return true;
    }

    // Has no embedded line number info.
    return false;
}

bool PEFile::HasDebugInfo( void ) const
{
    // We check if we have debug directory data.
    if ( this->debugInfo.addrOfRawData != 0 && this->debugInfo.sizeOfData != 0 )
        return true;

    return false;
}