#include "StdInc.h"
#include "peloader.h"

#include <unordered_map>
#include <set>

#include <sdk/MemoryRaw.h>
#include <sdk/MemoryUtils.h>

#define NOMINMAX
#include <Windows.h>

PEFile::PEFile( void ) : resourceRoot( std::wstring() ), sections( 0x1000, 0x10000 )
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
    DOSStub dos;

    // Cache some properties.
    LONG peFileStartOffset;
    {
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

        peFileStartOffset = dosHeader.e_lfanew;
    }

    // Go on to the PE header.
    PEFileInfo peInfo;

    // Cache some properties.
    WORD numSections;
    {
        int seekSuccess = peStream->SeekNative( peFileStartOffset, SEEK_SET );

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

        numSections = peHeader.FileHeader.NumberOfSections;

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
    }

    // Let's read our optional header!
    PEOptHeader peOpt;

    // We have to extract this.
    std::uint32_t sectionAlignment;
    IMAGE_DATA_DIRECTORY dataDirs[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    {
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

            // Extract the section alignment.
            sectionAlignment = optHeader.SectionAlignment;

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

            // Extract the section alignment.
            sectionAlignment = optHeader.SectionAlignment;

            // Extract the data directory information.
            DWORD numDataDirs = optHeader.NumberOfRvaAndSizes;

            if ( numDataDirs != IMAGE_NUMBEROF_DIRECTORY_ENTRIES )
                throw std::exception( "invalid number of PE directory entries" );

            // Extract the data directory information.
            memcpy( dataDirs, optHeader.DataDirectory, sizeof( dataDirs ) );
        }

        // Process the DLL flags and store them sensibly.
        peOpt.dll_supportsHighEntropy =     ( dllChars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA ) != 0;
        peOpt.dll_hasDynamicBase =          ( dllChars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ) != 0;
        peOpt.dll_forceIntegrity =          ( dllChars & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY ) != 0;
        peOpt.dll_nxCompat =                ( dllChars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT ) != 0;
        peOpt.dll_noIsolation =             ( dllChars & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ) != 0;
        peOpt.dll_noSEH =                   ( dllChars & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ) != 0;
        peOpt.dll_noBind =                  ( dllChars & IMAGE_DLLCHARACTERISTICS_NO_BIND ) != 0;
        peOpt.dll_appContainer =            ( dllChars & IMAGE_DLLCHARACTERISTICS_APPCONTAINER ) != 0;
        peOpt.dll_wdmDriver =               ( dllChars & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER ) != 0;
        peOpt.dll_guardCF =                 ( dllChars & IMAGE_DLLCHARACTERISTICS_GUARD_CF ) != 0;
        peOpt.dll_termServAware =           ( dllChars & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE ) != 0;
    }

    // Should handle data sections first because data directories depend on them.
    PESectionMan sections( sectionAlignment, peOpt.baseOfCode );

    for ( size_t n = 0; n < numSections; n++ )
    {
        IMAGE_SECTION_HEADER sectHeader;

        bool readSection = peStream->ReadStruct( sectHeader );

        if ( !readSection )
            throw std::exception( "failed to read PE section header" );

        fsOffsetNumber_t sectHeaderOff = peStream->TellNative();

        PESection section;
        section.shortName = std::string( (const char*)sectHeader.Name, strnlen( (const char*)sectHeader.Name, IMAGE_SIZEOF_SHORT_NAME ) );
        section.virtualSize = sectHeader.Misc.VirtualSize;
        section.virtualAddr = sectHeader.VirtualAddress;
        
        // Save characteristics flags.
        DWORD schars = sectHeader.Characteristics;

        section.chars.sect_hasNoPadding = ( schars & IMAGE_SCN_TYPE_NO_PAD ) != 0;
        section.chars.sect_containsCode = ( schars & IMAGE_SCN_CNT_CODE ) != 0;
        section.chars.sect_containsInitData = ( schars & IMAGE_SCN_CNT_INITIALIZED_DATA ) != 0;
        section.chars.sect_containsUninitData = ( schars & IMAGE_SCN_CNT_UNINITIALIZED_DATA ) != 0;
        section.chars.sect_link_other = ( schars & IMAGE_SCN_LNK_OTHER ) != 0;
        section.chars.sect_link_info = ( schars & IMAGE_SCN_LNK_INFO ) != 0;
        section.chars.sect_link_remove = ( schars & IMAGE_SCN_LNK_REMOVE ) != 0;
        section.chars.sect_link_comdat = ( schars & IMAGE_SCN_LNK_COMDAT ) != 0;
        section.chars.sect_noDeferSpecExcepts = ( schars & IMAGE_SCN_NO_DEFER_SPEC_EXC ) != 0;
        section.chars.sect_gprel = ( schars & IMAGE_SCN_GPREL ) != 0;
        section.chars.sect_mem_farData = ( schars & IMAGE_SCN_MEM_FARDATA ) != 0;
        section.chars.sect_mem_purgeable = ( schars & IMAGE_SCN_MEM_PURGEABLE ) != 0;
        section.chars.sect_mem_16bit = ( schars & IMAGE_SCN_MEM_16BIT ) != 0;
        section.chars.sect_mem_locked = ( schars & IMAGE_SCN_MEM_LOCKED ) != 0;
        section.chars.sect_mem_preload = ( schars & IMAGE_SCN_MEM_PRELOAD ) != 0;
        
        // Parse the alignment information out of the chars.
        PESection::eAlignment alignNum = (PESection::eAlignment)( ( schars & 0x00F00000 ) >> 20 );
        section.chars.sect_alignment = alignNum;

        section.chars.sect_link_nreloc_ovfl = ( schars & IMAGE_SCN_LNK_NRELOC_OVFL ) != 0;
        section.chars.sect_mem_discardable = ( schars & IMAGE_SCN_MEM_DISCARDABLE ) != 0;
        section.chars.sect_mem_not_cached = ( schars & IMAGE_SCN_MEM_NOT_CACHED ) != 0;
        section.chars.sect_mem_not_paged = ( schars & IMAGE_SCN_MEM_NOT_PAGED ) != 0;
        section.chars.sect_mem_shared = ( schars & IMAGE_SCN_MEM_SHARED ) != 0;
        section.chars.sect_mem_execute = ( schars & IMAGE_SCN_MEM_EXECUTE ) != 0;
        section.chars.sect_mem_read = ( schars & IMAGE_SCN_MEM_READ ) != 0;
        section.chars.sect_mem_write = ( schars & IMAGE_SCN_MEM_WRITE ) != 0;

        // Read raw data.
        {
            peStream->SeekNative( sectHeader.PointerToRawData, SEEK_SET );

            section.stream.Truncate( (std::uint32_t)sectHeader.SizeOfRawData );

            size_t actualReadCount = peStream->Read( section.stream.Data(), 1, sectHeader.SizeOfRawData );

            if ( actualReadCount != sectHeader.SizeOfRawData )
                throw std::exception( "failed to read PE section raw data" );
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
        bool regSuccess = ( sections.PlaceSection( std::move( section ) ) != NULL );

        if ( !regSuccess )
        {
            throw std::exception( "invalid PE section configuration" );
        }
    }

    // That is the end of the executable data reading.
    // Now we dispatch onto the data directories, which base on things found inside the sections.

    // Load the directory information now.
    // We decide to create meta-data structs out of them.
    // If possible, delete the section that contains the meta-data.
    // * EXPORT INFORMATION.
    PEExportDir expInfo;
    {
        const IMAGE_DATA_DIRECTORY& expDirEntry = dataDirs[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

        if ( expDirEntry.VirtualAddress != 0 )
        {
            PESection *expDirSect;

            IMAGE_EXPORT_DIRECTORY expEntry;
            {
                bool gotData = sections.ReadPEData( expDirEntry.VirtualAddress, sizeof(expEntry), &expEntry, &expDirSect );

                if ( !gotData )
                    throw std::exception( "invalid PE export directory" );
            }

            expDirSect->SetPlacedMemory( expInfo.allocEntry, expDirEntry.VirtualAddress, expDirEntry.Size );

            // Store the usual tidbits.
            expInfo.chars = expEntry.Characteristics;
            expInfo.timeDateStamp = expEntry.TimeDateStamp;
            expInfo.majorVersion = expEntry.MajorVersion;
            expInfo.minorVersion = expEntry.MinorVersion;
            expInfo.ordinalBase = expEntry.Base;

            size_t ordinalBase = ( expInfo.ordinalBase - 1 );

            // Read the name.
            PESection *sectOfName;
            {
                bool gotName = sections.ReadPEString( expEntry.Name, expInfo.name, &sectOfName );

                if ( !gotName )
                    throw std::exception( "failed to read PE export directory name" );
            }

            sectOfName->SetPlacedMemory( expInfo.nameAllocEntry, expEntry.Name );

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
                
                PESection *addrPtrSect;
                PEDataStream addrPtrStream;
                {
                    bool gotStream = sections.GetPEDataStream(
                        expEntry.AddressOfFunctions, addrPtrStream,
                        &addrPtrSect
                    );

                    if ( !gotStream )
                    {
                        throw std::exception( "failed to get PE export info function entries" );
                    }
                }

                addrPtrSect->SetPlacedMemory( expInfo.funcAddressAllocEntry, expEntry.AddressOfFunctions );

                for ( DWORD n = 0; n < expEntry.NumberOfFunctions; n++ )
                {
                    PEExportDir::func fentry;
                    fentry.isNamed = false; // by default no export is named.

                    bool isForwarder;
                    {
                        DWORD ptr;
                        addrPtrStream.Read( &ptr, sizeof(ptr) );

                        // Determine if we are a forwarder or an export.
                        {
                            typedef sliceOfData <DWORD> rvaSlice_t;

                            rvaSlice_t requestSlice( ptr, 1 );

                            rvaSlice_t expDirSlice( expDirEntry.VirtualAddress, expDirEntry.Size );

                            rvaSlice_t::eIntersectionResult intResult = requestSlice.intersectWith( expDirSlice );

                            isForwarder = ( rvaSlice_t::isFloatingIntersect( intResult ) == false );
                        }

                        // Store properties according to the type.
                        PESection *exportOffPtrSect;
                        PEDataStream expOffStream;
                        {
                            bool gotStream = sections.GetPEDataStream( ptr, expOffStream, &exportOffPtrSect );

                            if ( !gotStream )
                                throw std::exception( "failed to get PE export offset pointer" );
                        }

                        // We store the location of the data entry, but NOTE that
                        // this behavior NEVER is an allocation!
                        {
                            DWORD offStore;

                            if ( isForwarder )
                            {
                                offStore = ( ptr - expDirEntry.VirtualAddress );
                            }
                            else
                            {
                                offStore = ( ptr - exportOffPtrSect->virtualAddr );
                            }

                            fentry.forwExpFuncOffset = offStore;
                            fentry.forwExpFuncSection = exportOffPtrSect;
                        }

                        if ( isForwarder )
                        {
                            ReadPEString( expOffStream, fentry.forwarder );
                        }
                    }
                    fentry.isForwarder = isForwarder;

                    funcs.push_back( std::move( fentry ) );
                }

                // Read names and ordinals, if available.
                if ( expEntry.AddressOfNames != 0 && expEntry.AddressOfNameOrdinals != 0 )
                {
                    // Establish name ptr array.
                    PESection *addrNamesSect;
                    PEDataStream addrNamesStream;
                    {
                        bool gotStream = sections.GetPEDataStream( expEntry.AddressOfNames, addrNamesStream, &addrNamesSect );

                        if ( !gotStream )
                            throw std::exception( "failed to get PE export directory function name list" );
                    }

                    addrNamesSect->SetPlacedMemory( expInfo.funcNamesAllocEntry, expEntry.AddressOfNames );

                    // Establish ordinal mapping array.
                    PESection *addrNameOrdSect;
                    PEDataStream addrNameOrdStream;
                    {
                        bool gotStream = sections.GetPEDataStream( expEntry.AddressOfNameOrdinals, addrNameOrdStream, &addrNameOrdSect );
                        
                        if ( !gotStream )
                            throw std::exception( "failed to get PE export directory function ordinals" );
                    }

                    addrNameOrdSect->SetPlacedMemory( expInfo.funcOrdinalsAllocEntry, expEntry.AddressOfNameOrdinals );

                    // Map names to functions.
                    for ( DWORD n = 0; n < expEntry.NumberOfNames; n++ )
                    {
                        WORD ordinal;
                        addrNameOrdStream.Read( &ordinal, sizeof(ordinal) );

                        // Get the index to map the function name to (== ordinal).
                        size_t mapIndex = ( ordinal - ordinalBase );

                        if ( mapIndex >= funcs.size() )
                        {
                            // Invalid mapping.
                            throw std::exception( "PE binary has broken export mapping (ordinal out of bounds)" );
                        }

                        // Get the name we should map to.
                        PESection *realNamePtrSect;

                        DWORD namePtrRVA;
                        addrNamesStream.Read( &namePtrRVA, sizeof(namePtrRVA) );

                        // Read the actual name.
                        std::string realName;
                        {
                            bool gotString = sections.ReadPEString( namePtrRVA, realName, &realNamePtrSect );

                            if ( !gotString )
                                throw std::exception( "failed to get PE export directory function name ptr" );
                        }

                        if ( realName.empty() )
                        {
                            // Kind of invalid.
                            throw std::exception( "invalid PE export name: empty string" );
                        }

                        PEExportDir::func& fentry = funcs[ mapIndex ];

                        // Check for ambiguous name mappings.
                        // TODO: this is actually allowed and is called "alias"; pretty evil.
                        if ( fentry.isNamed )
                        {
                            throw std::exception( "ambiguous PE export name mapping" );
                        }

                        fentry.name = std::move( realName );
                        fentry.isNamed = true;  // yes, we have a valid name!

                        realNamePtrSect->SetPlacedMemory( fentry.nameAllocEntry, namePtrRVA );
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
            PESection *impDirSect;
            PEDataStream importDescsStream;
            {
                bool gotStream = sections.GetPEDataStream( impDir.VirtualAddress, importDescsStream, &impDirSect );

                if ( !gotStream )
                    throw std::exception( "failed to read PE import descriptors" );
            }

            impDirSect->SetPlacedMemory( this->importsAllocEntry, impDir.VirtualAddress, impDir.Size );

            // Read all the descriptors.
            const DWORD potentialNumDescriptors = ( impDir.Size / sizeof( IMAGE_IMPORT_DESCRIPTOR ) );

            impDescs.reserve( potentialNumDescriptors );

            DWORD n = 0;

            while ( n++ < potentialNumDescriptors )
            {
                IMAGE_IMPORT_DESCRIPTOR importInfo;
                importDescsStream.Read( &importInfo, sizeof(importInfo) );

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
                    PESection *importNameArraySect;
                    PEDataStream importNameArrayStream;
                    {
                        bool hasStream = sections.GetPEDataStream( importInfo.Characteristics, importNameArrayStream, &importNameArraySect );

                        if ( !hasStream )
                            throw std::exception( "failed to read PE import function name array" );
                    }
                    
                    importNameArraySect->SetPlacedMemory( impDesc.impNameArrayAllocEntry, importInfo.Characteristics );

                    // The array goes on until a terminating NULL.
                    decltype( impDesc.funcs ) funcs;

                    while ( true )
                    {
                        // Read the entry properly.
                        ULONGLONG importNameRVA;

                        if ( is64Bit )
                        {
                            ULONGLONG importNameRVA_read;
                            importNameArrayStream.Read( &importNameRVA_read, sizeof( importNameRVA_read ) );

                            importNameRVA = importNameRVA_read;
                        }
                        else
                        {
                            DWORD importNameRVA_read;
                            importNameArrayStream.Read( &importNameRVA_read, sizeof( importNameRVA_read ) );

                            importNameRVA = importNameRVA_read;
                        }

                        if ( !importNameRVA )
                            break;

                        PEImportDesc::importFunc funcInfo;

                        // Check if this is an ordinal import or a named import.
                        bool isOrdinalImport;

                        if ( is64Bit )
                        {
                            isOrdinalImport = ( importNameRVA & 0x8000000000000000 ) != 0;
                        }
                        else
                        {
                            isOrdinalImport = ( importNameRVA & 0x80000000 ) != 0;
                        }

                        if ( isOrdinalImport )
                        {
                            // The documentation says that even for PE32+ the number stays 31bit.
                            // It is really weird that this was made a 64bit number tho.
                            funcInfo.ordinal_hint = ( importNameRVA & 0x7FFFFFFF );
                        }
                        else
                        {
                            PESection *importNameSect;
                            PEDataStream importNameStream;
                            {
                                bool gotStream = sections.GetPEDataStream( (DWORD)importNameRVA, importNameStream, &importNameSect );

                                if ( !gotStream )
                                    throw std::exception( "failed to read PE import function name entry" );
                            }

                            importNameSect->SetPlacedMemory( funcInfo.nameAllocEntry, (DWORD)importNameRVA );

                            // Read stuff.
                            WORD ordinal_hint;
                            importNameStream.Read( &ordinal_hint, sizeof(ordinal_hint) );

                            funcInfo.ordinal_hint = ordinal_hint;

                            ReadPEString( importNameStream, funcInfo.name );
                        }
                        funcInfo.isOrdinalImport = isOrdinalImport;
                        
                        funcs.push_back( std::move( funcInfo ) );
                    }

                    impDesc.funcs = std::move( funcs );
                }

                // Store the DLL name we import from.
                {
                    PESection *dllNameSect;
                    {
                        bool gotName = sections.ReadPEString( importInfo.Name, impDesc.DLLName, &dllNameSect );

                        if ( !gotName )
                            throw std::exception( "failed to read PE import desc DLL name" );
                    }

                    dllNameSect->SetPlacedMemory( impDesc.DLLName_allocEntry, importInfo.Name );
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
            PESection *resDataSect;
            PEDataStream resDataStream;
            {
                bool gotStream = sections.GetPEDataStream( resDir.VirtualAddress, resDataStream, &resDataSect );

                if ( !gotStream )
                    throw std::exception( "invalid PE resource root" );
            }

            resDataSect->SetPlacedMemory( this->resAllocEntry, resDir.VirtualAddress, resDir.Size );

            PEStructures::IMAGE_RESOURCE_DIRECTORY resDir;
            resDataStream.Read( &resDir, sizeof(resDir) );

            resourceRoot = LoadResourceDirectory( sections, resDataStream, std::wstring(), resDir );
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

            PESection *rtFuncsSect;
            PEDataStream rtFuncsStream;
            {
                bool gotStream = sections.GetPEDataStream( rtDir.VirtualAddress, rtFuncsStream, &rtFuncsSect );

                if ( !gotStream )
                    throw std::exception( "invalid PE exception directory" );
            }

            rtFuncsSect->SetPlacedMemory( this->exceptAllocEntry, rtDir.VirtualAddress, rtDir.Size );

            const DWORD numFuncs = ( rtDir.Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY ) );

            exceptRFs.reserve( numFuncs );

            for ( size_t n = 0; n < numFuncs; n++ )
            {
                IMAGE_RUNTIME_FUNCTION_ENTRY func;
                rtFuncsStream.Read( &func, sizeof(func) );

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

            PESection *baseRelocDescsSect;
            PEDataStream baseRelocDescsStream;
            {
                bool gotStream = sections.GetPEDataStream( baserelocDir.VirtualAddress, baseRelocDescsStream, &baseRelocDescsSect );

                if ( !gotStream )
                    throw std::exception( "invalid PE base relocation directory" );
            }

            baseRelocDescsSect->SetPlacedMemory( this->baseRelocAllocEntry, baserelocDir.VirtualAddress, baserelocDir.Size );

            // We read relocation data until we are at the end of the directory.
            while ( true )
            {
                // Remember our current offset.
                std::uint32_t curOffset = baseRelocDescsStream.Tell();

                if ( curOffset >= sizeRelocations )
                    break;

                // Get current relocation.
                IMAGE_BASE_RELOCATION baseReloc;
                baseRelocDescsStream.Read( &baseReloc, sizeof(baseReloc) );

                // Store it.
                const size_t blockSize = baseReloc.SizeOfBlock;

                // Validate the blockSize.
                if ( blockSize < sizeof(IMAGE_BASE_RELOCATION) )
                    throw std::exception( "malformed PE base relocation sub block" );

                // Subtract the meta-data size.
                const size_t entryBlockSize = ( blockSize - sizeof(IMAGE_BASE_RELOCATION) );
                {
                    PEBaseReloc info;
                    info.offsetOfReloc = baseReloc.VirtualAddress;

                    // Read all relocations.
                    const DWORD numRelocItems = ( entryBlockSize / sizeof( PEStructures::IMAGE_BASE_RELOC_TYPE_ITEM ) );

                    info.items.reserve( numRelocItems );

                    for ( size_t n = 0; n < numRelocItems; n++ )
                    {
                        PEStructures::IMAGE_BASE_RELOC_TYPE_ITEM reloc;
                        baseRelocDescsStream.Read( &reloc, sizeof(reloc) );

                        PEBaseReloc::item itemInfo;
                        itemInfo.type = reloc.type;
                        itemInfo.offset = reloc.offset;

                        info.items.push_back( std::move( itemInfo ) );
                    }

                    // Remember us.
                    baseRelocs.push_back( std::move( info ) );
                }

                // Done reading this descriptor.
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
            PESection *debugEntrySection;
            PEDataStream debugEntryStream;
            {
                bool gotStream = sections.GetPEDataStream( debugDir.VirtualAddress, debugEntryStream, &debugEntrySection );

                if ( !gotStream )
                    throw std::exception( "invalid PE debug directory" );
            }

            debugEntrySection->SetPlacedMemory( debugInfo.allocEntry, debugDir.VirtualAddress, debugDir.Size );

            IMAGE_DEBUG_DIRECTORY debugEntry;
            debugEntryStream.Read( &debugEntry, sizeof(debugEntry) );

            // We store this debug information entry.
            // Debug information can be of many types and we cannot ever handle all of them!
            debugInfo.characteristics = debugEntry.Characteristics;
            debugInfo.timeDateStamp = debugEntry.TimeDateStamp;
            debugInfo.majorVer = debugEntry.MajorVersion;
            debugInfo.minorVer = debugEntry.MinorVersion;
            debugInfo.type = debugEntry.Type;
            debugInfo.sizeOfData = debugEntry.SizeOfData;
            debugInfo.addrOfRawData = debugEntry.AddressOfRawData;
            debugInfo.ptrToRawData = debugEntry.PointerToRawData;

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
            PESection *tlsDirSect;
            PEDataStream tlsDirStream;
            {
                bool gotStream = sections.GetPEDataStream( tlsDataDir.VirtualAddress, tlsDirStream, &tlsDirSect );

                if ( !gotStream )
                {
                    throw std::exception( "invalid PE thread-local-storage directory" );
                }
            }

            // It depends on the architecture what directory type we encounter here.
            if ( is64Bit )
            {
                IMAGE_TLS_DIRECTORY64 tlsDir;
                tlsDirStream.Read( &tlsDir, sizeof(tlsDir) );

                tlsInfo.startOfRawData = tlsDir.StartAddressOfRawData;
                tlsInfo.endOfRawData = tlsDir.EndAddressOfRawData;
                tlsInfo.addressOfIndices = tlsDir.AddressOfIndex;
                tlsInfo.addressOfCallbacks = tlsDir.AddressOfCallBacks;
                tlsInfo.sizeOfZeroFill = tlsDir.SizeOfZeroFill;
                tlsInfo.characteristics = tlsDir.Characteristics;
            }
            else
            {
                IMAGE_TLS_DIRECTORY32 tlsDir;
                tlsDirStream.Read( &tlsDir, sizeof(tlsDir) );

                tlsInfo.startOfRawData = tlsDir.StartAddressOfRawData;
                tlsInfo.endOfRawData = tlsDir.EndAddressOfRawData;
                tlsInfo.addressOfIndices = tlsDir.AddressOfIndex;
                tlsInfo.addressOfCallbacks = tlsDir.AddressOfCallBacks;
                tlsInfo.sizeOfZeroFill = tlsDir.SizeOfZeroFill;
                tlsInfo.characteristics = tlsDir.Characteristics;
            }

            tlsDirSect->SetPlacedMemory( tlsInfo.allocEntry, tlsDataDir.VirtualAddress, tlsDataDir.Size );
        }
    }

    // * LOAD CONFIG.
    PELoadConfig loadConfig;
    {
        const IMAGE_DATA_DIRECTORY& lcfgDataDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG ];

        if ( lcfgDataDir.VirtualAddress != 0 )
        {
            PESection *lcfgDirSect;
            PEDataStream lcfgDirStream;
            {
                bool gotStream = sections.GetPEDataStream( lcfgDataDir.VirtualAddress, lcfgDirStream, &lcfgDirSect );

                if ( !gotStream )
                {
                    throw std::exception( "invalid PE load config directory" );
                }
            }

            if ( is64Bit )
            {
                IMAGE_LOAD_CONFIG_DIRECTORY64 lcfgDir;
                lcfgDirStream.Read( &lcfgDir, sizeof(lcfgDir) );

                if ( lcfgDir.Size < sizeof(lcfgDir) )
                    throw std::exception( "invalid PE load configuration directory size" );

                loadConfig.timeDateStamp = lcfgDir.TimeDateStamp;
                loadConfig.majorVersion = lcfgDir.MajorVersion;
                loadConfig.minorVersion = lcfgDir.MinorVersion;
                loadConfig.globFlagsClear = lcfgDir.GlobalFlagsClear;
                loadConfig.globFlagsSet = lcfgDir.GlobalFlagsSet;
                loadConfig.critSecDefTimeOut = lcfgDir.CriticalSectionDefaultTimeout;
                loadConfig.deCommitFreeBlockThreshold = lcfgDir.DeCommitFreeBlockThreshold;
                loadConfig.deCommitTotalFreeThreshold = lcfgDir.DeCommitTotalFreeThreshold;
                loadConfig.lockPrefixTable = lcfgDir.LockPrefixTable;
                loadConfig.maxAllocSize = lcfgDir.MaximumAllocationSize;
                loadConfig.virtualMemoryThreshold = lcfgDir.VirtualMemoryThreshold;
                loadConfig.processAffinityMask = lcfgDir.ProcessAffinityMask;
                loadConfig.processHeapFlags = lcfgDir.ProcessHeapFlags;
                loadConfig.CSDVersion = lcfgDir.CSDVersion;
                loadConfig.reserved1 = lcfgDir.Reserved1;
                loadConfig.editList = lcfgDir.EditList;
                loadConfig.securityCookie = lcfgDir.SecurityCookie;
                loadConfig.SEHandlerTable = lcfgDir.SEHandlerTable;
                loadConfig.SEHandlerCount = lcfgDir.SEHandlerCount;
                loadConfig.guardCFCheckFunctionPtr = lcfgDir.GuardCFCheckFunctionPointer;
                loadConfig.reserved2 = lcfgDir.Reserved2;
                loadConfig.guardCFFunctionTable = lcfgDir.GuardCFFunctionTable;
                loadConfig.guardCFFunctionCount = lcfgDir.GuardCFFunctionCount;
                loadConfig.guardFlags = lcfgDir.GuardFlags;
            }
            else
            {
                IMAGE_LOAD_CONFIG_DIRECTORY32 lcfgDir;
                lcfgDirStream.Read( &lcfgDir, sizeof(lcfgDir) );

                if ( lcfgDir.Size < sizeof(lcfgDir) )
                    throw std::exception( "invalid PE load configuration directory size" );

                loadConfig.timeDateStamp = lcfgDir.TimeDateStamp;
                loadConfig.majorVersion = lcfgDir.MajorVersion;
                loadConfig.minorVersion = lcfgDir.MinorVersion;
                loadConfig.globFlagsClear = lcfgDir.GlobalFlagsClear;
                loadConfig.globFlagsSet = lcfgDir.GlobalFlagsSet;
                loadConfig.critSecDefTimeOut = lcfgDir.CriticalSectionDefaultTimeout;
                loadConfig.deCommitFreeBlockThreshold = lcfgDir.DeCommitFreeBlockThreshold;
                loadConfig.deCommitTotalFreeThreshold = lcfgDir.DeCommitTotalFreeThreshold;
                loadConfig.lockPrefixTable = lcfgDir.LockPrefixTable;
                loadConfig.maxAllocSize = lcfgDir.MaximumAllocationSize;
                loadConfig.virtualMemoryThreshold = lcfgDir.VirtualMemoryThreshold;
                loadConfig.processAffinityMask = lcfgDir.ProcessAffinityMask;
                loadConfig.processHeapFlags = lcfgDir.ProcessHeapFlags;
                loadConfig.CSDVersion = lcfgDir.CSDVersion;
                loadConfig.reserved1 = lcfgDir.Reserved1;
                loadConfig.editList = lcfgDir.EditList;
                loadConfig.securityCookie = lcfgDir.SecurityCookie;
                loadConfig.SEHandlerTable = lcfgDir.SEHandlerTable;
                loadConfig.SEHandlerCount = lcfgDir.SEHandlerCount;
                loadConfig.guardCFCheckFunctionPtr = lcfgDir.GuardCFCheckFunctionPointer;
                loadConfig.reserved2 = lcfgDir.Reserved2;
                loadConfig.guardCFFunctionTable = lcfgDir.GuardCFFunctionTable;
                loadConfig.guardCFFunctionCount = lcfgDir.GuardCFFunctionCount;
                loadConfig.guardFlags = lcfgDir.GuardFlags;
            }

            lcfgDirSect->SetPlacedMemory( loadConfig.allocEntry, lcfgDataDir.VirtualAddress, lcfgDataDir.Size );
        }
    }

    // * BOUND IMPORT DIR.
    std::vector <PEBoundImports> boundImports;
    {
        const IMAGE_DATA_DIRECTORY& boundDataDir = dataDirs[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ];

        if ( boundDataDir.VirtualAddress != 0 )
        {
#if 0
            const DWORD numDescs = ( boundDataDir.Size / sizeof( DWORD ) );

            const DWORD *boundImportDescsOffsets = (const DWORD*)GetPEDataPointer( boundDataDir.VirtualAddress, boundDataDir.Size );

            if ( !boundImportDescsOffsets )
                throw std::exception( "invalid PE bound imports directory" );

            // Read all bound import descriptors.
            for ( size_t n = 0; n < numDescs; n++ )
            {
                DWORD boundImportDescOffset = boundImportDescsOffsets[ n ];

                if ( boundImportDescOffset == NULL )
                    continue;

                const IMAGE_BOUND_IMPORT_DESCRIPTOR *desc = (const IMAGE_BOUND_IMPORT_DESCRIPTOR*)GetPEDataPointer( boundImportDescOffset, sizeof( IMAGE_BOUND_IMPORT_DESCRIPTOR ) );

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
#endif
            throw std::exception( "bound import loading not implemented, because not documented and no example" );

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
            PESection *delayLoadDescsSect;
            PEDataStream delayLoadDescsStream;
            {
                bool gotStream = sections.GetPEDataStream( delayDataDir.VirtualAddress, delayLoadDescsStream, &delayLoadDescsSect );

                if ( !gotStream )
                    throw std::exception( "invalid PE delay loads directory" );
            }

            delayLoadDescsSect->SetPlacedMemory( this->delayLoadsAllocEntry, delayDataDir.VirtualAddress, delayDataDir.Size );

            const DWORD numDelayLoads = ( delayDataDir.Size / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) );

            delayLoads.reserve( numDelayLoads );

            // Store all of the details.
            for ( size_t n = 0; n < numDelayLoads; n++ )
            {
                // Seek to this descriptor.
                delayLoadDescsStream.Seek( n * sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) );

                IMAGE_DELAYLOAD_DESCRIPTOR delayLoad;
                delayLoadDescsStream.Read( &delayLoad, sizeof(delayLoad) );

                PEDelayLoadDesc desc;
                desc.attrib = delayLoad.Attributes.AllAttributes;
                
                // Read DLL name.
                if ( delayLoad.DllNameRVA != 0 )
                {
                    PESection *dllNamePtrSect;
                    {
                        bool gotName = sections.ReadPEString( delayLoad.DllNameRVA, desc.DLLName, &dllNamePtrSect );

                        if ( !gotName )
                            throw std::exception( "failed to read PE delay load desc DLL name" );
                    }

                    dllNamePtrSect->SetPlacedMemory( desc.DLLName_allocEntry, delayLoad.DllNameRVA );
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

    inline DWORD AllocateAny( DWORD peSize, DWORD peAlignment = sizeof(DWORD) )
    {
        peFileAlloc::allocInfo alloc_data;

        if ( internalAlloc.FindSpace( peSize, alloc_data, peAlignment ) == false )
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

    inline DWORD GetSpanSize( DWORD alignment )
    {
        return ALIGN_SIZE( internalAlloc.GetSpanSize(), alignment );
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

PEFile::PESection::PESection( void ) : stream( NULL, 0, streamAllocMan )
{
    this->virtualSize = 0;
    this->virtualAddr = 0;
    this->chars.sect_hasNoPadding = true;
    this->chars.sect_containsCode = false;
    this->chars.sect_containsInitData = false;
    this->chars.sect_containsUninitData = false;
    this->chars.sect_link_other = false;
    this->chars.sect_link_info = false;
    this->chars.sect_link_remove = false;
    this->chars.sect_link_comdat = false;
    this->chars.sect_noDeferSpecExcepts = false;
    this->chars.sect_gprel = false;
    this->chars.sect_mem_farData = false;
    this->chars.sect_mem_purgeable = false;
    this->chars.sect_mem_16bit = false;
    this->chars.sect_mem_locked = false;
    this->chars.sect_mem_preload = false;
    this->chars.sect_alignment = eAlignment::BYTES_1;
    this->chars.sect_link_nreloc_ovfl = false;
    this->chars.sect_mem_discardable = false;
    this->chars.sect_mem_not_cached = false;
    this->chars.sect_mem_not_paged = false;
    this->chars.sect_mem_shared = false;
    this->chars.sect_mem_execute = false;
    this->chars.sect_mem_read = true;
    this->chars.sect_mem_write = false;
    this->isFinal = false;
    this->ownerImage = NULL;
}

PEFile::PESection::~PESection( void )
{
    // Destruction requires several undo-operations related to PE validity.
    // * all active section allocations have to be invalidated (they can be)
    {
        LIST_FOREACH_BEGIN( PESectionAllocation, this->dataAllocList.root, sectionNode )

            item->theSection = NULL;
            item->sectOffset = 0;
            item->dataSize = 0;

        LIST_FOREACH_END

        this->dataAlloc.Clear();
        LIST_CLEAR( this->dataAllocList.root );
    }
    // * all active placed offsets that refer to this section must be invalidated (write a dead-pointer instead)
    {
        LIST_FOREACH_BEGIN( PEPlacedOffset, this->RVAreferalList.root, targetNode )

            item->targetSect = NULL;
            item->dataOffset = 0;
            item->offsetIntoSect = 0;

        LIST_FOREACH_END

        LIST_CLEAR( this->RVAreferalList.root );
    }

    // Remove us from the PE image, if inside.
    this->unregisterOwnerImage();
}

// Allocation methods of PESection.
std::uint32_t PEFile::PESection::Allocate( PESectionAllocation& allocBlock, std::uint32_t allocSize, std::uint32_t alignment )
{
    // Final sections cannot be allocated on.
    assert( this->isFinal == false );

    // We want to allocate it anywhere.
    sectionSpaceAlloc_t::allocInfo ainfo;

    bool foundSpace = this->dataAlloc.FindSpace( allocSize, ainfo, alignment );

    if ( !foundSpace )
    {
        throw std::exception( "failed to allocate space inside PEFile section" );
    }

    this->dataAlloc.PutBlock( &allocBlock.sectionBlock, ainfo );

    // Update meta-data.
    std::uint32_t alloc_off = allocBlock.sectionBlock.slice.GetSliceStartPoint();

    assert( allocBlock.theSection == NULL );

    allocBlock.theSection = this;
    allocBlock.sectOffset = alloc_off;
    allocBlock.dataSize = allocSize;

    LIST_INSERT( this->dataAllocList.root, allocBlock.sectionNode );

    return alloc_off;
}

void PEFile::PESectionAllocation::WriteToSection( const void *dataPtr, std::uint32_t dataSize, std::int32_t dataOff )
{
    PESection *allocSect = this->theSection;

    if ( !allocSect )
    {
        throw std::exception( "invalid write section call on unallocated construct" );
    }

    allocSect->stream.Seek( dataOff );
    allocSect->stream.Write( dataPtr, dataSize );
}

void PEFile::PESectionAllocation::RegisterTargetRVA( std::uint32_t patchOffset, PESection *targetSect, std::uint32_t targetOff )
{
    this->theSection->RegisterTargetRVA( this->sectOffset + patchOffset, targetSect, targetOff );
}

void PEFile::PESectionAllocation::RegisterTargetRVA( std::uint32_t patchOffset, const PESectionAllocation& targetInfo, std::uint32_t targetOff )
{
    this->RegisterTargetRVA( patchOffset, targetInfo.theSection, targetInfo.sectOffset + targetOff );
}

void PEFile::PESection::SetPlacedMemory( PESectionAllocation& blockMeta, std::uint32_t allocOff, std::uint32_t allocSize )
{
    assert( this->isFinal == true );

    // We keep the block structure invalid.
    assert( blockMeta.theSection == NULL );

    // Verify that this allocation really is inside the section.
    {
        typedef sliceOfData <std::uint32_t> streamSlice_t;

        streamSlice_t sectionSlice( this->virtualAddr, this->virtualSize );
        
        streamSlice_t reqSlice( allocOff, std::max( allocSize, 1u ) );

        streamSlice_t::eIntersectionResult intResult = reqSlice.intersectWith( sectionSlice );

        assert( intResult == streamSlice_t::INTERSECT_INSIDE || intResult == streamSlice_t::INTERSECT_EQUAL );
    }

    blockMeta.sectOffset = ( allocOff - this->virtualAddr );
    blockMeta.dataSize = allocSize;
    blockMeta.theSection = this;

    LIST_INSERT( this->dataAllocList.root, blockMeta.sectionNode );
}

std::uint32_t PEFile::PESection::GetPENativeFlags( void ) const
{
    std::uint32_t chars = 0;

    if ( this->chars.sect_hasNoPadding )
    {
        chars |= IMAGE_SCN_TYPE_NO_PAD;
    }

    if ( this->chars.sect_containsCode )
    {
        chars |= IMAGE_SCN_CNT_CODE;
    }

    if ( this->chars.sect_containsInitData )
    {
        chars |= IMAGE_SCN_CNT_INITIALIZED_DATA;
    }

    if ( this->chars.sect_containsUninitData )
    {
        chars |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
    }

    if ( this->chars.sect_link_other )
    {
        chars |= IMAGE_SCN_LNK_OTHER;
    }

    if ( this->chars.sect_link_info )
    {
        chars |= IMAGE_SCN_LNK_INFO;
    }

    if ( this->chars.sect_link_remove )
    {
        chars |= IMAGE_SCN_LNK_REMOVE;
    }

    if ( this->chars.sect_link_comdat )
    {
        chars |= IMAGE_SCN_LNK_COMDAT;
    }

    if ( this->chars.sect_noDeferSpecExcepts )
    {
        chars |= IMAGE_SCN_NO_DEFER_SPEC_EXC;
    }

    if ( this->chars.sect_gprel )
    {
        chars |= IMAGE_SCN_GPREL;
    }

    if ( this->chars.sect_mem_farData )
    {
        chars |= IMAGE_SCN_MEM_FARDATA;
    }

    if ( this->chars.sect_mem_purgeable )
    {
        chars |= IMAGE_SCN_MEM_PURGEABLE;
    }

    if ( this->chars.sect_mem_16bit )
    {
        chars |= IMAGE_SCN_MEM_16BIT;
    }

    if ( this->chars.sect_mem_locked )
    {
        chars |= IMAGE_SCN_MEM_LOCKED;
    }

    if ( this->chars.sect_mem_preload )
    {
        chars |= IMAGE_SCN_MEM_PRELOAD;
    }

    switch( this->chars.sect_alignment )
    {
    case eAlignment::BYTES_UNSPECIFIED: break;  // unknown.
    case eAlignment::BYTES_1:           chars |= IMAGE_SCN_ALIGN_1BYTES; break;
    case eAlignment::BYTES_2:           chars |= IMAGE_SCN_ALIGN_2BYTES; break;
    case eAlignment::BYTES_4:           chars |= IMAGE_SCN_ALIGN_4BYTES; break;
    case eAlignment::BYTES_8:           chars |= IMAGE_SCN_ALIGN_8BYTES; break;
    case eAlignment::BYTES_16:          chars |= IMAGE_SCN_ALIGN_16BYTES; break;
    case eAlignment::BYTES_32:          chars |= IMAGE_SCN_ALIGN_32BYTES; break;
    case eAlignment::BYTES_64:          chars |= IMAGE_SCN_ALIGN_64BYTES; break;
    case eAlignment::BYTES_128:         chars |= IMAGE_SCN_ALIGN_128BYTES; break;
    case eAlignment::BYTES_256:         chars |= IMAGE_SCN_ALIGN_256BYTES; break;
    case eAlignment::BYTES_512:         chars |= IMAGE_SCN_ALIGN_512BYTES; break;
    case eAlignment::BYTES_1024:        chars |= IMAGE_SCN_ALIGN_1024BYTES; break;
    case eAlignment::BYTES_2048:        chars |= IMAGE_SCN_ALIGN_2048BYTES; break;
    case eAlignment::BYTES_4096:        chars |= IMAGE_SCN_ALIGN_4096BYTES; break;
    case eAlignment::BYTES_8192:        chars |= IMAGE_SCN_ALIGN_8192BYTES; break;
    default:                            break;  // should never happen.
    }

    if ( this->chars.sect_link_nreloc_ovfl )
    {
        chars |= IMAGE_SCN_LNK_NRELOC_OVFL;
    }

    if ( this->chars.sect_mem_discardable )
    {
        chars |= IMAGE_SCN_MEM_DISCARDABLE;
    }

    if ( this->chars.sect_mem_not_cached )
    {
        chars |= IMAGE_SCN_MEM_NOT_CACHED;
    }

    if ( this->chars.sect_mem_not_paged )
    {
        chars |= IMAGE_SCN_MEM_NOT_PAGED;
    }

    if ( this->chars.sect_mem_shared )
    {
        chars |= IMAGE_SCN_MEM_SHARED;
    }

    if ( this->chars.sect_mem_execute )
    {
        chars |= IMAGE_SCN_MEM_EXECUTE;
    }

    if ( this->chars.sect_mem_read )
    {
        chars |= IMAGE_SCN_MEM_READ;
    }

    if ( this->chars.sect_mem_write )
    {
        chars |= IMAGE_SCN_MEM_WRITE;
    }

    return chars;
}

void PEFile::PESection::RegisterTargetRVA( std::uint32_t patchOffset, PESection *targetSect, std::uint32_t targetOffset )
{
    this->placedOffsets.emplace_back( patchOffset, targetSect, targetOffset );
}

void PEFile::PESection::RegisterTargetRVA( std::uint32_t patchOffset, const PESectionAllocation& targetInfo )
{
    RegisterTargetRVA( patchOffset, targetInfo.theSection, targetInfo.sectOffset );
}

void PEFile::PESection::Finalize( void )
{
    if ( this->isFinal )
        return;

    // The image does not have a virtualSize parameter yet.
    assert( this->virtualSize == 0 );
    
    // It is created by taking the rawdata size.
    // The image will later round it to section alignment.
    this->virtualSize = ( (decltype(virtualSize))stream.Size() );

    // Final images are consider not allocatable anymore
    // so lets get rid of allocation information.
    this->dataAlloc.Clear();

    this->isFinal = true;
}

template <typename keyType, typename mapType>
inline decltype( auto ) FindMapValue( mapType& map, const keyType& key )
{
    const auto& foundIter = map.find( key );

    if ( foundIter == map.end() )
        return (decltype(&foundIter->second))NULL;

    return &foundIter->second;
}

void PEFile::CommitDataDirectories( void )
{
    // TODO: ensure that data has been properly committed to data sections which had to be.
    // First allocate a new section that should serve as allocation target.
    {
        PESection rdonlySect;
        rdonlySect.shortName = ".the_gta";

        PESection dataSect;
        dataSect.shortName = ".quiret";

        // We need to perform allocations onto directory structures for all meta-data.
        {
            // We first have to allocate everything.

            // * EXPORT DIRECTORY.
            PEExportDir& expDir = this->exportDir;

            if ( expDir.chars != 0 || expDir.name.empty() == false || expDir.functions.empty() == false )
            {
                // Allocate each directory with its own allocator.
                struct expfunc_allocInfo
                {
                    DWORD forwarder_off;
                    PESectionAllocation name_off;
                };
            
                std::unordered_map <size_t, expfunc_allocInfo> allocInfos;

                // Determine if we need to allocate a function name mapping.
                size_t numNamedEntries = 0;

                // Allocate forwarder RVAs.
                const size_t numExportEntries = expDir.functions.size();

                PESectionAllocation expDirAlloc;
                {
                    FileSpaceAllocMan expAllocMan;

                    expAllocMan.AllocateAt( 0, sizeof( IMAGE_EXPORT_DIRECTORY ) );

                    for ( size_t n = 0; n < numExportEntries; n++ )
                    {
                        const PEExportDir::func& funcEntry = expDir.functions[ n ];

                        if ( funcEntry.isForwarder )
                        {
                            // Allocate an entry for the forwarder.
                            const size_t strSize = ( funcEntry.forwarder.size() + 1 );

                            DWORD forwOffset = expAllocMan.AllocateAny( strSize, 1 );

                            expfunc_allocInfo& info = allocInfos[ n ];
                            info.forwarder_off = forwOffset;
                        }

                        // Are we a named entry? If yes we will need a mapping.
                        if ( funcEntry.isNamed )
                        {
                            // Allocate an entry for the name.
                            const size_t strSize = ( funcEntry.name.size() + 1 );
                    
                            expfunc_allocInfo& info = allocInfos[ n ];
                            rdonlySect.Allocate( info.name_off, strSize, 1 );

                            // We definately need a name-ordinal map.
                            numNamedEntries++;
                        }
                    }

                    // Since all entries inside the alloc directory are indeed allocated,
                    // we can create the allocation in the section!
                    rdonlySect.Allocate( expDirAlloc, expAllocMan.GetSpanSize( 1 ), sizeof(DWORD) );
                }

                // Now allocate the necessary arrays for export data.
                // Data offset, optional name ptr and orderinal maps.
                const size_t dataOffTableSize = ( sizeof(DWORD) * numExportEntries );

                PESectionAllocation dataTabOffAlloc;
                rdonlySect.Allocate( dataTabOffAlloc, dataOffTableSize );

                PESectionAllocation namePtrTableAlloc;
                PESectionAllocation ordMapTableAlloc;

                if ( numNamedEntries != 0 )
                {
                    const size_t namePtrTableSize = ( sizeof(DWORD) * numNamedEntries );

                    rdonlySect.Allocate( namePtrTableAlloc, namePtrTableSize );

                    const size_t ordMapTableSize = ( sizeof(DWORD) * numNamedEntries );

                    rdonlySect.Allocate( ordMapTableAlloc, ordMapTableSize, sizeof(WORD) );
                }

                // Also need to write the module name.
                const size_t moduleNameSize = ( expDir.name.size() + 1 );

                PESectionAllocation moduleNameAlloc;
                rdonlySect.Allocate( moduleNameAlloc, moduleNameSize, 1 );

                // At this point the entire export directory data is allocated.
                // Let's write it!
                IMAGE_EXPORT_DIRECTORY header;
                header.Characteristics = expDir.chars;
                header.TimeDateStamp = expDir.timeDateStamp;
                header.MajorVersion = expDir.majorVersion;
                header.MinorVersion = expDir.minorVersion;
                header.Name = 0;
                rdonlySect.RegisterTargetRVA( expDirAlloc.sectOffset + offsetof(IMAGE_EXPORT_DIRECTORY, Name), moduleNameAlloc );
                header.Base = expDir.ordinalBase;
                header.NumberOfFunctions = (DWORD)numExportEntries;
                header.NumberOfNames = (DWORD)numNamedEntries;
                header.AddressOfFunctions = 0;
                expDirAlloc.RegisterTargetRVA( offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfFunctions), dataTabOffAlloc );
                header.AddressOfNames = 0;
                expDirAlloc.RegisterTargetRVA( offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNames), namePtrTableAlloc );
                header.AddressOfNameOrdinals = 0;
                expDirAlloc.RegisterTargetRVA( offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals), ordMapTableAlloc );

                expDirAlloc.WriteToSection( &header, sizeof(header), 0 );

                // Write module name.
                moduleNameAlloc.WriteToSection( expDir.name.c_str(), moduleNameSize );
            
                // Write export offsets.
                for ( size_t n = 0; n < numExportEntries; n++ )
                {
                    const PEExportDir::func& funcInfo = expDir.functions[ n ];

                    // First shedule the offset for writing.
                    const std::uint32_t dataTabItemOff = ( sizeof(DWORD) * n );

                    const expfunc_allocInfo *finfo = FindMapValue( allocInfos, n );

                    if ( funcInfo.isForwarder )
                    {
                        assert( finfo != NULL );

                        dataTabOffAlloc.RegisterTargetRVA( dataTabItemOff, expDirAlloc, finfo->forwarder_off );
                    }
                    else
                    {
                        dataTabOffAlloc.RegisterTargetRVA( dataTabItemOff, funcInfo.forwExpFuncSection, funcInfo.forwExpFuncOffset );
                    }
                }

                // Maybe write a name ordinal map.
                if ( numNamedEntries != 0 )
                {
                    assert( namePtrTableAlloc.IsAllocated() == true && ordMapTableAlloc.IsAllocated() == true );

                    DWORD index = 0;

                    for ( const auto& keyIter : allocInfos )
                    {
                        WORD ordinal = (WORD)keyIter.first;

                        // Write this name map entry.
                        const size_t namePtrOff = ( sizeof(DWORD) * index );
                        const size_t ordOff = ( sizeof(WORD) * index );

                        namePtrTableAlloc.RegisterTargetRVA( namePtrOff, keyIter.second.name_off );
                        ordMapTableAlloc.WriteToSection( &ordinal, sizeof(ordinal), ordOff );
                    }
                }

                // After write-phase we can remember the new offsets.
                expDir.nameAllocEntry = std::move( moduleNameAlloc );
                expDir.funcAddressAllocEntry = std::move( dataTabOffAlloc );
                expDir.funcNamesAllocEntry = std::move( namePtrTableAlloc );
                expDir.funcOrdinalsAllocEntry = std::move( ordMapTableAlloc );

                for ( size_t n = 0; n < numExportEntries; n++ )
                {
                    PEExportDir::func& funcEntry = expDir.functions[ n ];

                    expfunc_allocInfo *finfo = FindMapValue( allocInfos, n );

                    if ( funcEntry.isForwarder )
                    {
                        assert( finfo != NULL );

                        funcEntry.forwExpFuncOffset = finfo->forwarder_off;
                        funcEntry.forwExpFuncSection = expDirAlloc.theSection;
                    }

                    if ( funcEntry.isNamed )
                    {
                        funcEntry.nameAllocEntry = std::move( finfo->name_off );
                    }
                }

                // Last but not least, our export directory pointer.
                expDir.allocEntry = std::move( expDirAlloc );
            }
        }

        // SECTION-ALLOC PHASE.
        // Put all sections that we added into virtualAddress space.
        // (by the way, pretty retarded that Microsoft does not allow __forceinline on lambdas.)

        if ( rdonlySect.IsEmpty() == false )
        {
            rdonlySect.Finalize();

            this->AddSection( std::move( rdonlySect ) );
        }
        if ( dataSect.IsEmpty() == false )
        {
            dataSect.Finalize();

            this->AddSection( std::move( dataSect ) );
        }
    }

    // After writing and storing all allocation information we should write the RVAs
    // that we previously sheduled. This is possible because now every section has been
    // registered in the image and placed somewhere on virtual memory.
    
    LIST_FOREACH_BEGIN( PESection, this->sections.sectionList.root, sectionNode )

        for ( const PESection::PEPlacedOffset& placedOff : item->placedOffsets )
        {
            // Parameters to write RVA.
            PESection *writeSect = item;
            std::uint32_t writeOff = placedOff.dataOffset;

            // Parameters to calculate RVA.
            PESection *targetSect = placedOff.targetSect;
            std::uint32_t targetOff = placedOff.offsetIntoSect;

            assert( targetSect->isFinal == true );

            // Calculate target RVA.
            std::uint32_t targetRVA = ( targetSect->virtualAddr + targetOff );

            // Write the RVA.
            writeSect->stream.Seek( (std::int32_t)writeOff );
            writeSect->stream.WriteUInt32( targetRVA );
        }

    LIST_FOREACH_END
}

PEFile::PESectionMan::PESectionMan( std::uint32_t sectionAlignment, std::uint32_t imageBase )
{
    this->numSections = 0;
    this->sectionAlignment = sectionAlignment;
    this->imageBase = imageBase;
}

PEFile::PESectionMan::~PESectionMan( void )
{
    // Destroy all sections that still reside in us.
    LIST_FOREACH_BEGIN( PESection, this->sectionList.root, sectionNode )

        item->ownerImage = NULL;

        delete item;

    LIST_FOREACH_END

    LIST_CLEAR( this->sectionList.root );

    this->numSections = 0;
}

PEFile::PESection* PEFile::PESectionMan::AddSection( PESection&& theSection )
{
    assert( theSection.ownerImage == NULL );

    // Before proceeding we must have finalized the section.
    // A final section must have a valid virtualSize region of all its allocations.
    assert( theSection.isFinal == true );

    // Images have a base address to start allocations from that is decided from the
    // very beginning.
    const std::uint32_t imageBase = this->imageBase;

    // When the section is bound to our image, we will give it an aligned size
    // based on sectionAlignment.
    const std::uint32_t sectionAlignment = this->sectionAlignment;

    std::uint32_t alignedSectionSize = ALIGN_SIZE( theSection.virtualSize, sectionAlignment );

    // We allocate space for this section inside of our executable.
    sectAllocSemantics::allocInfo allocInfo;

    bool foundSpace = sectAllocSemantics::FindSpace( sectVirtualAllocMan, alignedSectionSize, allocInfo, sectionAlignment, imageBase );

    if ( !foundSpace )
    {
        // In very critical scenarios the executable may be full!
        return false;
    }

    // We need to move the section into memory we control.
    PESection *ourSect = new PESection( std::move( theSection ) );

    // Since we did find some space lets register the new section candidate.
    ourSect->virtualAddr = allocInfo.slice.GetSliceStartPoint();
    ourSect->virtualSize = std::move( alignedSectionSize );

    // Put after correct block.
    LIST_INSERT( *allocInfo.blockToAppendAt.node_iter, ourSect->sectionNode );

    ourSect->ownerImage = this;

    this->numSections++;

    return ourSect;
}

PEFile::PESection* PEFile::PESectionMan::PlaceSection( PESection&& theSection )
{
    assert( theSection.ownerImage == NULL );

    // The section must be final because it requires a given offset and size.
    assert( theSection.isFinal == true );

    assert( theSection.virtualSize != 0 );

    // In this routine we place a section at it's requested aligned offset.
    const std::uint32_t sectionAlignment = this->sectionAlignment;

    std::uint32_t alignSectOffset = ALIGN( theSection.virtualAddr, 1u, sectionAlignment );
    std::uint32_t alignSectSize = ALIGN_SIZE( theSection.virtualSize, sectionAlignment );

    sectAllocSemantics::allocInfo allocInfo;

    bool obtSpace = sectAllocSemantics::ObtainSpaceAt( sectVirtualAllocMan, alignSectOffset, alignSectSize, allocInfo );

    if ( !obtSpace )
    {
        // If this is triggered then most likely there is an invalid PE section configuration.
        return NULL;
    }

    // Now put the section into our space.
    PESection *ourSect = new PESection( std::move( theSection ) );

    ourSect->virtualAddr = std::move( alignSectOffset );
    ourSect->virtualSize = std::move( alignSectSize );

    // Put after correct block.
    LIST_INSERT( *allocInfo.blockToAppendAt.node_iter, ourSect->sectionNode );

    ourSect->ownerImage = this;

    this->numSections++;

    return ourSect;
}

bool PEFile::PESectionMan::RemoveSection( PESection *section )
{
    if ( section->ownerImage != this )
        return false;

    LIST_REMOVE( section->sectionNode );

    section->ownerImage = NULL;

    this->numSections--;

    delete section;

    return true;
}

PEFile::PESection* PEFile::AddSection( PESection&& theSection )
{
    return this->sections.AddSection( std::move( theSection ) );
}

PEFile::PESection* PEFile::PlaceSection( PESection&& theSection )
{
    return this->sections.PlaceSection( std::move( theSection ) );
}

PEFile::PESection* PEFile::FindFirstSectionByName( const char *name )
{
    LIST_FOREACH_BEGIN( PESection, this->sections.sectionList.root, sectionNode )

        if ( item->shortName == name )
            return item;
    
    LIST_FOREACH_END

    return NULL;
}

PEFile::PESection* PEFile::FindFirstAllocatableSection( void )
{
    LIST_FOREACH_BEGIN( PESection, this->sections.sectionList.root, sectionNode )
    
        if ( item->isFinal == false )
            return item;
    
    LIST_FOREACH_END

    return NULL;
}

bool PEFile::RemoveSection( PESection *section )
{
    return sections.RemoveSection( section );
}

void PEFile::WriteToStream( CFile *peStream )
{
    // Write data that requires writing.
    this->CommitDataDirectories();
    
    // Prepare the data directories.
    IMAGE_DATA_DIRECTORY peDataDirs[ IMAGE_NUMBEROF_DIRECTORY_ENTRIES ];
    {
        // Reset everything we do not use.
        memset( peDataDirs, 0, sizeof( peDataDirs ) );

        auto dirRegHelper = []( IMAGE_DATA_DIRECTORY& dataDir, const PESectionAllocation& allocEntry )
        {
            if ( PESection *allocSect = allocEntry.theSection )
            {
                dataDir.VirtualAddress = allocSect->virtualAddr + allocEntry.sectOffset;
                dataDir.Size = allocEntry.dataSize;
            }
            else
            {
                dataDir.VirtualAddress = 0;
                dataDir.Size = 0;
            }
        };

        dirRegHelper( peDataDirs[ IMAGE_DIRECTORY_ENTRY_EXPORT ], this->exportDir.allocEntry );
        dirRegHelper( peDataDirs[ IMAGE_DIRECTORY_ENTRY_IMPORT ], this->importsAllocEntry );
        dirRegHelper( peDataDirs[ IMAGE_DIRECTORY_ENTRY_RESOURCE ], this->resAllocEntry );
        dirRegHelper( peDataDirs[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ], this->exceptAllocEntry );
        
        // Security.
        {
            IMAGE_DATA_DIRECTORY& secDataDir = peDataDirs[ IMAGE_DIRECTORY_ENTRY_SECURITY ];

            secDataDir.VirtualAddress = this->security.secDataOffset;
            secDataDir.Size = this->security.secDataSize;
        }

        dirRegHelper( peDataDirs[ IMAGE_DIRECTORY_ENTRY_BASERELOC ], this->baseRelocAllocEntry );
        dirRegHelper( peDataDirs[ IMAGE_DIRECTORY_ENTRY_DEBUG ], this->debugInfo.allocEntry );
        
        // Architecture.
        {
            IMAGE_DATA_DIRECTORY& archDataDir = peDataDirs[ IMAGE_DIRECTORY_ENTRY_ARCHITECTURE ];

            archDataDir.VirtualAddress = 0;
            archDataDir.Size = 0;
        }

        // Global pointer.
        {
            IMAGE_DATA_DIRECTORY& gptrDataDir = peDataDirs[ IMAGE_DIRECTORY_ENTRY_GLOBALPTR ];

            gptrDataDir.VirtualAddress = this->globalPtr.ptrOffset;
            gptrDataDir.Size = 0;
        }

        dirRegHelper( peDataDirs[ IMAGE_DIRECTORY_ENTRY_TLS ], this->tlsInfo.allocEntry );
        dirRegHelper( peDataDirs[ IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG ], this->loadConfig.allocEntry );
        dirRegHelper( peDataDirs[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ], this->boundImportsAllocEntry );
        
        // IAT.
        {
            IMAGE_DATA_DIRECTORY& iatDataDir = peDataDirs[ IMAGE_DIRECTORY_ENTRY_IAT ];

            iatDataDir.VirtualAddress = this->iatThunkAll.thunkDataStart;
            iatDataDir.Size = this->iatThunkAll.thunkDataSize;
        }

        dirRegHelper( peDataDirs[ IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT ], this->delayLoadsAllocEntry );

        // COM descriptor.
        {
            IMAGE_DATA_DIRECTORY& comDescDataDir = peDataDirs[ IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ];

            comDescDataDir.VirtualAddress = this->clrInfo.dataOffset;
            comDescDataDir.Size = this->clrInfo.dataSize;
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
        peDataSize += ( this->sections.numSections * sizeof( IMAGE_SECTION_HEADER ) );

        // TODO: there is "deprecated" information like lineinfo and native relocation
        // info allowed. should we add support? this would mean adding even more size to
        // peDataSize.

        DWORD peDataPos = allocMan.AllocateAny( peDataSize );
            
        IMAGE_PE_HEADER pe_data;
        pe_data.Signature = 'EP';
        pe_data.FileHeader.Machine = this->pe_finfo.machine_id;
        pe_data.FileHeader.NumberOfSections = (WORD)this->sections.numSections;
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
        // Offset of section data.
        const DWORD sectHeadOffset = ( peOptHeaderOffset + pe_data.FileHeader.SizeOfOptionalHeader );

        std::uint32_t sectionAlignment = this->sections.GetSectionAlignment();

        // Allocate section data.
        std::vector <IMAGE_SECTION_HEADER> sect_headers;
        {
            DWORD sectIndex = 0;

            LIST_FOREACH_BEGIN( PESection, this->sections.sectionList.root, sectionNode )
            
                // Allocate this section.
                const DWORD allocVirtualSize = ALIGN_SIZE( item->virtualSize, sectionAlignment );
                const DWORD rawDataSize = (DWORD)item->stream.Size();

                DWORD sectOffset = allocMan.AllocateAny( rawDataSize, this->peOptHeader.fileAlignment );

                IMAGE_SECTION_HEADER header;
                strncpy( (char*)header.Name, item->shortName.c_str(), _countof(header.Name) );
                header.VirtualAddress = item->virtualAddr;
                header.Misc.VirtualSize = allocVirtualSize;
                header.SizeOfRawData = rawDataSize;
                header.PointerToRawData = sectOffset;
                header.PointerToRelocations = 0;    // TODO: change this if native relocations become a thing.
                header.PointerToLinenumbers = 0;    // TODO: change this if linenumber data becomes a thing
                header.NumberOfRelocations = 0;
                header.NumberOfLinenumbers = 0;
                header.Characteristics = item->GetPENativeFlags();

                // Write it.
                {
                    // TODO: remember to update this logic if we support relocations or linenumbers.
                    const DWORD sectHeadFileOff = ( sectHeadOffset + sizeof(header) * sectIndex );

                    PEWrite( peStream, sectHeadFileOff, sizeof(header), &header );
                }

                // Also write the PE data.
                PEWrite( peStream, sectOffset, rawDataSize, item->stream.Data() );

                // TODO: make sure that sections are written in ascending order of their virtual addresses.

                sect_headers.push_back( std::move( header ) );

                sectIndex++;
            
            LIST_FOREACH_END
        }
        // Do note that the serialized section headers are ordered parallel to the section meta-data in PEFile.
        // So that the indices match for serialized and runtime data.

        // Calculate the required image size in memory.
        // Since sections are address sorted, this is pretty easy.
        DWORD memImageSize = sections.GetImageSize();

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
            optHeader.SizeOfUninitializedData = this->peOptHeader.sizeOfUninitializedData;
            optHeader.AddressOfEntryPoint = this->peOptHeader.addressOfEntryPoint;
            optHeader.BaseOfCode = this->peOptHeader.baseOfCode;
            optHeader.ImageBase = this->peOptHeader.imageBase;
            optHeader.SectionAlignment = sectionAlignment;
            optHeader.FileAlignment = this->peOptHeader.fileAlignment;
            optHeader.MajorOperatingSystemVersion = this->peOptHeader.majorOSVersion;
            optHeader.MinorOperatingSystemVersion = this->peOptHeader.minorOSVersion;
            optHeader.MajorImageVersion = this->peOptHeader.majorImageVersion;
            optHeader.MinorImageVersion = this->peOptHeader.minorImageVersion;
            optHeader.MajorSubsystemVersion = this->peOptHeader.majorSubsysVersion;
            optHeader.MinorSubsystemVersion = this->peOptHeader.minorSubsysVersion;
            optHeader.Win32VersionValue = this->peOptHeader.win32VersionValue;
            optHeader.SizeOfImage = memImageSize;
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
            memcpy( optHeader.DataDirectory, peDataDirs, sizeof( peDataDirs ) );

            PEWrite( peStream, peOptHeaderOffset, sizeof(optHeader), &optHeader );
        }
        else
        {
            IMAGE_OPTIONAL_HEADER32 optHeader;
            optHeader.Magic = 0x010B;   // todo: think about this, and 64bit support. (PE32+)
            optHeader.MajorLinkerVersion = this->peOptHeader.majorLinkerVersion;
            optHeader.MinorLinkerVersion = this->peOptHeader.minorLinkerVersion;
            optHeader.SizeOfCode = this->peOptHeader.sizeOfCode;
            optHeader.SizeOfInitializedData = this->peOptHeader.sizeOfInitializedData;
            optHeader.SizeOfUninitializedData = this->peOptHeader.sizeOfUninitializedData;
            optHeader.AddressOfEntryPoint = this->peOptHeader.addressOfEntryPoint;
            optHeader.BaseOfCode = this->peOptHeader.baseOfCode;
            optHeader.BaseOfData = this->peOptHeader.baseOfData;    // TODO: maybe this needs updating if we change from 32bit to 64bit.
            optHeader.ImageBase = (DWORD)this->peOptHeader.imageBase;
            optHeader.SectionAlignment = sectionAlignment;
            optHeader.FileAlignment = this->peOptHeader.fileAlignment;
            optHeader.MajorOperatingSystemVersion = this->peOptHeader.majorOSVersion;
            optHeader.MinorOperatingSystemVersion = this->peOptHeader.minorOSVersion;
            optHeader.MajorImageVersion = this->peOptHeader.majorImageVersion;
            optHeader.MinorImageVersion = this->peOptHeader.minorImageVersion;
            optHeader.MajorSubsystemVersion = this->peOptHeader.majorSubsysVersion;
            optHeader.MinorSubsystemVersion = this->peOptHeader.minorSubsysVersion;
            optHeader.Win32VersionValue = this->peOptHeader.win32VersionValue;
            optHeader.SizeOfImage = memImageSize;
            optHeader.SizeOfHeaders = ALIGN_SIZE( peDataSize, this->peOptHeader.fileAlignment );
            optHeader.CheckSum = this->peOptHeader.checkSum;    // TODO: Windows Critical components need to update this.
            optHeader.Subsystem = this->peOptHeader.subsys;
            optHeader.DllCharacteristics = this->GetPENativeDLLOptFlags();
            optHeader.SizeOfStackReserve = (DWORD)this->peOptHeader.sizeOfStackReserve;
            optHeader.SizeOfStackCommit = (DWORD)this->peOptHeader.sizeOfStackCommit;
            optHeader.SizeOfHeapReserve = (DWORD)this->peOptHeader.sizeOfHeapReserve;
            optHeader.SizeOfHeapCommit = (DWORD)this->peOptHeader.sizeOfHeapCommit;
            optHeader.LoaderFlags = this->peOptHeader.loaderFlags;
            optHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;   // TODO: maybe make this dynamic.
            memcpy( optHeader.DataDirectory, peDataDirs, sizeof( peDataDirs ) );

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
    LIST_FOREACH_BEGIN( PESection, this->sections.sectionList.root, sectionNode )
    
        if ( item->relocations.size() != 0 )
            return true;
    
    LIST_FOREACH_END

    // Check the relocation data.
    if ( this->baseRelocs.size() != 0 )
        return true;

    // Nothing found.
    return false;
}

bool PEFile::HasLinenumberInfo( void ) const
{
    // Check sections.
    LIST_FOREACH_BEGIN( PESection, this->sections.sectionList.root, sectionNode )
    
        if ( item->linenumbers.size() != 0 )
            return true;
    
    LIST_FOREACH_END

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

bool PEFile::IsDynamicLinkLibrary( void ) const
{
    return ( this->pe_finfo.isDLL );
}