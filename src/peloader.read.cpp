// Deserialization of PE files.
#include "StdInc.h"
#include "peloader.h"

#include "peloader.internal.hxx"

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
        section.shortName = std::string( (const char*)sectHeader.Name, strnlen( (const char*)sectHeader.Name, _countof(sectHeader.Name) ) );
        section.SetPlacementInfo( sectHeader.VirtualAddress, sectHeader.Misc.VirtualSize );
        
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
                                offStore = ( ptr - exportOffPtrSect->GetVirtualAddress() );
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
    PEResourceDir resourceRoot = std::u16string();  // very weird assignment here, but required; call the constructor.
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

            resourceRoot = LoadResourceDirectory( sections, resDataStream, std::u16string(), resDir );
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