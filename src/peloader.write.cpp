#include "StdInc.h"
#include "peloader.h"

#include "peloader.internal.hxx"

#include <unordered_map>

struct PEAllocFileAllocProxy
{
    template <typename sliceType>
    AINLINE bool IsInAllocationRange( const sliceType& slice )
    {
        // TODO: add limit checking for 32bit allocatibility here (if required).
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

template <typename keyType, typename mapType>
inline decltype( auto ) FindMapValue( mapType& map, const keyType& key )
{
    const auto& foundIter = map.find( key );

    if ( foundIter == map.end() )
        return (decltype(&foundIter->second))NULL;

    return &foundIter->second;
}

namespace ResourceTools
{

struct item_allocInfo
{
    inline item_allocInfo( void )
    {
        dataitem_off = 0;
    }
    inline item_allocInfo( const item_allocInfo& right ) = delete;
    inline item_allocInfo( item_allocInfo&& right ) = default;

    inline item_allocInfo& operator = ( const item_allocInfo& right ) = delete;
    inline item_allocInfo& operator = ( item_allocInfo&& right ) = default;

    // Both entries are relative to the resource directory VA.
    DWORD entry_off;        // Offset to the directory or item entry
    DWORD name_off;         // Offset to the name string (unicode); only valid if child
    DWORD dataitem_off;     // Offset to the resource data item info; only valid if leaf

    std::unordered_map <size_t, item_allocInfo> children;
};

template <typename callbackType>
static AINLINE void ForAllResourceItems( const PEFile::PEResourceDir& resDir, item_allocInfo& allocItem, callbackType& cb )
{
    size_t numChildren = resDir.children.size();

    for ( size_t n = 0; n < numChildren; n++ )
    {
        const PEFile::PEResourceItem *childItem = resDir.children[ n ];

        auto& childAllocItemNode = allocItem.children.find( n );

        assert( childAllocItemNode != allocItem.children.end() );

        item_allocInfo& childAllocItem = childAllocItemNode->second;

        // Execute for us.
        cb( childItem, childAllocItem );

        if ( childItem->itemType == PEFile::PEResourceItem::eType::DIRECTORY )
        {
            const PEFile::PEResourceDir *childItemDir = (const PEFile::PEResourceDir*)childItem;

            // Now for all children.
            ForAllResourceItems( *childItemDir, childAllocItem, cb );
        }
    }
}

};

void PEFile::CommitDataDirectories( void )
{
    bool is64Bit = this->is64Bit;

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
                // Data offset, optional name ptr and ordinal maps.
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
                rdonlySect.RegisterTargetRVA( expDirAlloc.ResolveInternalOffset( offsetof(IMAGE_EXPORT_DIRECTORY, Name) ), moduleNameAlloc );
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

                    for ( auto& keyIter : allocInfos )
                    {
                        size_t funcIndex = keyIter.first;

                        // Write the name.
                        const PEExportDir::func& funcInfo = expDir.functions[ funcIndex ];

                        if ( funcInfo.isNamed )
                        {
                            const std::string& expName = funcInfo.name;

                            const size_t numCharWrite = ( expName.size() + 1 );

                            keyIter.second.name_off.WriteToSection( expName.c_str(), numCharWrite + 1 );
                        }

                        WORD ordinal = (WORD)funcIndex;

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
                        funcEntry.forwExpFuncSection = expDirAlloc.GetSection();
                    }

                    if ( funcEntry.isNamed )
                    {
                        funcEntry.nameAllocEntry = std::move( finfo->name_off );
                    }
                }

                // Last but not least, our export directory pointer.
                expDir.allocEntry = std::move( expDirAlloc );
            }

            // * IMPORT DIRECTORY.
            auto& importDescs = this->imports;

            size_t numImportDescriptors = importDescs.size();

            if ( numImportDescriptors > 0 )
            {
                // Remember that we write a finishing NULL descriptor.
                const size_t writeNumImportDescs = ( numImportDescriptors + 1 );

                // The import descriptor directory consists of a single array of descriptors.
                PESectionAllocation impDescsAlloc;
                rdonlySect.Allocate( impDescsAlloc, sizeof(IMAGE_IMPORT_DESCRIPTOR) * writeNumImportDescs, sizeof(DWORD) );

                for ( size_t n = 0; n < numImportDescriptors; n++ )
                {
                    PEImportDesc& impDesc = importDescs[ n ];

                    // Each descriptor has a list of import IDs, which is an array of
                    // either ordinal or name entries.
                    auto& funcs = impDesc.funcs;

                    size_t numFuncs = funcs.size();

                    if ( numFuncs != 0 )
                    {
                        // The size of an entry depends on PE32 or PE32+.
                        size_t entrySize;

                        if ( is64Bit )
                        {
                            entrySize = sizeof(ULONGLONG);
                        }
                        else
                        {
                            entrySize = sizeof(DWORD);
                        }

                        // We need to end of the array with a zero-entry to describe the end.
                        size_t actualArrayItemCount = ( numFuncs + 1 );

                        PESectionAllocation impNameAllocArrayEntry;
                        rdonlySect.Allocate( impNameAllocArrayEntry, actualArrayItemCount * entrySize, entrySize );

                        for ( size_t n = 0; n < numFuncs; n++ )
                        {
                            PEImportDesc::importFunc& funcInfo = funcs[ n ];

                            ULONGLONG entry = 0;
                            size_t entryWriteOffset = ( entrySize * n );

                            if ( funcInfo.isOrdinalImport )
                            {
                                entry |= funcInfo.ordinal_hint;

                                if ( is64Bit )
                                {
                                    entry |= IMAGE_ORDINAL_FLAG64;
                                }
                                else
                                {
                                    entry |= IMAGE_ORDINAL_FLAG32;
                                }
                            }
                            else
                            {
                                // Dynamic size of the name entry, since it contains optional ordinal hint.
                                size_t funcNameWriteCount = ( funcInfo.name.size() + 1 );
                                size_t nameEntrySize = ( sizeof(WORD) + funcNameWriteCount );

                                // Decide if we have to write a trailing zero byte, as required by the documentation.
                                // It is required if this entry size is not a multiple of sizeof(WORD).
                                bool requiresTrailZeroByte = false;

                                if ( ( nameEntrySize % sizeof(WORD) ) != 0 )
                                {
                                    requiresTrailZeroByte = true;

                                    nameEntrySize++;
                                }

                                PESectionAllocation nameAllocEntry;
                                rdonlySect.Allocate( nameAllocEntry, nameEntrySize, sizeof(WORD) );

                                // Ordinal hint.
                                nameAllocEntry.WriteToSection( &funcInfo.ordinal_hint, sizeof(funcInfo.ordinal_hint), 0 );

                                // Actual name.
                                nameAllocEntry.WriteToSection( funcInfo.name.c_str(), funcNameWriteCount, sizeof(WORD) );

                                if ( requiresTrailZeroByte )
                                {
                                    nameAllocEntry.WriteUInt8( 0, sizeof(WORD) + funcNameWriteCount );
                                }

                                // Because the PE format does not set the flag when it writes a RVA, we
                                // can use our delayed RVA writer routine without modifications.
                                impNameAllocArrayEntry.RegisterTargetRVA( entryWriteOffset, nameAllocEntry );

                                funcInfo.nameAllocEntry = std::move( nameAllocEntry );
                            }

                            // Write the item.
                            if ( is64Bit )
                            {
                                impNameAllocArrayEntry.WriteUInt32( (DWORD)entry, entryWriteOffset );
                            }
                            else
                            {
                                impNameAllocArrayEntry.WriteUInt64( entry, entryWriteOffset );
                            }
                        }

                        // Finish it off with a zero.
                        {
                            if ( is64Bit )
                            {
                                impNameAllocArrayEntry.WriteUInt64( 0, entrySize * numFuncs );
                            }
                            else
                            {
                                impNameAllocArrayEntry.WriteUInt32( 0, entrySize * numFuncs );
                            }
                        }

                        // Remember the new allocation.
                        impDesc.impNameArrayAllocEntry = std::move( impNameAllocArrayEntry );
                    }

                    // Allocate and write the module name that we should import from.
                    {
                        const std::string& DLLName = impDesc.DLLName;

                        const size_t writeCount = ( DLLName.size() + 1 );

                        PESectionAllocation DLLName_allocEntry;
                        rdonlySect.Allocate( DLLName_allocEntry, writeCount, 1 );
                        
                        DLLName_allocEntry.WriteToSection( DLLName.c_str(), writeCount );

                        impDesc.DLLName_allocEntry = std::move( DLLName_allocEntry );
                    }

                    // Since all data is allocated now let us write the descriptor.
                    const size_t descWriteOffset = ( sizeof(IMAGE_IMPORT_DESCRIPTOR) * n );

                    IMAGE_IMPORT_DESCRIPTOR nativeImpDesc;
                    nativeImpDesc.Characteristics = 0;
                    impDescsAlloc.RegisterTargetRVA( descWriteOffset + offsetof(IMAGE_IMPORT_DESCRIPTOR, Characteristics), impDesc.impNameArrayAllocEntry );
                    nativeImpDesc.TimeDateStamp = 0;
                    nativeImpDesc.ForwarderChain = 0;
                    nativeImpDesc.Name = 0;
                    impDescsAlloc.RegisterTargetRVA( descWriteOffset + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name), impDesc.DLLName_allocEntry );
                    nativeImpDesc.FirstThunk = impDesc.firstThunkOffset;

                    impDescsAlloc.WriteToSection( &nativeImpDesc, sizeof(nativeImpDesc), descWriteOffset );
                }

                // Write the terminating NULL descriptor.
                {
                    const std::uint32_t nullDescOff = ( numImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR) );

                    IMAGE_IMPORT_DESCRIPTOR nullImpDesc = { 0 };

                    impDescsAlloc.WriteToSection( &nullImpDesc, sizeof(nullImpDesc), nullDescOff );
                }

                // We have written all import descriptors, so remember this allocation.
                this->importsAllocEntry = std::move( impDescsAlloc );
            }

            // * Resources.
            {
                PEResourceDir& resRootDir = this->resourceRoot;

                FileSpaceAllocMan resDataAlloc;

                using namespace ResourceTools;

                struct auxil
                {
                    static item_allocInfo AllocateResourceDirectory_dirData( FileSpaceAllocMan& allocMan, const PEResourceItem *item )
                    {
                        item_allocInfo infoOut;

                        // We allocate a structure depending on the type.
                        PEResourceItem::eType itemType = item->itemType;

                        if ( itemType == PEResourceItem::eType::DIRECTORY )
                        {
                            const PEResourceDir *itemDir = (const PEResourceDir*)item;

                            // This is the directory entry...
                            size_t itemSize = sizeof(IMAGE_RESOURCE_DIRECTORY);

                            // and the items following it.
                            size_t numChildren = itemDir->children.size();

                            itemSize += numChildren * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

                            infoOut.entry_off = allocMan.AllocateAny( itemSize, sizeof(DWORD) );

                            // Now allocate all children aswell.
                            // First allocate the named entries.
                            for ( size_t n = 0; n < numChildren; n++ )
                            {
                                const PEResourceItem *childItem = itemDir->children[n];

                                if ( childItem->hasIdentifierName != false )
                                    continue;

                                item_allocInfo childAlloc = AllocateResourceDirectory_dirData( allocMan, childItem );

                                // We allocate name strings later.
                                childAlloc.name_off = 0;

                                // Register this child alloc item.
                                infoOut.children.insert( std::make_pair( n, std::move( childAlloc ) ) );
                            }

                            // Now allocate all ID based entries.
                            for ( size_t n = 0; n < numChildren; n++ )
                            {
                                const PEResourceItem *childItem = itemDir->children[n];

                                if ( childItem->hasIdentifierName != true )
                                    continue;

                                item_allocInfo childAlloc = AllocateResourceDirectory_dirData( allocMan, childItem );

                                // Not named.
                                childAlloc.name_off = 0;

                                infoOut.children.insert( std::make_pair( n, std::move( childAlloc ) ) );
                            }
                        }
                        else if ( itemType == PEResourceItem::eType::DATA )
                        {
                            // We process data items later.
                            infoOut.entry_off = 0;
                        }

                        return infoOut;
                    }

                    static void AllocateResourceDirectory_nameStrings( FileSpaceAllocMan& allocMan, const PEResourceDir& rootDir, item_allocInfo& allocItem )
                    {
                        ForAllResourceItems( rootDir, allocItem,
                            [&]( const PEResourceItem *childItem, item_allocInfo& childAllocItem )
                        {
                            // Any name string to allocate?
                            if ( childItem->hasIdentifierName == false )
                            {
                                const size_t nameItemCount = ( childItem->name.size() );

                                size_t nameDataSize = ( childItem->name.size() * sizeof(char16_t) );

                                // Add the size of the header.
                                nameDataSize += sizeof(std::uint16_t);

                                childAllocItem.name_off = allocMan.AllocateAny( nameDataSize, sizeof(char16_t) );
                            }
                        });

                        // Processed this node.
                    }

                    static void AllocateResourceDirectory_dataItems( FileSpaceAllocMan& allocMan, const PEResourceDir& rootDir, item_allocInfo& allocItem )
                    {
                        ForAllResourceItems( rootDir, allocItem,
                            [&]( const PEResourceItem *childItem, item_allocInfo& childAllocItem )
                        {
                            if ( childItem->itemType == PEResourceItem::eType::DATA )
                            {
                                // Single item allocation.
                                const size_t itemSize = sizeof(IMAGE_RESOURCE_DATA_ENTRY);

                                childAllocItem.entry_off = allocMan.AllocateAny( itemSize, sizeof(DWORD) );
                            }
                        });
                    }

                    static void AllocateResourceDirectory_dataFiles( FileSpaceAllocMan& allocMan, const PEResourceDir& rootDir, item_allocInfo& allocItem )
                    {
                        ForAllResourceItems( rootDir, allocItem,
                            [&]( const PEResourceItem *childItem, item_allocInfo& childAllocItem )
                        {
                            if ( childItem->itemType == PEResourceItem::eType::DATA )
                            {
                                // TODO: make sure to update this once we support resource data injection!

                                const PEResourceInfo *childInfoItem = (const PEResourceInfo*)childItem;

                                // Allocate space inside of our resource section.
                                const size_t resFileSize = childInfoItem->sectRef.GetDataSize();

                                childAllocItem.dataitem_off = allocMan.AllocateAny( resFileSize, 1 );
                            }
                        });
                    }

                    static void WriteResourceDirectory( const PEResourceDir& writeNode, const item_allocInfo& allocNode, PESectionAllocation& writeBuf )
                    {
                        IMAGE_RESOURCE_DIRECTORY nativeResDir;
                        nativeResDir.Characteristics = writeNode.characteristics;
                        nativeResDir.TimeDateStamp = writeNode.timeDateStamp;
                        nativeResDir.MajorVersion = writeNode.majorVersion;
                        nativeResDir.MinorVersion = writeNode.minorVersion;
                        
                        // Count how many named and how many ID children we have.
                        WORD numNamedEntries = 0;
                        WORD numIDEntries = 0;

                        size_t numChildren = writeNode.children.size();
                        {
                            for ( size_t n = 0; n < numChildren; n++ )
                            {
                                const PEResourceItem *childItem = writeNode.children[ n ];

                                if ( !childItem->hasIdentifierName )
                                {
                                    numNamedEntries++;
                                }
                                else
                                {
                                    numIDEntries++;
                                }
                            }
                        }

                        nativeResDir.NumberOfNamedEntries = numNamedEntries;
                        nativeResDir.NumberOfIdEntries = numIDEntries;

                        const std::uint32_t dirWriteOff = allocNode.entry_off;

                        writeBuf.WriteToSection( &nativeResDir, sizeof(nativeResDir), allocNode.entry_off );

                        // Now write all children.
                        const std::uint32_t linkWriteOff = ( dirWriteOff + sizeof(nativeResDir) );

                        for ( size_t n = 0; n < numChildren; n++ )
                        {
                            const PEResourceItem *childItem = writeNode.children[ n ];

                            auto& childAllocInfoNode = allocNode.children.find( n );

                            assert( childAllocInfoNode != allocNode.children.end() );

                            const item_allocInfo& childAllocInfo = childAllocInfoNode->second;

                            // We write a link entry for this child.
                            IMAGE_RESOURCE_DIRECTORY_ENTRY lnkEntry = { 0 };

                            // Write and register ID information, be it name or number.
                            if ( !childItem->hasIdentifierName )
                            {
                                lnkEntry.NameIsString = true;

                                std::uint32_t nameWriteOff = childAllocInfo.name_off;

                                assert( nameWriteOff != 0 );    // invalid because zero is already root directory info offset.

                                // First store the amount of characters.
                                const std::uint16_t numWriteItems = (std::uint16_t)childItem->name.size();

                                writeBuf.WriteToSection( &numWriteItems, sizeof(numWriteItems), nameWriteOff );

                                // Write the name correctly.
                                writeBuf.WriteToSection( childItem->name.c_str(), numWriteItems * sizeof(char16_t), nameWriteOff + sizeof(std::uint16_t) );

                                // Give the offset.
                                lnkEntry.NameOffset = childAllocInfo.name_off;
                            }
                            else
                            {
                                lnkEntry.NameIsString = false;

                                // Just write the ID.
                                lnkEntry.Id = childItem->identifier;
                            }

                            PEResourceItem::eType itemType = childItem->itemType;

                            // Give information about the child we are going to write.
                            lnkEntry.DataIsDirectory = ( itemType == PEResourceItem::eType::DIRECTORY );
                            lnkEntry.OffsetToDirectory = ( childAllocInfo.entry_off );

                            const size_t lnkEntryOff = ( linkWriteOff + n * sizeof(lnkEntry) );

                            writeBuf.WriteToSection( &lnkEntry, sizeof(lnkEntry), lnkEntryOff );

                            if ( itemType == PEResourceItem::eType::DIRECTORY )
                            {
                                const PEResourceDir *childDir = (const PEResourceDir*)childItem;

                                // Just recurse to write more data.
                                WriteResourceDirectory( *childDir, childAllocInfo, writeBuf );
                            }
                            else if ( itemType == PEResourceItem::eType::DATA )
                            {
                                const PEResourceInfo *childData = (const PEResourceInfo*)childItem;

                                // TODO: once we support injecting data buffers into the resource directory,
                                // we will have to extend this with memory stream reading support.

                                std::uint32_t fileWriteOff = childAllocInfo.dataitem_off;

                                assert( fileWriteOff != 0 );    // invalid because already taken by root directory info.

                                PEDataStream fileSrcStream = PEDataStream::fromDataRef( childData->sectRef );

                                // Write data over.
                                const std::uint32_t fileDataSize = childData->sectRef.GetDataSize();
                                {
                                    char buffer[ 0x4000 ];

                                    std::uint32_t curDataOff = 0;
                                    
                                    while ( curDataOff < fileDataSize )
                                    {
                                        size_t actualProcCount = std::min( fileDataSize - curDataOff, sizeof(buffer) );

                                        fileSrcStream.Read( buffer, actualProcCount );

                                        writeBuf.WriteToSection( buffer, actualProcCount, fileWriteOff + curDataOff );

                                        curDataOff += sizeof(buffer);
                                    }
                                }

                                std::uint32_t dataEntryOff = childAllocInfo.entry_off;

                                IMAGE_RESOURCE_DATA_ENTRY nativeDataEntry;
                                // We need to write the RVA later.
                                nativeDataEntry.OffsetToData = 0;
                                writeBuf.RegisterTargetRVA( dataEntryOff + offsetof(IMAGE_RESOURCE_DATA_ENTRY, OffsetToData), writeBuf.GetSection(), writeBuf.ResolveInternalOffset( fileWriteOff ) );
                                nativeDataEntry.Size = fileDataSize;
                                nativeDataEntry.CodePage = childData->codePage;
                                nativeDataEntry.Reserved = childData->reserved;

                                assert( childAllocInfo.entry_off != 0 );    // invalid because zero is already taken by root directory.

                                writeBuf.WriteToSection( &nativeDataEntry, sizeof(nativeDataEntry), childAllocInfo.entry_off );
                            }
                            else
                            {
                                assert( 0 );
                            }
                        }

                        // Finished writing all children.
                    }
                };

                // First allocate all directory entries.
                item_allocInfo allocInfo = auxil::AllocateResourceDirectory_dirData( resDataAlloc, &resRootDir );

                // Then come the name strings.
                auxil::AllocateResourceDirectory_nameStrings( resDataAlloc, resRootDir, allocInfo );

                // And last but not least the data entries.
                auxil::AllocateResourceDirectory_dataItems( resDataAlloc, resRootDir, allocInfo );

                // Resource files must be allocated in the resource section, by documentation.
                auxil::AllocateResourceDirectory_dataFiles( resDataAlloc, resRootDir, allocInfo );

                assert( allocInfo.entry_off == 0 );
                allocInfo.name_off = 0;     // the root directory has no name.

                // Get a main allocation spot inside of the section now that allocation has finished.
                PESectionAllocation resDirEntry;
                rdonlySect.Allocate( resDirEntry, resDataAlloc.GetSpanSize( 1 ), sizeof(DWORD) );

                // Write the data into the executable memory now.
                auxil::WriteResourceDirectory( resRootDir, allocInfo, resDirEntry );

                // Remember the allocation now.
                this->resAllocEntry = std::move( resDirEntry );
            }

            // * Exception Information.
            const auto& exceptRFs = this->exceptRFs;

            size_t numExceptEntries = exceptRFs.size();

            if ( numExceptEntries != 0 )
            {
                // TODO: remember that exception data is machine dependent.
                // revisit this if we need multi-architecture support.
                // (currently we specialize on x86/AMD64)

                const size_t exceptTableSize = ( sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) * numExceptEntries );

                PESectionAllocation exceptTableAlloc;
                rdonlySect.Allocate( exceptTableAlloc, exceptTableSize, sizeof(DWORD) );

                // Now write all entries.
                // TODO: documentation says that these entries should be address sorted.
                for ( size_t n = 0; n < numExceptEntries; n++ )
                {
                    const PERuntimeFunction& rfEntry = this->exceptRFs[ n ];

                    IMAGE_RUNTIME_FUNCTION_ENTRY funcInfo;
                    funcInfo.BeginAddress = rfEntry.beginAddr;
                    funcInfo.EndAddress = rfEntry.endAddr;
                    funcInfo.UnwindInfoAddress = rfEntry.unwindInfo;

                    const size_t rfEntryOff = ( n * sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) );

                    exceptTableAlloc.WriteToSection( &funcInfo, sizeof(funcInfo), rfEntryOff );
                }

                // Remember this valid exception table.
                this->exceptAllocEntry = std::move( exceptTableAlloc );
            }

            // nothing to allocate for security cookie.

            // * BASE RELOC.
            const auto& baseRelocs = this->baseRelocs;

            size_t numBaseRelocations = baseRelocs.size();

            if ( numBaseRelocations != 0 )
            {

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
            std::int32_t writeOff = placedOff.dataOffset;

            // Parameters to calculate RVA.
            PESection *targetSect = placedOff.targetSect;
            std::uint32_t targetOff = placedOff.offsetIntoSect;

            // Calculate target RVA.
            std::uint32_t targetRVA = targetSect->ResolveRVA( targetOff );

            // Write the RVA.
            writeSect->stream.Seek( writeOff );
            writeSect->stream.WriteUInt32( targetRVA );
        }

        // Since we have committed the RVAs into binary memory, no need for the meta-data anymore.
        item->placedOffsets.clear();

    LIST_FOREACH_END
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
            if ( allocEntry.IsAllocated() )
            {
                dataDir.VirtualAddress = allocEntry.ResolveOffset( 0 );
                dataDir.Size = allocEntry.GetDataSize();
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
                const DWORD allocVirtualSize = ALIGN_SIZE( item->GetVirtualSize(), sectionAlignment );
                const DWORD rawDataSize = (DWORD)item->stream.Size();

                DWORD sectOffset = allocMan.AllocateAny( rawDataSize, this->peOptHeader.fileAlignment );

                IMAGE_SECTION_HEADER header;
                strncpy( (char*)header.Name, item->shortName.c_str(), _countof(header.Name) );
                header.VirtualAddress = item->GetVirtualAddress();
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