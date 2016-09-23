#ifndef _PELOADER_CORE_
#define _PELOADER_CORE_

#include <sdk/rwlist.hpp>
#include <sdk/MemoryUtils.h>
#include <sdk/MemoryUtils.stream.h>

namespace PEStructures
{

struct IMAGE_BASE_RELOC_TYPE_ITEM
{
    std::uint16_t type : 4;
    std::uint16_t offset : 12;
};

struct IMAGE_RESOURCE_DIRECTORY {
    std::uint32_t Characteristics;
    std::uint32_t TimeDateStamp;
    std::uint16_t MajorVersion;
    std::uint16_t MinorVersion;
    std::uint16_t NumberOfNamedEntries;
    std::uint16_t NumberOfIdEntries;
//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY
{
    union {
        struct {
            std::uint32_t NameOffset:31;
            std::uint32_t NameIsString:1;
        };
        std::uint32_t     Name;
        std::uint16_t     Id;
    };
    union {
        std::uint32_t     OffsetToData:31;
        struct {
            std::uint32_t OffsetToDirectory:31;
            std::uint32_t DataIsDirectory:1;
        };
    };
};

struct IMAGE_RESOURCE_DIRECTORY_STRING
{
    std::uint16_t       Length;
    char                NameString[ 1 ];
};

struct IMAGE_RESOURCE_DIR_STRING_U
{
    std::uint16_t       Length;
    wchar_t             NameString[ 1 ];
};

struct IMAGE_RESOURCE_DATA_ENTRY
{
    std::uint32_t OffsetToData;
    std::uint32_t Size;
    std::uint32_t CodePage;
    std::uint32_t Reserved;
};

};

struct PEFile
{
    PEFile( void );
    ~PEFile( void );

    void LoadFromDisk( CFile *peStream );
    void WriteToStream( CFile *peStream );

    bool HasRelocationInfo( void ) const;
    bool HasLinenumberInfo( void ) const;
    bool HasDebugInfo( void ) const;

    bool IsDynamicLinkLibrary( void ) const;

private:
    // DOS information.
    struct DOSStub
    {
        std::uint16_t cblp;
        std::uint16_t cp;
        std::uint16_t crlc;
        std::uint16_t cparhdr;
        std::uint16_t minalloc, maxalloc;
        std::uint16_t ss;
        std::uint16_t sp;
        std::uint16_t csum;
        std::uint16_t ip;
        std::uint16_t cs;
        std::uint16_t lfarlc;
        std::uint16_t ovno;
        std::uint16_t reserved1[4];
        std::uint16_t oemid;
        std::uint16_t oeminfo;
        std::uint16_t reserved2[10];

        // Actual DOS program data.
        std::vector <unsigned char> progData;
    };
    DOSStub dos_data;

    // Start of PE stuff.
    struct PEFileInfo
    {
        inline PEFileInfo( void )
        {
            this->machine_id = 0;
            this->timeDateStamp = 0;
            this->isExecutableImage = false;
            this->hasLocalSymbols = false;
            this->hasAggressiveTrim = false;
            this->largeAddressAware = false;
            this->bytesReversedLO = false;
            this->removableRunFromSwap = false;
            this->netRunFromSwap = false;
            this->isSystemFile = false;
            this->isDLL = false;
            this->upSystemOnly = false;
            this->bytesReversedHI = false;
        }

        std::uint16_t machine_id;
        std::uint32_t timeDateStamp;

        // More meta information.
        bool isExecutableImage;
        bool hasLocalSymbols;
        bool hasAggressiveTrim;
        bool largeAddressAware;
        bool bytesReversedLO;
        bool removableRunFromSwap;
        bool netRunFromSwap;
        bool isSystemFile;
        bool isDLL;
        bool upSystemOnly;
        bool bytesReversedHI;

        // Other stuff is used for parsing more advanced business.
    };
    PEFileInfo pe_finfo;

    struct PEOptHeader
    {
        std::uint8_t majorLinkerVersion;
        std::uint8_t minorLinkerVersion;
        std::uint32_t sizeOfCode;
        std::uint32_t sizeOfInitializedData;
        std::uint32_t sizeOfUninitializedData;
        std::uint32_t addressOfEntryPoint;
        std::uint32_t baseOfCode;
        std::uint32_t baseOfData;

        std::uint64_t imageBase;
        std::uint32_t fileAlignment;
        std::uint16_t majorOSVersion;
        std::uint16_t minorOSVersion;
        std::uint16_t majorImageVersion;
        std::uint16_t minorImageVersion;
        std::uint16_t majorSubsysVersion;
        std::uint16_t minorSubsysVersion;
        std::uint32_t win32VersionValue;
        std::uint32_t sizeOfImage;
        std::uint32_t sizeOfHeaders;
        std::uint32_t checkSum;
        std::uint16_t subsys;
        std::uint64_t sizeOfStackReserve;
        std::uint64_t sizeOfStackCommit;
        std::uint64_t sizeOfHeapReserve;
        std::uint64_t sizeOfHeapCommit;
        std::uint32_t loaderFlags;

        // DLL flags.
        bool dll_supportsHighEntropy;
        bool dll_hasDynamicBase;
        bool dll_forceIntegrity;
        bool dll_nxCompat;
        bool dll_noIsolation;
        bool dll_noSEH;
        bool dll_noBind;
        bool dll_appContainer;
        bool dll_wdmDriver;
        bool dll_guardCF;
        bool dll_termServAware;

        // More advanced stuff to follow.
    };
    PEOptHeader peOptHeader;

    // Executable sections.
    struct PERelocation
    {
        union
        {
            std::uint32_t virtAddr;
            std::uint32_t relocCount;
        };

        std::uint32_t symbolTableIndex;
        std::uint16_t type;
    };

    struct PELinenumber
    {
        union
        {
            std::uint32_t symTableIndex;
            std::uint32_t virtAddr;
        };
        std::uint16_t number;
    };

    struct PESectionMan;

    struct PESection
    {
        PESection( void );
        PESection( const PESection& right ) = delete;
        PESection( PESection&& right )
            : shortName( std::move( right.shortName ) ), virtualSize( std::move( right.virtualSize ) ),
              virtualAddr( std::move( right.virtualAddr ) ), relocations( std::move( right.relocations ) ),
              linenumbers( std::move( right.linenumbers ) ), chars( std::move( right.chars ) ),
              isFinal( std::move( right.isFinal ) ), dataAlloc( std::move( right.dataAlloc ) ),
              streamAllocMan( std::move( right.streamAllocMan ) ), stream( std::move( right.stream ) ),
              placedOffsets( std::move( right.placedOffsets ) ), RVAreferalList( std::move( right.RVAreferalList ) )
        {
            // Since I have been writing this, how about a move constructor that allows
            // default-construction of all members but on top of that executes its own constructor body?

            // We keep a list of RVAs that point to us, which needs updating.
            patchSectionPointers();

            // If we belong to a PE image, we must move our node over.
            moveFromOwnerImage( right );
        }
        ~PESection( void );

    private:
        inline void moveFromOwnerImage( PESection& right )
        {
            PESectionMan *ownerImage = right.ownerImage;

            if ( ownerImage )
            {
                this->sectionNode.moveFrom( std::move( right.sectionNode ) );

                right.ownerImage = NULL;
            }

            this->ownerImage = ownerImage;
        }

        inline void unregisterOwnerImage( void )
        {
            if ( PESectionMan *ownerImage = this->ownerImage )
            {
                LIST_REMOVE( this->sectionNode );

                this->ownerImage = NULL;
            }
        }

        inline void patchSectionPointers( void )
        {
            // First we want to fix the allocations that have been made on this section.
            LIST_FOREACH_BEGIN( PESectionAllocation, this->dataAllocList.root, sectionNode )

                item->theSection = this;

            LIST_FOREACH_END

            // Then fix the RVAs that could target us.
            LIST_FOREACH_BEGIN( PEPlacedOffset, this->RVAreferalList.root, targetNode )

                item->targetSect = this;

            LIST_FOREACH_END
        }

    public:
        inline PESection& operator =( const PESection& right ) = delete;
        inline PESection& operator =( PESection&& right )
        {
            // The same default-assignment paradigm could be applied here as
            // for the move constructor.

            this->shortName = std::move( right.shortName );
            this->virtualSize = std::move( right.virtualSize );
            this->virtualAddr = std::move( right.virtualAddr );
            this->relocations = std::move( right.relocations );
            this->linenumbers = std::move( right.linenumbers );
            this->chars = std::move( right.chars );
            this->isFinal = std::move( right.isFinal );
            this->dataAlloc = std::move( right.dataAlloc );
            this->streamAllocMan = std::move( right.streamAllocMan );
            this->stream = std::move( right.stream );
            this->placedOffsets = std::move( right.placedOffsets );
            this->RVAreferalList = std::move( right.RVAreferalList );

            patchSectionPointers();

            // Update PE image.
            {
                // Make sure we long to no more PE image anymore
                unregisterOwnerImage(),

                // Set us into the new owner image.
                moveFromOwnerImage( right );
            }

            return *this;
        }

        std::string shortName;
        std::uint32_t virtualSize;
        std::uint32_t virtualAddr;
        
        std::vector <PERelocation> relocations;
        std::vector <PELinenumber> linenumbers;

        enum class eAlignment
        {
            BYTES_UNSPECIFIED,
            BYTES_1,
            BYTES_2,
            BYTES_4,
            BYTES_8,
            BYTES_16,
            BYTES_32,
            BYTES_64,
            BYTES_128,
            BYTES_256,
            BYTES_512,
            BYTES_1024,
            BYTES_2048,
            BYTES_4096,
            BYTES_8192
        };

        // Characteristics.
        struct
        {
            bool sect_hasNoPadding;
            bool sect_containsCode;
            bool sect_containsInitData;
            bool sect_containsUninitData;
            bool sect_link_other;
            bool sect_link_info;
            bool sect_link_remove;
            bool sect_link_comdat;
            bool sect_noDeferSpecExcepts;
            bool sect_gprel;
            bool sect_mem_farData;
            bool sect_mem_purgeable;
            bool sect_mem_16bit;
            bool sect_mem_locked;
            bool sect_mem_preload;
        
            eAlignment sect_alignment;

            bool sect_link_nreloc_ovfl;
            bool sect_mem_discardable;
            bool sect_mem_not_cached;
            bool sect_mem_not_paged;
            bool sect_mem_shared;
            bool sect_mem_execute;
            bool sect_mem_read;
            bool sect_mem_write;
        } chars;

        // Meta-data that we manage.
        // * Allocation status.
        bool isFinal;

        typedef InfiniteCollisionlessBlockAllocator <std::uint32_t> sectionSpaceAlloc_t;

        struct PESectionAllocation
        {
            // TODO: once we begin differing between PE file version we have to be
            // careful about maintaining allocations.

            inline PESectionAllocation( void )
            {
                this->theSection = NULL;
                this->sectOffset = 0;
                this->dataSize = 0;
            }

            inline PESectionAllocation( PESectionAllocation&& right )
            {
                PESection *newSectionHost = right.theSection;

                this->theSection = newSectionHost;
                this->sectOffset = right.sectOffset;
                this->dataSize = right.dataSize;

                if ( newSectionHost )
                {
                    // If the section is final, we do not exist
                    // in the list, because final sections do not have to
                    // know about existing chunks.
                    // Keeping a list would over-complicate things.
                    if ( newSectionHost->isFinal == false )
                    {
                        this->sectionBlock.moveFrom( std::move( right.sectionBlock ) );
                    }

                    // Add to general allocation list.
                    this->sectionNode.moveFrom( std::move( right.sectionNode ) );
                }

                // Invalidate the old section.
                right.theSection = NULL;
            }
            inline PESectionAllocation( const PESectionAllocation& right ) = delete;

        private:
            inline void removeFromSection( void )
            {
                // If we are allocated on a section, we want to remove ourselves.
                if ( PESection *sect = this->theSection )
                {
                    if ( sect->isFinal == false )
                    {
                        // Block remove.
                        sect->dataAlloc.RemoveBlock( &this->sectionBlock );
                    }

                    // General list remove.
                    LIST_REMOVE( this->sectionNode );

                    this->theSection = NULL;
                }
            }

        public:
            inline void operator = ( PESectionAllocation&& right )
            {
                // Actually the same as the destructor does.
                this->removeFromSection();

                new (this) PESectionAllocation( std::move( right ) );
            }
            inline void operator = ( const PESectionAllocation& right ) = delete;

            inline ~PESectionAllocation( void )
            {
                this->removeFromSection();
            }

            // Data-access methods for this allocation
            void WriteToSection( const void *dataPtr, std::uint32_t dataSize, std::int32_t dataOff = 0 );

            // For allocating placed RVAs into allocated structs.
            void RegisterTargetRVA( std::uint32_t patchOffset, PESection *targetSect, std::uint32_t targetOff );
            void RegisterTargetRVA( std::uint32_t patchOffset, const PESectionAllocation& targetInfo, std::uint32_t targetOff = 0 );

            PESection *theSection;
            std::uint32_t sectOffset;
            std::uint32_t dataSize;     // if 0 then true size not important/unknown.

            inline bool IsAllocated( void ) const
            {
                return ( theSection != NULL );
            }

            // Every allocation can ONLY exist on ONE section.

            sectionSpaceAlloc_t::block_t sectionBlock;

            RwListEntry <PESectionAllocation> sectionNode;  // despite having a collision-based list node we need a general node aswell.

            // This method is not required anymore.
            inline static PESectionAllocation* GetSectionAllocationFromAllocBlock( sectionSpaceAlloc_t::block_t *block )
            {
                return (PESectionAllocation*)( (char*)block - offsetof(PESectionAllocation, sectionBlock) );
            }
        };

        // Allocation methods.
        std::uint32_t Allocate( PESectionAllocation& blockMeta, std::uint32_t allocSize, std::uint32_t alignment = sizeof(std::uint32_t) );
        void SetPlacedMemory( PESectionAllocation& blockMeta, std::uint32_t allocOff, std::uint32_t allocSize = 0u );

        std::uint32_t GetPENativeFlags( void ) const;

        // If we are final, we DO NOT keep a list of allocations.
        // Otherwise we keep a collisionless struct of allocations we made.
        sectionSpaceAlloc_t dataAlloc;

        // List which contains unordered allocated chunks, mostly useful for
        // final sections.
        RwList <PESectionAllocation> dataAllocList;

        inline bool IsEmpty( void ) const
        {
            if ( isFinal )
            {
                return ( this->virtualSize == 0 );
            }
            else
            {
                return ( LIST_EMPTY( this->dataAlloc.blockList.root ) == true );
            }
        }

private:
        // Writing and possibly reading from this data section
        // should be done through this memory stream.
        BasicMemStream::basicMemStreamAllocMan <std::int32_t> streamAllocMan;
public:
        typedef BasicMemStream::basicMemoryBufferStream <std::int32_t> memStream;

        memStream stream;

        // We need RVA finalization patches which come in the form of virtual
        // RVA registrations into a section.
        struct PEPlacedOffset
        {
            inline PEPlacedOffset( std::uint32_t dataOffset, PESection *targetSect, std::uint32_t offsetIntoSect )
            {
                this->dataOffset = dataOffset;
                this->targetSect = targetSect;
                this->offsetIntoSect = offsetIntoSect;

                LIST_INSERT( targetSect->RVAreferalList.root, this->targetNode );
            }

            inline PEPlacedOffset( PEPlacedOffset&& right )
            {
                PESection *targetSect = right.targetSect;

                this->dataOffset = right.dataOffset;
                this->targetSect = targetSect;
                this->offsetIntoSect = right.offsetIntoSect;

                if ( targetSect )
                {
                    this->targetNode.moveFrom( std::move( right.targetNode ) );

                    right.targetSect = NULL;
                }
            }

            inline PEPlacedOffset( const PEPlacedOffset& right ) = delete;

            inline ~PEPlacedOffset( void )
            {
                if ( this->targetSect )
                {
                    LIST_REMOVE( this->targetNode );
                }
            }

            inline PEPlacedOffset& operator =( PEPlacedOffset&& right )
            {
                this->~PEPlacedOffset();

                new (this) PEPlacedOffset( std::move( right ) );

                return *this;
            }
            inline PEPlacedOffset& operator =( const PEPlacedOffset& right ) = delete;

            std::int32_t dataOffset;        // the offset into the section where the RVA has to be written.
            PESection *targetSect;          // before getting a real RVA the section has to be allocated.
            std::int32_t offsetIntoSect;    // we have to add this to the section placement to get real RVA.

            RwListEntry <PEPlacedOffset> targetNode;    // list node inside target section to keep pointer valid.
        };

        std::vector <PEPlacedOffset> placedOffsets;     // list of all RVAs that are in the data of this section.

        RwList <PEPlacedOffset> RVAreferalList;     // list of all our placed RVAs that refer to this section.

        // API to register RVAs for commit phase.
        void RegisterTargetRVA( std::uint32_t patchOffset, PESection *targetSect, std::uint32_t targetOffset );
        void RegisterTargetRVA( std::uint32_t patchOffset, const PESectionAllocation& targetInfo );

        // Call just before placing into image.
        void Finalize( void );

        // Node into the list of sections in a PESectionMan.
        RwListEntry <PESection> sectionNode;
        PESectionMan *ownerImage;
    };
    using PESectionAllocation = PESection::PESectionAllocation;

private:
    // Data inside of a PE file is stored in sections which have special
    // rules if they ought to be "zero padded".
    struct PEDataStream
    {
        inline PEDataStream( void )
        {
            this->accessSection = NULL;
            this->dataOffset = 0;
            this->seek_off = 0;
        }

        inline PEDataStream( PESection *theSection, std::uint32_t dataOffset )
        {
            this->accessSection = theSection;
            this->dataOffset = dataOffset;
            this->seek_off = 0;
        }

        inline void Seek( std::uint32_t offset )
        {
            this->seek_off = offset;
        }

        inline std::uint32_t Tell( void )
        {
            return this->seek_off;
        }

        inline void Read( void *dataBuf, std::uint32_t readCount )
        {
            PESection *theSection = this->accessSection;

            if ( !theSection )
                throw std::exception( "attempt to read from invalid PE data stream" );

            typedef sliceOfData <std::uint32_t> sectionSlice_t;

            // Get the slice of the present data.
            const std::uint32_t sectVirtualAddr = theSection->virtualAddr;
            const std::uint32_t sectVirtualSize = theSection->virtualSize;

            sectionSlice_t dataSlice( 0, theSection->stream.Size() );

            // Get the slice of the zero padding.
            const std::uint32_t validEndPoint = ( sectVirtualSize );

            sectionSlice_t zeroSlice = sectionSlice_t::fromOffsets( dataSlice.GetSliceEndPoint() + 1, validEndPoint );

            // Now the slice of our read operation.
            sectionSlice_t opSlice( ( this->dataOffset + this->seek_off ), readCount );

            // Begin output to buffer operations.
            char *outputPtr = (char*)dataBuf;

            std::uint32_t totalReadCount = 0;

            // First return the amount of data that was requested, if it counts.
            sectionSlice_t retDataSlice;

            if ( opSlice.getSharedRegion( dataSlice, retDataSlice ) )
            {
                std::uint32_t numReadData = retDataSlice.GetSliceSize();

                const void *srcDataPtr = ( (const char*)theSection->stream.Data() + retDataSlice.GetSliceStartPoint() );

                memcpy( outputPtr, srcDataPtr, numReadData );

                outputPtr += numReadData;

                totalReadCount += numReadData;
            }

            // Next see if we have to return any zeroes.
            if ( opSlice.getSharedRegion( zeroSlice, retDataSlice ) )
            {
                std::uint32_t numZeroes = retDataSlice.GetSliceSize();

                memset( outputPtr, 0, numZeroes );

                outputPtr += numZeroes;

                totalReadCount += numZeroes;
            }

            this->seek_off += readCount;

            if ( totalReadCount != readCount )
            {
                throw std::exception( "PE file out-of-bounds section read exception" );
            }
        }

    private:
        PESection *accessSection;
        std::uint32_t dataOffset;
        std::uint32_t seek_off;
    };

    template <typename charType>
    inline static void ReadPEString(
        PEDataStream& stream, std::basic_string <charType>& strOut
    )
    {
        while ( true )
        {
            charType c;
            stream.Read( &c, sizeof(c) );

            if ( c == '\0' )
            {
                break;
            }

            strOut += c;
        }
    }

    struct PESectionMan
    {
        PESectionMan( std::uint32_t sectionAlignment, std::uint32_t imageBase );
        PESectionMan( const PESectionMan& right ) = delete;
        PESectionMan( PESectionMan&& right ) = default;
        ~PESectionMan( void );

        PESectionMan& operator = ( const PESectionMan& right ) = delete;
        PESectionMan& operator = ( PESectionMan&& right ) = default;

        // Private section management API.
        PESection* AddSection( PESection&& theSection );
        PESection* PlaceSection( PESection&& theSection );
        bool RemoveSection( PESection *section );

        std::uint32_t GetSectionAlignment( void )       { return this->sectionAlignment; }
        std::uint32_t GetImageBase( void )              { return this->imageBase; }

        inline std::uint32_t GetImageSize( void )
        {
            std::uint32_t unalignedMemImageEndOffMax = sectAllocSemantics::GetSpanSize( sectVirtualAllocMan );

            return ALIGN_SIZE( unalignedMemImageEndOffMax, this->sectionAlignment );
        }

        // Function to get a data pointer of data directories.
        inline bool GetPEDataStream(
            std::uint64_t virtAddr, PEDataStream& streamOut,
            PESection **allocSectOut = NULL
        )
        {
            typedef sliceOfData <std::uint64_t> memSlice_t;

            // Create a memory slice of the request.
            memSlice_t requestRegion( virtAddr, 1 );

            LIST_FOREACH_BEGIN( PESection, this->sectionList.root, sectionNode )
        
                // We only support that for sections whose data is figured out already.
                if ( item->isFinal )
                {
                    // Create a memory slice of this section.
                    std::uint64_t sectAddr, sectSize;
                    {
                        sectAddr = item->virtualAddr;
                        sectSize = item->virtualSize;
                    }

                    memSlice_t sectRegion( sectAddr, sectSize );

                    // Our memory request has to be entirely inside of a section.
                    memSlice_t::eIntersectionResult intResult = requestRegion.intersectWith( sectRegion );

                    if ( intResult == memSlice_t::INTERSECT_INSIDE ||
                         intResult == memSlice_t::INTERSECT_EQUAL )
                    {
                        if ( allocSectOut )
                        {
                            *allocSectOut = item;
                        }

                        // OK. We return a stream into this section.
                        std::uint32_t offsetIntoSect = (uint32_t)( virtAddr - sectAddr );

                        streamOut = PEDataStream( item, offsetIntoSect );
                        return true;
                    }
                }
        
            LIST_FOREACH_END

            // Not found.
            return false;
        }

        inline bool ReadPEData(
            std::uint32_t dataOffset, std::uint32_t dataSize,
            void *dataBuf, PESection **sectionOut
        )
        {
            PEDataStream stream;

            bool gotData = GetPEDataStream( dataOffset, stream, sectionOut );

            if ( !gotData )
            {
                return false;
            }

            stream.Read( dataBuf, dataSize );

            return true;
        }

        inline bool ReadPEString(
            std::uint32_t dataOffset, std::string& strOut,
            PESection **sectionOut
        )
        {
            PEDataStream stream;

            bool gotData = GetPEDataStream( dataOffset, stream, sectionOut );

            if ( !gotData )
                return false;

            PEFile::ReadPEString( stream, strOut );
            return true;
        }

    private:
        std::uint32_t sectionAlignment;
        std::uint32_t imageBase;

        struct sectVirtualAllocMan_t
        {
            AINLINE sectVirtualAllocMan_t( void ) = default;
            AINLINE sectVirtualAllocMan_t( const sectVirtualAllocMan_t& right ) = delete;
            AINLINE sectVirtualAllocMan_t( sectVirtualAllocMan_t&& right ) = default;

            AINLINE sectVirtualAllocMan_t& operator = ( const sectVirtualAllocMan_t& right ) = delete;
            AINLINE sectVirtualAllocMan_t& operator = ( sectVirtualAllocMan_t&& right ) = default;

            typedef sliceOfData <decltype(PESection::virtualAddr)> memSlice_t;

            struct blockIter_t
            {
                AINLINE blockIter_t( void )
                {
                    return;
                }

                AINLINE blockIter_t( RwListEntry <PESection>& node )
                {
                    this->node_iter = &node;
                }

                AINLINE void Increment( void )
                {
                    this->node_iter = this->node_iter->next;
                }

                AINLINE memSlice_t GetMemorySlice( void )
                {
                    PESection *sect = LIST_GETITEM( PESection, this->node_iter, sectionNode );

                    return memSlice_t( sect->virtualAddr, sect->virtualSize );
                }

                RwListEntry <PESection> *node_iter;
            };

            AINLINE PESectionMan* GetManager( void )
            {
                return (PESectionMan*)( this - offsetof(PESectionMan, sectVirtualAllocMan) );
            }

            AINLINE blockIter_t GetFirstMemoryBlock( void )
            {
                return ( *GetManager()->sectionList.root.next );
            }

            AINLINE blockIter_t GetLastMemoryBlock( void )
            {
                return ( *GetManager()->sectionList.root.prev );
            }

            AINLINE bool HasMemoryBlocks( void )
            {
                return ( LIST_EMPTY( GetManager()->sectionList.root ) == false );
            }

            AINLINE blockIter_t GetRootNode( void )
            {
                return ( GetManager()->sectionList.root );
            }

            AINLINE blockIter_t GetAppendNode( blockIter_t iter )
            {
                return iter;
            }

            AINLINE bool IsEndMemoryBlock( const blockIter_t& iter )
            {
                return ( iter.node_iter == &GetManager()->sectionList.root );
            }

            AINLINE bool IsInAllocationRange( const memSlice_t& memRegion )
            {
                const memSlice_t peFileRegion( 0, std::numeric_limits <std::int32_t>::max() );

                memSlice_t::eIntersectionResult intResult = memRegion.intersectWith( peFileRegion );

                return ( intResult == memSlice_t::INTERSECT_EQUAL || intResult == memSlice_t::INTERSECT_INSIDE );
            }
        };

        sectVirtualAllocMan_t sectVirtualAllocMan;

        typedef FirstPassAllocationSemantics <decltype(PESection::virtualAddr), sectVirtualAllocMan_t> sectAllocSemantics;

    public:
        unsigned int numSections;

        RwList <PESection> sectionList;     // all sections belong to a PEFile MUST have a valid allocation spot.
    };

    PESectionMan sections;

public:
    // Generic section management API.
    PESection* AddSection( PESection&& theSection );
    PESection* PlaceSection( PESection&& theSection );
    PESection* FindFirstSectionByName( const char *name );
    PESection* FindFirstAllocatableSection( void );
    bool RemoveSection( PESection *section );

    // Data directory business.
    struct PEExportDir
    {
        inline PEExportDir( void )
        {
            this->chars = 0;
            this->timeDateStamp = 0;
            this->majorVersion = 0;
            this->minorVersion = 0;
            this->ordinalBase = 0;
        }

        std::uint32_t chars;
        std::uint32_t timeDateStamp;
        std::uint16_t majorVersion;
        std::uint16_t minorVersion;
        std::string name;   // NOTE: name table is serialized lexigraphically.
        std::uint32_t ordinalBase;

        PESectionAllocation nameAllocEntry;

        struct func
        {
            // Mandatory valid fields for each function.
            std::uint32_t forwExpFuncOffset;    // might look like an allocation but is NOT.
            PESection *forwExpFuncSection;
            std::string forwarder;
            bool isForwarder;
            
            // Optional fields.
            std::string name;       // is valid if not empty
            bool isNamed;
            PESectionAllocation nameAllocEntry;
            // definition of ordinal: index into function array.
            // thus it is given implicitly.
        };
        std::vector <func> functions;

        PESectionAllocation funcAddressAllocEntry;
        PESectionAllocation funcNamesAllocEntry;
        PESectionAllocation funcOrdinalsAllocEntry;

        PESectionAllocation allocEntry;
    };
    PEExportDir exportDir;

    // Import informations.
    struct PEImportDesc
    {
        struct importFunc
        {
            std::uint64_t ordinal_hint;
            std::string name;
            bool isOrdinalImport;

            PESectionAllocation nameAllocEntry;
        };
        std::vector <importFunc> funcs;
        std::string DLLName;

        PESectionAllocation impNameArrayAllocEntry;
        PESectionAllocation DLLName_allocEntry;
        
        // Meta-information we must keep because it is baked
        // by compilers.
        std::uint32_t firstThunkOffset;
    };
    std::vector <PEImportDesc> imports;

    PESectionAllocation importsAllocEntry;

    // Resource information.
    struct PEResourceItem
    {
        enum class eType
        {
            DIRECTORY,
            DATA
        };

        inline PEResourceItem( eType typeDesc, std::wstring name ) : itemType( typeDesc ), name( std::move( name ) )
        {
            this->identifier = 0;
            this->hasIdentifierName = false;
        }

        virtual ~PEResourceItem( void )
        {
            return;
        }

        eType itemType;
        std::wstring name;
        std::uint16_t identifier;
        bool hasIdentifierName;
    };

    struct PEResourceInfo : PEResourceItem
    {
        inline PEResourceInfo( std::wstring name ) : PEResourceItem( eType::DATA, std::move( name ) )
        {
            this->dataOffset = 0;
            this->dataSize = 0;
            this->codePage = 0;
            this->reserved = 0;
        }

        std::uint32_t dataOffset;   // we link resources to data in sections.
        std::uint32_t dataSize;
        std::uint32_t codePage;
        std::uint32_t reserved;
    };
    
    struct PEResourceDir : PEResourceItem
    {
        inline PEResourceDir( std::wstring name ) : PEResourceItem( eType::DIRECTORY, std::move( name ) )
        {
            this->characteristics = 0;
            this->timeDateStamp = 0;
            this->majorVersion = 0;
            this->minorVersion = 0;
        }

        std::uint32_t characteristics;
        std::uint32_t timeDateStamp;
        std::uint16_t majorVersion;
        std::uint16_t minorVersion;
        
        // We contain named and id entries.
        std::vector <PEResourceItem*> children;
    };
    PEResourceDir resourceRoot;
    
    PESectionAllocation resAllocEntry;

    struct PERuntimeFunction
    {
        std::uint32_t beginAddr;
        std::uint32_t endAddr;
        std::uint32_t unwindInfo;
    };
    std::vector <PERuntimeFunction> exceptRFs;

    PESectionAllocation exceptAllocEntry;

    struct PESecurity
    {
        inline PESecurity( void )
        {
            this->secDataOffset = 0;
            this->secDataSize = 0;
        }

        std::uint32_t secDataOffset;    // this is file offset NOT RVA
        std::uint32_t secDataSize;
    };
    PESecurity security;

    struct PEBaseReloc
    {
        std::uint32_t offsetOfReloc;

        struct item
        {
            std::uint16_t type : 4;
            std::uint16_t offset : 12;
        };
        std::vector <item> items;
    };
    std::vector <PEBaseReloc> baseRelocs;

    PESectionAllocation baseRelocAllocEntry;

    struct PEDebug
    {
        inline PEDebug( void )
        {
            this->characteristics = 0;
            this->timeDateStamp = 0;
            this->majorVer = 0;
            this->minorVer = 0;
            this->type = 0;
            this->sizeOfData = 0;
            this->addrOfRawData = 0;
            this->ptrToRawData = 0;
        }

        std::uint32_t characteristics;
        std::uint32_t timeDateStamp;
        std::uint16_t majorVer, minorVer;
        std::uint32_t type;
        std::uint32_t sizeOfData;
        std::uint32_t addrOfRawData;
        std::uint32_t ptrToRawData;

        PESectionAllocation allocEntry;
    };
    PEDebug debugInfo;

    struct PEGlobalPtr
    {
        inline PEGlobalPtr( void )
        {
            this->ptrOffset = 0;
        }

        std::uint32_t ptrOffset;
    };
    PEGlobalPtr globalPtr;

    struct PEThreadLocalStorage
    {
        inline PEThreadLocalStorage( void )
        {
            this->startOfRawData = 0;
            this->endOfRawData = 0;
            this->addressOfIndices = 0;
            this->addressOfCallbacks = 0;
            this->sizeOfZeroFill = 0;
            this->characteristics = 0;
        }

        std::uint64_t startOfRawData;
        std::uint64_t endOfRawData;
        std::uint64_t addressOfIndices;
        std::uint64_t addressOfCallbacks;
        std::uint32_t sizeOfZeroFill;
        std::uint32_t characteristics;

        PESectionAllocation allocEntry;
    };
    PEThreadLocalStorage tlsInfo;

    struct PELoadConfig
    {
        inline PELoadConfig( void )
        {
            this->timeDateStamp = 0;
            this->majorVersion = 0;
            this->minorVersion = 0;
            this->globFlagsClear = 0;
            this->globFlagsSet = 0;
            this->critSecDefTimeOut = 0;
            this->deCommitFreeBlockThreshold = 0;
            this->deCommitTotalFreeThreshold = 0;
            this->lockPrefixTable = 0;
            this->maxAllocSize = 0;
            this->virtualMemoryThreshold = 0;
            this->processAffinityMask = 0;
            this->processHeapFlags = 0;
            this->CSDVersion = 0;
            this->reserved1 = 0;
            this->editList = 0;
            this->securityCookie = 0;
            this->SEHandlerTable = 0;
            this->SEHandlerCount = 0;
            this->guardCFCheckFunctionPtr = 0;
            this->reserved2 = 0;
            this->guardCFFunctionTable = 0;
            this->guardCFFunctionCount = 0;
            this->guardFlags = 0;
        }

        std::uint32_t timeDateStamp;
        std::uint16_t majorVersion, minorVersion;
        std::uint32_t globFlagsClear;
        std::uint32_t globFlagsSet;
        std::uint32_t critSecDefTimeOut;
        std::uint64_t deCommitFreeBlockThreshold;
        std::uint64_t deCommitTotalFreeThreshold;
        std::uint64_t lockPrefixTable;
        std::uint64_t maxAllocSize;
        std::uint64_t virtualMemoryThreshold;
        std::uint64_t processAffinityMask;
        std::uint32_t processHeapFlags;
        std::uint16_t CSDVersion;
        std::uint16_t reserved1;
        std::uint64_t editList;
        std::uint64_t securityCookie;
        std::uint64_t SEHandlerTable;
        std::uint64_t SEHandlerCount;
        std::uint64_t guardCFCheckFunctionPtr;
        std::uint64_t reserved2;
        std::uint64_t guardCFFunctionTable;
        std::uint64_t guardCFFunctionCount;
        std::uint32_t guardFlags;

        PESectionAllocation allocEntry;
    };
    PELoadConfig loadConfig;

    struct PEBoundImports
    {
        std::uint32_t timeDateStamp;
        std::string DLLName;

        struct binding
        {
            std::uint32_t timeDateStamp;
            std::string DLLName;
            std::uint16_t reserved;
        };
        std::vector <binding> bindings;
    };
    std::vector <PEBoundImports> boundImports;

    PESectionAllocation boundImportsAllocEntry;

    struct PEThunkIATStore
    {
        inline PEThunkIATStore( void )
        {
            this->thunkDataStart = 0;
            this->thunkDataSize = 0;
        }

        std::uint32_t thunkDataStart;
        std::uint32_t thunkDataSize;
    };
    PEThunkIATStore iatThunkAll;

    struct PEDelayLoadDesc
    {
        std::uint32_t attrib;
        std::string DLLName;
        PESectionAllocation DLLName_allocEntry;
        std::uint32_t DLLHandleOffset;
        std::uint32_t IATOffset;
        std::uint32_t importNameTableOffset;
        std::uint32_t boundImportAddrTableOffset;
        std::uint32_t unloadInfoTableOffset;
        std::uint32_t timeDateStamp;
    };
    std::vector <PEDelayLoadDesc> delayLoads;

    PESectionAllocation delayLoadsAllocEntry;

    struct PECommonLanguageRuntimeInfo
    {
        inline PECommonLanguageRuntimeInfo( void )
        {
            this->dataOffset = 0;
            this->dataSize = 0;
        }

        std::uint32_t dataOffset;
        std::uint32_t dataSize;
    };
    PECommonLanguageRuntimeInfo clrInfo;

    // Meta-data.
    bool is64Bit;

    inline static PEResourceDir LoadResourceDirectory( PESectionMan& sections, PEDataStream& rootStream, std::wstring nameOfDir, const PEStructures::IMAGE_RESOURCE_DIRECTORY& serResDir )
    {
        using namespace PEStructures;

        PEResourceDir curDir( std::move( nameOfDir ) );

        // Store general details.
        curDir.characteristics = serResDir.Characteristics;
        curDir.timeDateStamp = serResDir.TimeDateStamp;
        curDir.majorVersion = serResDir.MajorVersion;
        curDir.minorVersion = serResDir.MinorVersion;

        // Read sub entries.
        // Those are planted directly after the directory.
        std::uint16_t numNamedEntries = serResDir.NumberOfNamedEntries;
        std::uint16_t numIDEntries = serResDir.NumberOfIdEntries;

        // Function to read the data behind a resource directory entry.
        auto resDataParser = [&]( std::wstring nameOfItem, const PEStructures::IMAGE_RESOURCE_DIRECTORY_ENTRY& entry ) -> PEResourceItem*
        {
            // Seek to this data entry.
            rootStream.Seek( entry.OffsetToData );

            // Are we a sub-directory or an actual data leaf?
            if ( entry.DataIsDirectory )
            {
                // Get the sub-directory structure.
                PEStructures::IMAGE_RESOURCE_DIRECTORY subDirData;
                rootStream.Read( &subDirData, sizeof(subDirData) );

                PEResourceDir subDir = LoadResourceDirectory( sections, rootStream, std::move( nameOfItem ), subDirData );

                PEResourceDir *subDirItem = new PEResourceDir( std::move( subDir ) );

                return subDirItem;
            }
            else
            {
                // Get the data leaf.
                PEStructures::IMAGE_RESOURCE_DATA_ENTRY itemData;
                rootStream.Read( &itemData, sizeof(itemData) );

                // We dont have to recurse anymore.
                PEResourceInfo resItem( std::move( nameOfItem ) );
                resItem.dataOffset = itemData.OffsetToData;
                resItem.dataSize = itemData.Size;
                resItem.codePage = itemData.CodePage;
                resItem.reserved = itemData.Reserved;

                PEResourceInfo *resItemPtr = new PEResourceInfo( std::move( resItem ) );

                return resItemPtr;
            }
        };

        curDir.children.reserve( numNamedEntries + numIDEntries );

        // Due to us using only one PEDataStream we need to seek to all our entries properly.
        std::uint32_t subDirStartOff = rootStream.Tell();

        for ( size_t n = 0; n < numNamedEntries; n++ )
        {
            rootStream.Seek( subDirStartOff + n * sizeof(PEStructures::IMAGE_RESOURCE_DIRECTORY_ENTRY) );

            PEStructures::IMAGE_RESOURCE_DIRECTORY_ENTRY namedEntry;
            rootStream.Read( &namedEntry, sizeof(namedEntry) );

            if ( namedEntry.NameIsString == false )
            {
                throw std::exception( "invalid PE resource directory entry: expected named entry" );
            }

            // Load the name.
            std::wstring nameOfItem;
            {
                rootStream.Seek( namedEntry.NameOffset );

                ReadPEString( rootStream, nameOfItem );
            }

            // Create a resource item.
            PEResourceItem *resItem = resDataParser( std::move( nameOfItem ), namedEntry );

            resItem->hasIdentifierName = false;

            // Store ourselves.
            curDir.children.push_back( resItem );
        }

        for ( size_t n = 0; n < numIDEntries; n++ )
        {
            rootStream.Seek( subDirStartOff + ( n + numNamedEntries ) * sizeof(PEStructures::IMAGE_RESOURCE_DIRECTORY_ENTRY) );
            
            PEStructures::IMAGE_RESOURCE_DIRECTORY_ENTRY idEntry;
            rootStream.Read( &idEntry, sizeof(idEntry) );

            if ( idEntry.NameIsString == true )
                throw std::exception( "invalid PE resource directory ID entry" );

            // Create a resource item.
            PEResourceItem *resItem = resDataParser( std::wstring(), idEntry );

            resItem->identifier = idEntry.Id;
            resItem->hasIdentifierName = true;

            // Store it.
            curDir.children.push_back( resItem );
        }

        return curDir;
    }

private:
    // Helper functions to off-load the duty work from the main
    // serialization function.
    std::uint16_t GetPENativeFileFlags( void );
    std::uint16_t GetPENativeDLLOptFlags( void );

public:
    void CommitDataDirectories( void );
};

#endif //_PELOADER_CORE_