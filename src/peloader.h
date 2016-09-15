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
        std::uint32_t sectionAlignment;
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

    struct PESection
    {
        PESection( void );
        PESection( const PESection& right ) = delete;
        PESection( PESection&& right ) = default;
        ~PESection( void );

        inline PESection& operator =( const PESection& right ) = delete;
        inline PESection& operator =( PESection&& right ) = default;

        std::string shortName;
        union
        {
            std::uint32_t physAddr;
            std::uint32_t virtualSize;
        };
        std::uint32_t virtualAddr;
        
        std::vector <PERelocation> relocations;
        std::vector <PELinenumber> linenumbers;

        // Characteristics.
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
        eAlignment sect_alignment;

        bool sect_link_nreloc_ovfl;
        bool sect_mem_discardable;
        bool sect_mem_not_cached;
        bool sect_mem_not_paged;
        bool sect_mem_shared;
        bool sect_mem_execute;
        bool sect_mem_read;
        bool sect_mem_write;

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
                }

                // Invalidate the old section.
                right.theSection = NULL;
            }

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

            inline ~PESectionAllocation( void )
            {
                this->removeFromSection();
            }

            // Data-access methods for this allocation
            void WriteToSection( const void *dataPtr, std::uint32_t dataSize, std::int32_t dataOff = 0 );

            PESection *theSection;
            std::uint32_t sectOffset;
            std::uint32_t dataSize;     // if 0 then true size not important/unknown.

            // Every allocation can ONLY exist on ONE section.

            sectionSpaceAlloc_t::block_t sectionBlock;
        };

        // Allocation methods.
        std::uint32_t Allocate( PESectionAllocation& blockMeta, std::uint32_t allocSize, std::uint32_t alignment = sizeof(std::uint32_t) );
        void SetPlacedMemory( PESectionAllocation& blockMeta, std::uint32_t allocOff, std::uint32_t allocSize = 0u );

        std::uint32_t GetPENativeFlags( void ) const;

        // If we are final, we DO NOT keep a list of allocations.
        // Otherwise we keep a collisionless struct of allocations we made.
        sectionSpaceAlloc_t dataAlloc;

private:
        // Writing and possibly reading from this data section
        // should be done through this memory stream.
        BasicMemStream::basicMemStreamAllocMan <std::int32_t> streamAllocMan;

public:
        typedef BasicMemStream::basicMemoryBufferStream <std::int32_t> memStream;

        memStream stream;
    };
    using PESectionAllocation = PESection::PESectionAllocation;

    std::vector <PESection> sections;

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
            std::uint32_t exportOff;
            std::string forwarder;
            bool isForwarder;
            PESectionAllocation forwAllocEntry;
            
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

    // Function to get a data pointer of data directories.
    inline static const void* GetPEDataPointer(
        std::vector <PESection>& sections,
        std::uint64_t virtAddr, std::uint64_t virtSize,
        PESection **allocSectOut = NULL
    )
    {
        typedef sliceOfData <std::uint64_t> memSlice_t;

        // Create a memory slice of the request.
        memSlice_t requestRegion( virtAddr, virtSize );

        for ( PESection& sect : sections )
        {
            // Create a memory slice of this section.
            std::uint64_t sectAddr, sectSize;
            {
                sectAddr = sect.virtualAddr;
                sectSize = sect.stream.Size();
            }

            memSlice_t sectRegion( sectAddr, sectSize );

            // Our memory request has to be entirely inside of a section.
            memSlice_t::eIntersectionResult intResult = requestRegion.intersectWith( sectRegion );

            if ( intResult == memSlice_t::INTERSECT_INSIDE ||
                 intResult == memSlice_t::INTERSECT_EQUAL )
            {
                if ( allocSectOut )
                {
                    *allocSectOut = &sect;
                }

                // OK. We return a pointer into this section.
                return ( (const char*)sect.stream.Data() + ( virtAddr - sectAddr ) );
            }
        }

        // Not found.
        return NULL;
    }

    inline static PEResourceDir LoadResourceDirectory( const void *resRootDir, std::vector <PESection>& sections, std::wstring nameOfDir, const PEStructures::IMAGE_RESOURCE_DIRECTORY *serResDir )
    {
        using namespace PEStructures;

        PEResourceDir curDir( std::move( nameOfDir ) );

        // Store general details.
        curDir.characteristics = serResDir->Characteristics;
        curDir.timeDateStamp = serResDir->TimeDateStamp;
        curDir.majorVersion = serResDir->MajorVersion;
        curDir.minorVersion = serResDir->MinorVersion;

        // Read sub entries.
        // Those are planted directly after the directory.
        std::uint16_t numNamedEntries = serResDir->NumberOfNamedEntries;
        std::uint16_t numIDEntries = serResDir->NumberOfIdEntries;

        const PEStructures::IMAGE_RESOURCE_DIRECTORY_ENTRY *dirEntries =
            (const PEStructures::IMAGE_RESOURCE_DIRECTORY_ENTRY*)( serResDir + 1 );

        // Function to read the data behind a resource directory entry.
        auto resDataParser = [&]( std::wstring nameOfItem, const PEStructures::IMAGE_RESOURCE_DIRECTORY_ENTRY& entry ) -> PEResourceItem*
        {
            // Are we a sub-directory or an actual data leaf?
            if ( entry.DataIsDirectory )
            {
                // Get the sub-directory structure.
                const PEStructures::IMAGE_RESOURCE_DIRECTORY *subDirData =
                    (const PEStructures::IMAGE_RESOURCE_DIRECTORY*)( (const char*)resRootDir + entry.OffsetToDirectory );

                if ( !subDirData )
                    throw std::exception( "invalid PE resource directory data" );

                PEResourceDir subDir = LoadResourceDirectory( resRootDir, sections, std::move( nameOfItem ), subDirData );

                PEResourceDir *subDirItem = new PEResourceDir( std::move( subDir ) );

                return subDirItem;
            }
            else
            {
                // Read the data leaf.
                const PEStructures::IMAGE_RESOURCE_DATA_ENTRY *itemData =
                    (const PEStructures::IMAGE_RESOURCE_DATA_ENTRY*)( (const char*)resRootDir + entry.OffsetToData );

                if ( !itemData )
                    throw std::exception( "invalid PE resource item data" );

                // We dont have to recurse anymore.
                PEResourceInfo resItem( std::move( nameOfItem ) );
                resItem.dataOffset = itemData->OffsetToData;
                resItem.dataSize = itemData->Size;
                resItem.codePage = itemData->CodePage;
                resItem.reserved = itemData->Reserved;

                PEResourceInfo *resItemPtr = new PEResourceInfo( std::move( resItem ) );

                return resItemPtr;
            }
        };

        curDir.children.reserve( numNamedEntries + numIDEntries );

        for ( size_t n = 0; n < numNamedEntries; n++ )
        {
            const PEStructures::IMAGE_RESOURCE_DIRECTORY_ENTRY& namedEntry = dirEntries[ n ];

            if ( namedEntry.NameIsString == false )
                throw std::exception( "invalid PE resource directory named entry" );

            // Load the name.
            std::wstring nameOfItem;
            {
                const PEStructures::IMAGE_RESOURCE_DIR_STRING_U *strEntry =
                    (const PEStructures::IMAGE_RESOURCE_DIR_STRING_U*)( (const char*)resRootDir + namedEntry.NameOffset );

                if ( !strEntry )
                    throw std::exception( "invalid PE resource directory string" );

                nameOfItem = std::wstring( strEntry->NameString, strEntry->Length );
            }

            // Create a resource item.
            PEResourceItem *resItem = resDataParser( std::move( nameOfItem ), namedEntry );

            resItem->hasIdentifierName = false;

            // Store ourselves.
            curDir.children.push_back( resItem );
        }

        for ( size_t n = 0; n < numIDEntries; n++ )
        {
            const PEStructures::IMAGE_RESOURCE_DIRECTORY_ENTRY& idEntry = dirEntries[ numNamedEntries + n ];

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

    // Helper functions to off-load the duty work from the main
    // serialization function.
    std::uint16_t GetPENativeFileFlags( void );
    std::uint16_t GetPENativeDLLOptFlags( void );

    // Generic section management API.
    PESection* FindFirstSectionByName( const char *name );
    PESection* FindFirstAllocatableSection( void );
    bool RemoveSection( PESection *section );

    void CommitDataDirectories( void );
};

#endif //_PELOADER_CORE_