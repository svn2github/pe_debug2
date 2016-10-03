#include "StdInc.h"
#include <memory>
#include <codecvt>
#include <regex>

#include <assert.h>

#include <CFileSystem.h>

#include <peframework.h>

#include <gtaconfig/include.h>

// Get PDB headers.
#include "msft_pdb/include/cvinfo.h"
#include "msft_pdb/langapi/include/pdb.h"
#include "msft_pdb/langapi/shared/crc32.h"

extern CFileSystem *fileSystem;

thread_local std::string myTestString = "hello_world";
thread_local std::string debugStringOfValue = "debug entry world";
thread_local int myValueTest = 1337;

__declspec(dllexport) int meow = 0;

// Utility to parse debug information from a text file, created by an IDC script...
// https://www.hex-rays.com/products/ida/support/freefiles/dumpinfo.idc
struct nameInfo
{
    std::string name;
    std::uint64_t absolute_va;
};
typedef std::vector <nameInfo> symbolNames_t;

static const std::regex patternMatchItem( "[\\w\\d\\.]+\\:([0123456789aAbBcCdDeEfF]+)[\\s\\t]+\\(([^)]+)\\)[\\s\\t]+(.+)" );

static symbolNames_t ParseSymbolNames( CFile *inputStream )
{
    symbolNames_t symbols;

    // We skip 11 lines.
    for ( size_t n = 0; n < 11; n++ )
    {
        std::string _skipContent;

        Config::GetConfigLine( inputStream, _skipContent );
    }

    // Read all entries.
    while ( inputStream->IsEOF() == false )
    {
        std::string lineCont;

        bool gotLine = Config::GetConfigLine( inputStream, lineCont );

        if ( gotLine )
        {
            std::smatch results;

            bool gotMatch = std::regex_match( lineCont, results, patternMatchItem );

            if ( gotMatch && results.size() == 4 )
            {
                std::string offset = std::move( results[ 1 ] );
                std::string typeName = std::move( results[ 2 ] );
                std::string valueString = std::move( results[ 3 ] );

                if ( typeName == "UserName" )
                {
                    try
                    {
                        nameInfo newInfo;
                        newInfo.name = std::move( valueString );
                        newInfo.absolute_va = std::stoull( offset, NULL, 16 );

                        symbols.push_back( std::move( newInfo ) );
                    }
                    catch( ... )
                    {
                        // Ignore cast error.
                    }
                }
            }
        }
    }

    return symbols;
}

// Thanks to https://www.snip2code.com/Snippet/735099/Dump-PDB-information-from-a-PE-file/
const DWORD CV_SIGNATURE_RSDS = 0x53445352; // 'SDSR'

struct CV_INFO_PDB70
{
    DWORD      CvSignature;
    SIG70      Signature;
    DWORD      Age;
    //BYTE       PdbFileName[1];
};

static void tryGenerateSamplePDB( PEFile& peFile )
{
    // Prepare symbol names from an input file.
    symbolNames_t symbols;
    {
        std::unique_ptr <CFile> symbolsFile( fileRoot->Open( L"symbols.txt", "rb" ) );

        if ( symbolsFile )
        {
            symbols = ParseSymbolNames( symbolsFile.get() );
        }
    }
    
    // Establish a file location.
    std::wstring widePDBFileLocation;
    {
        filePath pdbFileLocation;

        fileRoot->GetFullPathFromRoot( L"gen.pdb", true, pdbFileLocation );

        widePDBFileLocation = pdbFileLocation.convert_unicode();
    }

    EC error_code_out;
    wchar_t errorBuf[ 4096 ];

    PDB *pdbHandle;

    BOOL openSuccess =
        PDB::Open2W(
            widePDBFileLocation.c_str(), "wb", &error_code_out, errorBuf, _countof(errorBuf),
            &pdbHandle
        );

    if ( openSuccess == FALSE )
    {
        // We fail in life.
        return;
    }

    // Yes!
    DBI *dbiHandle;

    BOOL dbiOpenSuccess =  pdbHandle->OpenDBI( NULL, "wb", &dbiHandle );

    if ( dbiOpenSuccess == TRUE )
    {
        // One step closer.

        // I guess we should try creating a module and putting symbols into it?
        // Or something else... Let's see...
        dbiHandle->SetMachineType( IMAGE_FILE_MACHINE_I386 );

        // It is a good idea to create a dummy module, at least.
        {
            Mod *mainMod = NULL;
        
            BOOL gotMainMod = dbiHandle->OpenMod( "main", "main-module (made possible by The_GTA, wordwhirl@outlook.de)", &mainMod );

            if ( gotMainMod == TRUE )
            {
                // TODO: maybe do some stuff with this.

                // Close the main mod again.
                mainMod->Close();
            }
        }

        // Embed parsed symbols as publics.
        {
            CV_PUBSYMFLAGS pubflags_func;
            pubflags_func.grfFlags = 0;
            pubflags_func.fFunction = true;

            CV_PUBSYMFLAGS pubflags_data;
            pubflags_data.grfFlags = 0;

            std::uint64_t imageBase = peFile.GetImageBase();

            for ( const nameInfo& infoItem : symbols )
            {
                // Convert the VA into a RVA.
                std::uint32_t rva = (std::uint32_t)( infoItem.absolute_va - imageBase );

                // Find the section associated with this item.
                // If we found it, add it as public symbol.
                std::uint32_t sectIndex = 0;

                PEFile::PESection *symbSect = peFile.FindSectionByRVA( rva, &sectIndex );

                if ( symbSect )
                {
                    // Get the offset into the section.
                    std::uint32_t native_off = ( rva - symbSect->GetVirtualAddress() );
                    
                    // If this item is in the executable section, we put a function symbol.
                    // Otherwise we put a data symbol.
                    CV_pubsymflag_t useFlags;

                    if ( symbSect->chars.sect_mem_execute )
                    {
                        useFlags = pubflags_func.grfFlags;
                    }
                    else
                    {
                        useFlags = pubflags_data.grfFlags;
                    }

                    dbiHandle->AddPublic2( infoItem.name.c_str(), sectIndex + 1, native_off, useFlags );
                }
            }
        }

        // Write information about all sections.
        Dbg *dbgSectHeader;

        BOOL gotSectStream = dbiHandle->OpenDbg( dbgtypeSectionHdr, &dbgSectHeader );

        if ( gotSectStream == TRUE )
        {
            // We do not want any previous data.
            dbgSectHeader->Clear();

            // Write new things.
            peFile.ForAllSections(
                [&]( PEFile::PESection *sect )
            {
                IMAGE_SECTION_HEADER header;
                strncpy( (char*)header.Name, sect->shortName.c_str(), _countof(header.Name) );
                header.Misc.VirtualSize = sect->GetVirtualSize();
                header.VirtualAddress = sect->GetVirtualAddress();
                header.SizeOfRawData = (DWORD)sect->stream.Size();
                header.PointerToRawData = 0;
                header.PointerToRelocations = 0;
                header.PointerToLinenumbers = 0;
                header.NumberOfRelocations = 0;
                header.NumberOfLinenumbers = 0;
                header.Characteristics = sect->GetPENativeFlags();

                dbgSectHeader->Append( 1, &header );
            });

            dbgSectHeader->Close();
        }

        // Remember to close our stuff.
        dbiHandle->Close();
    }

    // Make sure everything is written?
    pdbHandle->Commit();

    // Inject PDB information into the EXE file.
    {
        peFile.ClearDebugDataOfType( IMAGE_DEBUG_TYPE_CODEVIEW );

        PEFile::PEDebugDesc& cvDebug = peFile.AddDebugData( IMAGE_DEBUG_TYPE_CODEVIEW );

        PEFile::fileSpaceStream_t stream = cvDebug.dataStore.OpenStream();

        // First write the header.
        CV_INFO_PDB70 pdbDebugEntry;
        pdbDebugEntry.CvSignature = CV_SIGNATURE_RSDS;
        BOOL gotSig = pdbHandle->QuerySignature2( &pdbDebugEntry.Signature );
        pdbDebugEntry.Age = pdbHandle->QueryAge();

        assert( gotSig == TRUE );

        stream.Write( &pdbDebugEntry, sizeof(pdbDebugEntry) );

        // Inside of the EXE file we must use backslashes.
        std::replace( widePDBFileLocation.begin(), widePDBFileLocation.end(), L'/', L'\\' );

        // Create a UTF-8 version of the wide PDB location string.
        std::string utf8_pdbLoc;
        {
            std::wstring_convert <std::codecvt_utf8 <wchar_t>> utf8_conv;
            utf8_pdbLoc = utf8_conv.to_bytes( widePDBFileLocation );
        }

        // Then write the zero-terminated PDB file location, UTF-8.
        stream.Write( utf8_pdbLoc.c_str(), utf8_pdbLoc.size() + 1 );

        // Done!
    }

    // Remember to close our PDB again for sanity!
    pdbHandle->Close();
}

int main( int argc, char *argv[] )
{
    // We want to read our own PE executable.
    // After that we want to write it out again in the exactly same format.
    fs_construction_params constrParam;
    constrParam.nativeExecMan = NULL;

    CFileSystem::Create( constrParam );

    try
    {
        // Read some PE file.
        const char *inputName = "gta_sa.exe";

        std::unique_ptr <CFile> filePtr( fileRoot->Open( inputName, "rb" ) );

        if ( filePtr )
        {
            PEFile filedata;

            filedata.LoadFromDisk( filePtr.get() );

            // Do some PDB magic I guess.
            tryGenerateSamplePDB( filedata );

            // Decide on the PE image type what output filename we should pick.
            filePath outFileName;

            if ( filedata.IsDynamicLinkLibrary() )
            {
                outFileName = "out.dll";
            }
            else
            {
                outFileName = "out.exe";
            }

            // If we have the same input name as output name, then
            // slightly change the output name.
            if ( outFileName.equals( inputName, false ) )
            {
                filePath extItem;
                
                filePath nameItem = FileSystem::GetFileNameItem( outFileName, false, NULL, &extItem );

                outFileName = ( nameItem + "_new." + extItem );
            }

            // Write it to another location.
            // This is a test that we can 1:1 convert executables.
            std::unique_ptr <CFile> outFilePtr( fileRoot->Open( outFileName, "wb" ) );

            if ( outFilePtr )
            {
                filedata.WriteToStream( outFilePtr.get() );
            }
        }
    }
    catch( ... )
    {
        CFileSystem::Destroy( fileSystem );

        throw;
    }

    // Clean-up.
    CFileSystem::Destroy( fileSystem );

    // :-)
    return 0;
}