#include "StdInc.h"
#include <memory>

#include <assert.h>

#include <CFileSystem.h>

#include <peframework.h>

// Get PDB headers.
#include "msft_pdb/include/cvinfo.h"
#include "msft_pdb/langapi/include/pdb.h"
#include "msft_pdb/langapi/shared/crc32.h"

extern CFileSystem *fileSystem;

thread_local std::string myTestString = "hello_world";
thread_local std::string debugStringOfValue = "debug entry world";
thread_local int myValueTest = 1337;

__declspec(dllexport) int meow = 0;

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
    EC error_code_out;
    wchar_t errorBuf[ 4096 ];

    PDB *pdbHandle;

    BOOL openSuccess =
        PDB::Open2W(
            L"pdb_test.pdb", "wb", &error_code_out, errorBuf, _countof(errorBuf),
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
        
            BOOL gotMainMod = dbiHandle->OpenMod( "main", "main-module", &mainMod );

            if ( gotMainMod == TRUE )
            {
                // TODO: maybe do some stuff with this.

                // Close the main mod again.
                mainMod->Close();
            }
        }

        // Add some test symbols.
        {
            CV_PUBSYMFLAGS pubflags_func;
            pubflags_func.grfFlags = 0;
            pubflags_func.fFunction = true;

            dbiHandle->AddPublicW( L"testsym", 1, 0x10, pubflags_func.grfFlags );
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
        pdbHandle->QuerySignature2( &pdbDebugEntry.Signature );
        pdbDebugEntry.Age = pdbHandle->QueryAge();

        stream.Write( &pdbDebugEntry, sizeof(pdbDebugEntry) );

        // Then write the zero-terminated PDB file location, UTF-8.
        const std::string pdbLocation = "C:\\Users\\The_GTA\\Desktop\\pe_debug\\output\\pdb_test.pdb";

        stream.Write( pdbLocation.c_str(), pdbLocation.size() + 1 );

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
        const char *inputName = "pdb_test.exe";

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