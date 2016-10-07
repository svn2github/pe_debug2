#include "StdInc.h"
#include <memory>
#include <codecvt>
#include <regex>

#include <assert.h>

#include <CFileSystem.h>

#include <peframework.h>

#include <gtaconfig/include.h>

#include "mangle.h"

// Get PDB headers.
#include "msft_pdb/include/cvinfo.h"
#include "msft_pdb/langapi/include/pdb.h"
#include "msft_pdb/langapi/shared/crc32.h"

#include <Shellapi.h>

extern CFileSystem *fileSystem;

// From other compilation modules (for a reason).
void tryGenerateSamplePDB( PEFile& peFile, const filePath& outPathWithoutExt );

static void printHeader( void )
{
    printf(
        "PEframework PE file debug extender written by The_GTA\n" \
        "Made to advance the professionality of the GTA community hacking experience\n" \
        "wordwhirl@outlook.de\n\n"
    );
}

int main( int _, char *__[] )
{
    printHeader();

    // Parse the command line.
    const wchar_t *cmdLine = GetCommandLineW();

    int argc;

    const wchar_t *const *cmdArgs = CommandLineToArgvW( cmdLine, &argc );

    if ( cmdArgs == NULL )
    {
        printf( "failed to parse command line arguments\n" );
        return -1;
    }

    // Get the filename from the arguments, at least.
    if ( argc < 2 )
    {
        printf( "too little arguments; at least path to executable required\n" );
        return -1;
    }

    std::wstring executablePath;
    {
        // We skip the source executable path.
        for ( int n = 1; n < argc; n++ )
        {
            if ( n != 1 )
            {
                executablePath += L" ";
            }

            executablePath += cmdArgs[ n ];
        }
    }

    // We want to read our own PE executable.
    // After that we want to write it out again in the exactly same format.
    fs_construction_params constrParam;
    constrParam.nativeExecMan = NULL;

    CFileSystem::Create( constrParam );

    try
    {
        // Get access to the output file root.
        std::unique_ptr <CFileTranslator> workRoot( fileSystem->CreateSystemMinimumAccessPoint( executablePath.c_str() ) );

        if ( workRoot )
        {
            // Read the PE file.
            std::unique_ptr <CFile> filePtr( workRoot->Open( executablePath.c_str(), "rb" ) );

            if ( filePtr )
            {
                printf( "found input file, processing...\n" );

                PEFile filedata;

                filedata.LoadFromDisk( filePtr.get() );

                printf( "loaded input file from disk\n" );

                // Decide on the PE image type what output filename we should pick.
                filePath outFileName;

                // First get the same target directory as the input file.
                filePath nameItem = FileSystem::GetFileNameItem( filePtr->GetPath(), false, &outFileName, NULL );

                assert( nameItem.empty() == false );

                outFileName += nameItem;
                outFileName += "_debug";

                // Do some PDB magic I guess.
                tryGenerateSamplePDB( filedata, outFileName );

                // We get the extension from the PE file format.
                if ( filedata.IsDynamicLinkLibrary() )
                {
                    outFileName += ".dll";
                }
                else
                {
                    outFileName += ".exe";
                }

                // Write it to another location.
                // This is a test that we can 1:1 convert executables.
                std::unique_ptr <CFile> outFilePtr( fileRoot->Open( outFileName, "wb" ) );

                if ( outFilePtr )
                {
                    printf( "writing PE file\n" );

                    filedata.WriteToStream( outFilePtr.get() );

                    printf( "done!\n" );
                }
            }
            else
            {
                printf( "failed to find input file\n" );
            }
        }
        else
        {
            printf( "failed to get handle to work folder\n" );
        }
    }
    catch( ... )
    {
        CFileSystem::Destroy( fileSystem );

        throw;
    }

    // Clean-up.
    CFileSystem::Destroy( fileSystem );

    printf( "\n\nHave fun!\n" );

    // :-)
    return 0;
}