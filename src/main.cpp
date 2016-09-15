#include "StdInc.h"
#include <memory>

#include <assert.h>

#include <CFileSystem.h>

#include "peloader.h"

extern CFileSystem *fileSystem;

thread_local std::string myTestString = "hello_world";
thread_local std::string debugStringOfValue = "debug entry world";
thread_local int myValueTest = 1337;

__declspec(dllexport) int meow = 0;

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
        std::unique_ptr <CFile> filePtr( fileRoot->Open( "kernel32.dll", "rb" ) );

        if ( filePtr )
        {
            PEFile filedata;

            filedata.LoadFromDisk( filePtr.get() );

            // Write it to another location.
            // This is a test that we can 1:1 convert executables.
            std::unique_ptr <CFile> outFilePtr( fileRoot->Open( "out.exe", "wb" ) );

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