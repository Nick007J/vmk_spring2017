#include <Windows.h>
#include <stdio.h>

#define BUFFER_SIZE 0x1000


HANDLE GetFileFromArguments( int argc, char** argv );
unsigned int ReadFileToBuffer( HANDLE fileHandle, char buffer[ BUFFER_SIZE ] );
void PrintHelp( char* programName );
void PrintError( char* functionFrom );
void ParseFile( char* buffer, int bufferSize );

int main( int argc, char** argv )
{
  HANDLE fileHandle = GetFileFromArguments( argc, argv );
  if( NULL != fileHandle )
  {
    char buffer[ BUFFER_SIZE ];
    int readSize = ReadFileToBuffer( fileHandle, buffer );
    CloseHandle( fileHandle );
    if( 0x00 != readSize )
    {
      ParseFile( buffer, readSize );
    }
  }
  return 0x00;
}

HANDLE GetFileFromArguments( int argc, char** argv )
{
  HANDLE fileHandle = NULL;
  if( 0x02 == argc )
  {
    fileHandle = CreateFileA( argv[ 0x01 ], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if( INVALID_HANDLE_VALUE == fileHandle )
    {
      PrintError( "CreateFileA" );
    }
  }
  else
  {
    PrintHelp( argv[ 0x00 ] );
  }
  return fileHandle;
}

unsigned int ReadFileToBuffer( HANDLE fileHandle, char buffer[ BUFFER_SIZE ] )
{
  unsigned int returnValue = 0x00;
  if( NULL != fileHandle )
  {
    unsigned int fileSize = GetFileSize( fileHandle, NULL );
    if( INVALID_FILE_SIZE == fileSize )
    {
      PrintError( "GetFileSize" );
    }
    else
    {
      unsigned long bytesRead;
      fileSize = min( fileSize, BUFFER_SIZE );
      if( true == ReadFile( fileHandle, buffer, fileSize, &bytesRead, NULL ) )
      {
        returnValue = bytesRead;
      }
      else
      {
        PrintError( "ReadFile" );
      }
    }
  }
  return returnValue;
}

int GetInfoFromNTHeader(void* p_optheader, ULONGLONG* ib, DWORD* ep)
{
    IMAGE_OPTIONAL_HEADER32* opth32 = (IMAGE_OPTIONAL_HEADER32*)p_optheader;
    if (opth32->Magic == 0x10B || opth32->Magic == 0x107) {
        *ib = opth32->ImageBase;
        *ep = opth32->AddressOfEntryPoint;
        return 1;
    }
    IMAGE_OPTIONAL_HEADER64* opth64 = (IMAGE_OPTIONAL_HEADER64*)p_optheader;
    if (opth64->Magic == 0x20B) {
        *ib = opth64->ImageBase;
        *ep = opth64->AddressOfEntryPoint;
        return 1;
    }
    return 0;
}

void ParseFile(char* buffer, int bufferSize)
{
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buffer;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a valid DOS header\n");
        return;
    }
    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(buffer + dos_header->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        printf("Not a valid NT signature\n");
        return;
    }
    IMAGE_FILE_HEADER* file_header = &nt_header->FileHeader;
    WORD nsec = file_header->NumberOfSections;
    ULONGLONG ib;
    DWORD ep;
    if (!GetInfoFromNTHeader(&nt_header->OptionalHeader, &ib, &ep)) {
        printf("Not a valid magic in optional header\n");
        return;
    }
    printf("Entry point (%llX)\n", ep+ib);
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt_header);
    for (WORD i = 0; i < nsec; i++, section++) {
        DWORD va = section->VirtualAddress;
        DWORD size = section->Misc.VirtualSize;
        if (va < ep && ep < va + size) {
            char* name = (char*)malloc(IMAGE_SIZEOF_SHORT_NAME + 1);
            memcpy(name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
            name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
            printf("In section %d, %s\n", i, name);
            DWORD offset = (ep - va) * 100 / size;
            printf("Offset in section %X, %d %%\n", ep - va, offset);
            free(name);
            return;
        }
    }
    printf("Section of entry point not found\n");
    printf("Buffer length: %d\n", bufferSize);
}

#pragma region __ Print functions __
void PrintHelp( char* programName )
{
  printf( "Usage:\n%s <filename>", programName );
}

void PrintError( char* functionFrom )
{
  char* errorMessage;
  DWORD errorCode = GetLastError( );

  // Retrieve the system error message for the last-error code
  FormatMessageA( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  errorCode,
                  MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
                  ( LPSTR ) &errorMessage,
                  0, NULL );

  printf( "In function %s, error %d:\n%s", functionFrom, errorCode, errorMessage );
  LocalFree( errorMessage );
}

#pragma endregion

