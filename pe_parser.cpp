#include <Windows.h>
#include <stdio.h>

#define BUFFER_SIZE 0x1000
#define CYRILLIC_CODE_PAGE 1251


HANDLE GetFileFromArguments( int argc, char** argv );
unsigned int ReadFileToBuffer( HANDLE fileHandle, char* buffer, unsigned int size );
void PrintHelp( char* programName );
void PrintError( char* functionFrom );
void ParseFile( char* buffer, unsigned int bufferSize, HANDLE* file_handle );

int main( int argc, char** argv )
{
  UINT codePage = GetConsoleOutputCP();
  SetConsoleOutputCP(CYRILLIC_CODE_PAGE); // set code page to display russian symbols

  HANDLE fileHandle = GetFileFromArguments( argc, argv );
  if( NULL != fileHandle )
  {
    char buffer[ BUFFER_SIZE ];
    unsigned int readSize = ReadFileToBuffer( fileHandle, buffer, BUFFER_SIZE );   
    if( 0x00 != readSize )
    {
      ParseFile( buffer, readSize, &fileHandle );
    }
    CloseHandle(fileHandle);
  }

  SetConsoleOutputCP(codePage);  // restore code page
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

unsigned int ReadFileToBuffer( HANDLE fileHandle, char* buffer, unsigned int size )
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
      fileSize = min( fileSize, size );
      SetFilePointer( fileHandle, 0, NULL, FILE_BEGIN );
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

int GetInfoFromNTHeader(void* opt_header, ULONGLONG* image_base, DWORD* entry_point)
{
    IMAGE_OPTIONAL_HEADER32* opth32 = (IMAGE_OPTIONAL_HEADER32*)opt_header;
    if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == opth32->Magic || IMAGE_ROM_OPTIONAL_HDR_MAGIC == opth32->Magic) {
        *image_base = opth32->ImageBase;
        *entry_point = opth32->AddressOfEntryPoint;
        return 1;
    }
    IMAGE_OPTIONAL_HEADER64* opth64 = (IMAGE_OPTIONAL_HEADER64*)opt_header;
    if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == opth64->Magic) {
        *image_base = opth64->ImageBase;
        *entry_point = opth64->AddressOfEntryPoint;
        return 1;
    }
    return 0;
}

bool ReadFileAgain(unsigned int required_size, unsigned int* new_size, char** buffer, bool* memory_allocated, HANDLE* file_handle)
{
    unsigned int pure_size = (required_size / BUFFER_SIZE + 1) * BUFFER_SIZE;
    if (*memory_allocated)
        free(*buffer);
    *buffer = (char*)malloc(pure_size);
    *memory_allocated = true;
    *new_size = ReadFileToBuffer(*file_handle, *buffer, pure_size);
    if (*new_size < required_size)
        return false;
    return true;
}

char* GetSectionName(IMAGE_SECTION_HEADER* section)
{
    char* new_name = (char*)malloc(IMAGE_SIZEOF_SHORT_NAME + 1);
    memcpy(new_name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
    new_name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
    return new_name;
}

void ParseFile(char* buffer, unsigned int buffer_size, HANDLE* file_handle)
{
    bool memory_allocated = false;
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buffer;
    if (IMAGE_DOS_SIGNATURE != dos_header->e_magic) {
        printf("Not a valid DOS header\n");
        goto cleanup;
    }
    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(buffer + dos_header->e_lfanew);
    if ((unsigned int)nt_header - (unsigned int)buffer + sizeof(IMAGE_NT_HEADERS) > buffer_size) {
        if (!ReadFileAgain((unsigned int)nt_header - (unsigned int)buffer + sizeof(IMAGE_NT_HEADERS), &buffer_size, &buffer, &memory_allocated, file_handle)) {
            printf("File doesn't contain correct NT header\n");
            goto cleanup;
        }
        dos_header = (IMAGE_DOS_HEADER*)buffer;
        nt_header = (IMAGE_NT_HEADERS*)(buffer + dos_header->e_lfanew);
    }
    if (IMAGE_NT_SIGNATURE != nt_header->Signature) {
        printf("Not a valid NT signature\n");
        goto cleanup;
    }
    IMAGE_FILE_HEADER* file_header = &nt_header->FileHeader;
    WORD nsec = file_header->NumberOfSections;
    ULONGLONG image_base;
    DWORD entry_point;
    if (!GetInfoFromNTHeader(&nt_header->OptionalHeader, &image_base, &entry_point)) {
        printf("Not a valid magic in optional header\n");
        goto cleanup;
    }
    printf("Entry point (%llX)\n", entry_point + image_base);
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt_header);
    if ((unsigned int)section - (unsigned int)buffer + sizeof(IMAGE_SECTION_HEADER)*nsec > buffer_size) {

        if (!ReadFileAgain(((unsigned int)section - (unsigned int)buffer + sizeof(IMAGE_SECTION_HEADER)*nsec), &buffer_size, &buffer, &memory_allocated, file_handle)) {
            printf("Header doesn't contain all sections\n");
            return;
        }
        dos_header = (IMAGE_DOS_HEADER*)buffer;
        nt_header = (IMAGE_NT_HEADERS*)(buffer + dos_header->e_lfanew);
        section = IMAGE_FIRST_SECTION(nt_header);
    }
    for (WORD i = 0; i < nsec; i++, section++) {
        DWORD virt_address = section->VirtualAddress;
        DWORD size = section->Misc.VirtualSize;
        if (virt_address <= entry_point && entry_point < virt_address + size) {
            char* name = GetSectionName(section);
            printf("In section %d, %s\n", i, name);
            DWORD offset = (entry_point - virt_address) * 100 / size;
            printf("Offset in section %lX, %ld %%\n", entry_point - virt_address, offset);
            free(name);
            goto cleanup;
        }
    }
    printf("Section of entry point not found\n");
    printf("Buffer length: %d\n", buffer_size);
cleanup:
    if (memory_allocated)
        free(buffer);
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

