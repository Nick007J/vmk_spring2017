#pragma once
#include <Windows.h>
#include <stdio.h>

#pragma region __ Constants __
#define BUFFER_SIZE 0x1000
#define CYRILLIC_CODE_PAGE 1251 
#define MEGABYTE 1048576
#define MAX_FILE_SIZE_ALLOWED_TO_READ 20 * MEGABYTE
#define SIZE_OF_CALL_INSTRUCTION 5
#define OFFSET_PATTERN 0x77777777

#define CAN_NOT_READ_ENTIRE_FILE "Can not read entire file"
#define TOO_LARGE_FILE "File is larger than allowed, can not parse"
#define NULL_FILE_SIZE "File has size of 0"  

#define INVALID_OPTIONAL_HEADER_MAGIC "Not a valid magic in optional header\n"
#define INVALID_DOS_HEADER "Not a valid DOS header\n"
#define INVALID_NT_HEADER "File doesn't contain correct NT header\n"
#define INVALID_NT_SIGNATURE "Not a valid NT signature\n"
#define WRONG_NUMBER_OF_SECTIONS "Header doesn't contain all sections\n"
#define SECTION_NOT_FOUND "Section of entry point not found\n"
#define CODE_NOT_GENERATED "Code wasn't generated\n"
#define NO_STRATEGY_FOUND "No strategy for injection found\n"
#pragma endregion


#pragma region __ Structutes __
struct ENTRY_POINT_CODE
{
  DWORD sizeOfCode;
  char* code;
};
#pragma endregion


#pragma region __ Functions __
HANDLE GetFileFromArguments( int argc, char** argv );
DWORD ReadFileToBuffer( HANDLE fileHandle, char* buffer, DWORD bufferSize );
DWORD WriteFileFromBuffer( char* filename, char* buffer, DWORD bufferSize );
void ChangeEntryPoint( char* buffer, DWORD bufferSize, char* originalFilename );
DWORD CheckFileSizeForCorrectness( DWORD fileSize );
DWORD* GetPositionOfPattern( char* buffer, DWORD bufferSize, DWORD pattern );
ENTRY_POINT_CODE GetEntryPointCodeSmall( DWORD rvaToNewEntryPoint, DWORD rvaToOriginalEntryPoint );

void PrintError( char* functionFrom );
void PrintHelp( char* programName );
#pragma endregion

