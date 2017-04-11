#include "pe_parser.h"

int GetInfoFromNTHeader(void* optHeader, ULONGLONG* imageBase, DWORD** entryPoint)
{
    IMAGE_OPTIONAL_HEADER32* opth32 = (IMAGE_OPTIONAL_HEADER32*)optHeader;
    if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == opth32->Magic || IMAGE_ROM_OPTIONAL_HDR_MAGIC == opth32->Magic) {
        *imageBase = opth32->ImageBase;
        *entryPoint = &opth32->AddressOfEntryPoint;
        return 1;
    }
    IMAGE_OPTIONAL_HEADER64* opth64 = (IMAGE_OPTIONAL_HEADER64*)optHeader;
    if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == opth64->Magic) {
        *imageBase = opth64->ImageBase;
        *entryPoint = &opth64->AddressOfEntryPoint;
        return 1;
    }
    return 0;
}

bool GetNTHeader(char* buffer, unsigned int bufferSize, IMAGE_NT_HEADERS** header)
{
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buffer;
    if (IMAGE_DOS_SIGNATURE != dos_header->e_magic) {
        printf(INVALID_DOS_HEADER);
        return false;
    }
    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(buffer + dos_header->e_lfanew);
    if ((unsigned int)nt_header - (unsigned int)buffer + sizeof(IMAGE_NT_HEADERS) > bufferSize) {
        printf(INVALID_NT_HEADER);
        return false;
    }
    if (IMAGE_NT_SIGNATURE != nt_header->Signature) {
        printf(INVALID_NT_SIGNATURE);
        return false;
    }
    *header = nt_header;
    return true;
}

bool CheckValidityOfEntryPointCode(ENTRY_POINT_CODE* code)
{
    return code->sizeOfCode != 0;
}

void WriteNewFile(char* originalFilename, char* buffer, DWORD bufferSize)
{
    const char* suffix = "_new";
    char* newFilename = (char*)malloc(strlen(originalFilename) + strlen(suffix) + 1);
    char* exePtr = strstr(originalFilename, ".exe");
    if (exePtr) {
        memcpy(newFilename, originalFilename, exePtr - originalFilename);
        memcpy(newFilename + (exePtr - originalFilename), suffix, strlen(suffix));
        memcpy(newFilename + (exePtr - originalFilename) + strlen(suffix), exePtr, strlen(originalFilename) - (exePtr - originalFilename));
    }
    else {
        memcpy(newFilename, originalFilename, strlen(originalFilename));
        memcpy(newFilename + strlen(originalFilename), suffix, strlen(suffix));
    }
    newFilename[strlen(originalFilename) + strlen(suffix)] = '\0';
    WriteFileFromBuffer(newFilename, buffer, bufferSize);
    free(newFilename);
}

void FixSectionRawData(IMAGE_NT_HEADERS* ntHeader, WORD numSections, DWORD rawAddress, DWORD rawOffset)
{
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);
    for (WORD i = 0; i < numSections; i++, section++) {
        if (section->PointerToRawData >= rawAddress)
            section->PointerToRawData += rawOffset;
    }
}

DWORD AlignAddress(DWORD original, DWORD alignment)
{
    return (original / alignment + 1) * alignment;
}

void ChangeEntryPoint( char* buffer, DWORD bufferSize, char* originalFilename )
{
    IMAGE_NT_HEADERS* ntHeader;
    if (!GetNTHeader(buffer, bufferSize, &ntHeader))
        return;
    DWORD* entryPoint;
    ULONGLONG imageBase;
    if (!GetInfoFromNTHeader(&ntHeader->OptionalHeader, &imageBase, &entryPoint)) {
        printf(INVALID_OPTIONAL_HEADER_MAGIC);
        return;
    }
    IMAGE_FILE_HEADER* fileHeader = &ntHeader->FileHeader;
    WORD* nsec = &fileHeader->NumberOfSections;
    if ((unsigned int)IMAGE_FIRST_SECTION(ntHeader) - (unsigned int)buffer + sizeof(IMAGE_SECTION_HEADER) * *nsec > bufferSize) {
        printf(WRONG_NUMBER_OF_SECTIONS);
        return;
    }
    IMAGE_SECTION_HEADER* j = IMAGE_FIRST_SECTION(ntHeader);
    IMAGE_SECTION_HEADER* section = NULL;
    WORD i;
    DWORD firstFileAddress = MAXDWORD;
    DWORD lastVirtualAddress = 0;
    DWORD sizeOfLastSection = 0;
    for (i = 0; i < *nsec; i++, j++) {
        DWORD virtAddress = j->VirtualAddress;
        DWORD size = j->Misc.VirtualSize;
        if (virtAddress <= *entryPoint && *entryPoint < virtAddress + size) {
            section = j;
        }
        if (j->PointerToRawData < firstFileAddress)
            firstFileAddress = j->PointerToRawData;
        if (j->VirtualAddress > lastVirtualAddress) {
            lastVirtualAddress = j->VirtualAddress;
            sizeOfLastSection = j->Misc.VirtualSize;
        }
    }
    if (section == NULL) {
        printf(SECTION_NOT_FOUND);
        return;
    }
    DWORD sizeRaw = section->SizeOfRawData;
    DWORD virtSize = section->Misc.VirtualSize;
    DWORD sectAlign = ntHeader->OptionalHeader.SectionAlignment;
    DWORD rawAlign = ntHeader->OptionalHeader.FileAlignment;
    ENTRY_POINT_CODE code = GetEntryPointCodeSmall(section->VirtualAddress + virtSize, *entryPoint);
    if (!CheckValidityOfEntryPointCode(&code)) {
        printf(CODE_NOT_GENERATED);
        return;
    }
    // strategy1
    if (sizeRaw >= virtSize + code.sizeOfCode) {
        *entryPoint = section->VirtualAddress + virtSize;
        section->Misc.VirtualSize += code.sizeOfCode;
        memcpy(buffer + section->PointerToRawData + virtSize, code.code, code.sizeOfCode);
        WriteNewFile(originalFilename, buffer, bufferSize);
        return;
    }
    //strategy2
    if (virtSize % sectAlign + code.sizeOfCode <= sectAlign) {
        unsigned int newbufSize = bufferSize + AlignAddress(code.sizeOfCode, rawAlign);
        *entryPoint = section->VirtualAddress + sizeRaw;
        FixSectionRawData(ntHeader, *nsec, section->PointerToRawData + section->SizeOfRawData, AlignAddress(code.sizeOfCode, rawAlign));
        section->SizeOfRawData += AlignAddress(code.sizeOfCode, rawAlign);
        char* newbuf = (char*)malloc(newbufSize);
        memcpy(newbuf, buffer, section->PointerToRawData + sizeRaw);
        memcpy(newbuf + section->PointerToRawData + sizeRaw, code.code, code.sizeOfCode);
        memset(newbuf + section->PointerToRawData + sizeRaw + code.sizeOfCode, 0, rawAlign - code.sizeOfCode);
        memcpy(newbuf + section->PointerToRawData + sizeRaw + AlignAddress(code.sizeOfCode, rawAlign), buffer + section->PointerToRawData + sizeRaw, bufferSize - (section->PointerToRawData + sizeRaw));
        WriteNewFile(originalFilename, newbuf, newbufSize);
        free(newbuf);
        return;
    }
    //strategy3
    if (firstFileAddress >= ((char*)j - buffer) + sizeof(IMAGE_SECTION_HEADER)) {
        memcpy(j->Name, ".altext\0", 8);
        j->VirtualAddress = (sizeOfLastSection % sectAlign == 0 ? sizeOfLastSection : AlignAddress(sizeOfLastSection, sectAlign)) + lastVirtualAddress;
        ENTRY_POINT_CODE code = GetEntryPointCodeSmall(j->VirtualAddress, *entryPoint);
        if (!CheckValidityOfEntryPointCode(&code)) {
            printf(CODE_NOT_GENERATED);
            return;
        }
        j->Misc.VirtualSize = code.sizeOfCode;
        j->SizeOfRawData = AlignAddress(code.sizeOfCode, rawAlign);
        j->PointerToRawData = bufferSize;
        j->PointerToRelocations = 0;
        j->PointerToLinenumbers = 0;
        j->NumberOfRelocations = 0;
        j->NumberOfLinenumbers = 0;
        j->Characteristics = section->Characteristics;
        (*nsec)++;
        *entryPoint = j->VirtualAddress;
        ntHeader->OptionalHeader.SizeOfHeaders += sizeof(section);
        ntHeader->OptionalHeader.SizeOfImage += AlignAddress(code.sizeOfCode, sectAlign);
        char* newbuf = (char*)malloc(bufferSize + j->SizeOfRawData);
        memcpy(newbuf, buffer, bufferSize);
        memcpy(newbuf + bufferSize, code.code, code.sizeOfCode);
        memset(newbuf + bufferSize + code.sizeOfCode, 0, j->SizeOfRawData - code.sizeOfCode);
        WriteNewFile(originalFilename, newbuf, bufferSize + j->SizeOfRawData);
        free(newbuf);
        return;
    }
    printf(NO_STRATEGY_FOUND);
}

ENTRY_POINT_CODE GetEntryPointCodeSmall( DWORD rvaToNewEntryPoint, DWORD rvaToOriginalEntryPoint )
{
  ENTRY_POINT_CODE code;
  char byteCode[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x8B, 0x44, 0x24, 0x04, 0x05, 0x77, 0x77, 0x77, 0x77, 0x89, 0x44, 0x24, 0x04, 0x58, 0xC3 };
  DWORD offsetToOriginalEntryPoint = rvaToOriginalEntryPoint - rvaToNewEntryPoint - SIZE_OF_CALL_INSTRUCTION;
  DWORD* positionOfOffsetToOriginalEntryPoint = GetPositionOfPattern( byteCode, sizeof( byteCode ), OFFSET_PATTERN );
  if( NULL != positionOfOffsetToOriginalEntryPoint )
  {
    *positionOfOffsetToOriginalEntryPoint = offsetToOriginalEntryPoint;
    code.sizeOfCode = sizeof( byteCode );
    code.code = ( char* ) malloc( code.sizeOfCode );
    memcpy( code.code, byteCode, code.sizeOfCode );
  }
  else
  {
    code.code = NULL;
    code.sizeOfCode = 0x00;
  }
  return code;
}

DWORD* GetPositionOfPattern( char* buffer, DWORD bufferSize, DWORD pattern )
{
  DWORD* foundPosition = NULL;
  char* position;
  char* lastPosition = buffer + bufferSize - sizeof( DWORD );

  for( position = buffer; position <= lastPosition; ++position )
  {
    if( *( ( DWORD* ) position ) == pattern )
    {
      foundPosition = ( DWORD* ) position;
      break;
    }
  }
  return foundPosition;
}
