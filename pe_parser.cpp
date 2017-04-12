#include "pe_parser.h"
#include <time.h>

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

void InsertEntryPointToCavern(char* buffer, DWORD bufferSize, char* originalFilename, INJECTOR_INFO* info)
{
    DWORD offset = rand() % info->size;
    ENTRY_POINT_CODE code = GetEntryPointCodeSmall(info->execSection->VirtualAddress + info->execSection->Misc.VirtualSize + offset, *(info->entryPoint));
    *(info->entryPoint) = info->execSection->VirtualAddress + info->execSection->Misc.VirtualSize + offset;
    memcpy(buffer + info->execSection->PointerToRawData + info->execSection->Misc.VirtualSize + offset, code.code, code.sizeOfCode);
    info->execSection->Misc.VirtualSize += code.sizeOfCode + offset;
    WriteNewFile(originalFilename, buffer, bufferSize);
    free(code.code);
}

void ExpandSection(char* buffer, DWORD bufferSize, char* originalFilename, INJECTOR_INFO* info)
{
    DWORD sizeRaw = info->execSection->SizeOfRawData;
    DWORD rawAlign = info->ntHeader->OptionalHeader.FileAlignment;
    IMAGE_FILE_HEADER* fileHeader = &info->ntHeader->FileHeader;
    WORD* nsec = &fileHeader->NumberOfSections;
    DWORD offset = rand() % info->size;
    ENTRY_POINT_CODE code = GetEntryPointCodeSmall(info->execSection->VirtualAddress + sizeRaw + offset, *(info->entryPoint));
    if (!CheckValidityOfEntryPointCode(&code)) {
        printf(CODE_NOT_GENERATED);
        return;
    }
    unsigned int newbufSize = bufferSize + AlignAddress(offset + code.sizeOfCode, rawAlign);
    *(info->entryPoint) = info->execSection->VirtualAddress + sizeRaw + offset;
    FixSectionRawData(info->ntHeader, *nsec, info->execSection->PointerToRawData + info->execSection->SizeOfRawData, AlignAddress(offset + code.sizeOfCode, rawAlign));
    info->execSection->SizeOfRawData += AlignAddress(offset + code.sizeOfCode, rawAlign);
    char* newbuf = (char*)malloc(newbufSize);
    memcpy(newbuf, buffer, info->execSection->PointerToRawData + sizeRaw);
    memset(newbuf + info->execSection->PointerToRawData + sizeRaw, 0, offset);
    memcpy(newbuf + info->execSection->PointerToRawData + sizeRaw + offset, code.code, code.sizeOfCode);
    memset(newbuf + info->execSection->PointerToRawData + sizeRaw + offset + code.sizeOfCode, 0, AlignAddress(offset, rawAlign) - code.sizeOfCode - offset);
    memcpy(newbuf + info->execSection->PointerToRawData + sizeRaw + AlignAddress(offset, rawAlign), buffer + info->execSection->PointerToRawData + sizeRaw, bufferSize - (info->execSection->PointerToRawData + sizeRaw));
    WriteNewFile(originalFilename, newbuf, newbufSize);
    free(newbuf);
    free(code.code);
}

void CreateNewSection(char* buffer, DWORD bufferSize, char* originalFilename, INJECTOR_INFO* info)
{
    DWORD sectAlign = info->ntHeader->OptionalHeader.SectionAlignment;
    DWORD rawAlign = info->ntHeader->OptionalHeader.FileAlignment;
    IMAGE_FILE_HEADER* fileHeader = &info->ntHeader->FileHeader;
    WORD* nsec = &fileHeader->NumberOfSections;
    memcpy(info->addSection->Name, ".altext\0", 8);
    info->addSection->VirtualAddress = (info->sizeOfLastSection % sectAlign == 0 ? info->sizeOfLastSection : AlignAddress(info->sizeOfLastSection, sectAlign)) + info->lastVirtualAddress;
    ENTRY_POINT_CODE code = GetEntryPointCodeSmall(info->addSection->VirtualAddress, *info->entryPoint);
    if (!CheckValidityOfEntryPointCode(&code)) {
        printf(CODE_NOT_GENERATED);
        return;
    }
    info->addSection->Misc.VirtualSize = code.sizeOfCode;
    info->addSection->SizeOfRawData = AlignAddress(code.sizeOfCode, rawAlign);
    info->addSection->PointerToRawData = bufferSize;
    info->addSection->PointerToRelocations = 0;
    info->addSection->PointerToLinenumbers = 0;
    info->addSection->NumberOfRelocations = 0;
    info->addSection->NumberOfLinenumbers = 0;
    info->addSection->Characteristics = info->execSection->Characteristics;
    (*nsec)++;
    *info->entryPoint = info->addSection->VirtualAddress;
    info->ntHeader->OptionalHeader.SizeOfHeaders += sizeof(*info->execSection);
    info->ntHeader->OptionalHeader.SizeOfImage += AlignAddress(code.sizeOfCode, sectAlign);
    info->ntHeader->OptionalHeader.SizeOfInitializedData += AlignAddress(code.sizeOfCode, rawAlign);
    info->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    info->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    char* newbuf = (char*)malloc(bufferSize + info->addSection->SizeOfRawData);
    memcpy(newbuf, buffer, bufferSize);
    memcpy(newbuf + bufferSize, code.code, code.sizeOfCode);
    memset(newbuf + bufferSize + code.sizeOfCode, 0, info->addSection->SizeOfRawData - code.sizeOfCode);
    WriteNewFile(originalFilename, newbuf, bufferSize + info->addSection->SizeOfRawData);
    free(newbuf);
    free(code.code);
}

void ChangeEntryPoint( char* buffer, DWORD bufferSize, char* originalFilename )
{
    srand(time(NULL));
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
    IMAGE_SECTION_HEADER* sectIter = IMAGE_FIRST_SECTION(ntHeader);
    IMAGE_SECTION_HEADER* execSection = NULL;
    DWORD firstFileAddress = MAXDWORD;
    DWORD lastVirtualAddress = 0;
    DWORD sizeOfLastSection = 0;
    for (WORD i = 0; i < *nsec; i++, sectIter++) {
        DWORD virtAddress = sectIter->VirtualAddress;
        DWORD size = sectIter->Misc.VirtualSize;
        if (virtAddress <= *entryPoint && *entryPoint < virtAddress + size) {
            execSection = sectIter;
        }
        if (sectIter->PointerToRawData < firstFileAddress)
            firstFileAddress = sectIter->PointerToRawData;
        if (sectIter->VirtualAddress > lastVirtualAddress) {
            lastVirtualAddress = sectIter->VirtualAddress;
            sizeOfLastSection = sectIter->Misc.VirtualSize;
        }
    }
    if (execSection == NULL) {
        printf(SECTION_NOT_FOUND);
        return;
    }
    DWORD sizeRaw = execSection->SizeOfRawData;
    DWORD virtSize = execSection->Misc.VirtualSize;
    DWORD sectAlign = ntHeader->OptionalHeader.SectionAlignment;
    ENTRY_POINT_CODE code = GetEntryPointCodeSmall(execSection->VirtualAddress + virtSize, *entryPoint);
    if (!CheckValidityOfEntryPointCode(&code)) {
        printf(CODE_NOT_GENERATED);
        return;
    }
    DWORD codeSize = code.sizeOfCode;
    free(code.code);
    INJECTOR_INFO info;
    info.ntHeader = ntHeader;
    info.execSection = execSection;
    info.entryPoint = entryPoint;
    info.lastVirtualAddress = lastVirtualAddress;
    info.sizeOfLastSection = sizeOfLastSection;
    info.addSection = sectIter;
    void(*strategies[])(char* buffer, DWORD bufferSize, char* originalFilename, INJECTOR_INFO* info) = { InsertEntryPointToCavern, ExpandSection, CreateNewSection };
    bool application[] = { sizeRaw >= virtSize + codeSize, virtSize % sectAlign + code.sizeOfCode <= sectAlign, firstFileAddress >= ((char*)sectIter - buffer) + sizeof(IMAGE_SECTION_HEADER) };
    DWORD sizes[] = { sizeRaw - virtSize - codeSize , sectAlign - virtSize % sectAlign - codeSize , 0 };
    const char* names[] = { "INSERT", "EXPAND", "NEW SECTION" };
    int total = 0;
    for (int i = 0; i < sizeof(application); i++)
        total += application[i] ? 1 : 0;
    if (total == 0) {
        printf(NO_STRATEGY_FOUND);
        return;
    }
    int target = rand() % total;
    int cur = 0;
    for (int i = 0; i < sizeof(application)/sizeof(*application); i++) {
        if (application[i]) {
            if (cur == target) {
                info.size = sizes[i];
                printf("Applied strategy %s\n", names[i]);
                strategies[i](buffer, bufferSize, originalFilename, &info);
                return;
            }
            else {
                cur++;
            }
        }
    }
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
