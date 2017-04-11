#include "pe_parser.h"

#define DEBUG_OUTPUT 0

int GetInfoFromNTHeader(void* opt_header, ULONGLONG* image_base, DWORD** entry_point)
{
    IMAGE_OPTIONAL_HEADER32* opth32 = (IMAGE_OPTIONAL_HEADER32*)opt_header;
    if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == opth32->Magic || IMAGE_ROM_OPTIONAL_HDR_MAGIC == opth32->Magic) {
#if DEBUG_OUTPUT
        printf("32 bit\n");
#endif
        *image_base = opth32->ImageBase;
        *entry_point = &opth32->AddressOfEntryPoint;
        return 1;
    }
    IMAGE_OPTIONAL_HEADER64* opth64 = (IMAGE_OPTIONAL_HEADER64*)opt_header;
    if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == opth64->Magic) {
#if DEBUG_OUTPUT
        printf("64 bit\n");
#endif
        *image_base = opth64->ImageBase;
        *entry_point = &opth64->AddressOfEntryPoint;
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

void ChangeEntryPoint( char* buffer, DWORD bufferSize, char* originalFilename )
{
  // TODO: Необходимо изменить точку входа в программу (AddressOfEntryPoint).
  // Поддерживаются только 32-разрядные файлы (или можете написать свой код точки входа для 64-разрядных)
  // Варианты размещения новой точки входа - в каверне имеющихся секций, в расширеннной области 
  // секций или в новой секции. Подробнее:
  //    Каверна секции - это разница между SizeOfRawData и VirtualSize. Так как секция хранится
  //      на диске с выравниванием FileAlignment (обычно по размеру сектора, 0x200 байт), а в VirtualSize 
  //      указан точный размер секции в памяти, то получается, что на диске хранится лишних
  //      ( SizeOfRawData - VirtualSize ) байт. Их можно использовать.
  //    Расширенная область секции - так как в памяти секции выравниваются по значению SectionAlignment 
  //      (обычно по размеру страницы, 0x1000), то следующая секция начинается с нового SectionAlignment.
  //      Например, если SectionAlignment равен 0x1000, а секция занимает всего 0x680 байт, то в памяти будет
  //      находится еще 0x980 нулевых байт. То есть секцию можно расширить (как в памяти, так и на диске)
  //      и записать в нее данные.
  //    Новая секция - вы можете создать новую секцию (если места для еще одного заголовка секции достаточно)
  //      Легче всего добавить последнюю секцию. Необходимо помнить о всех сопутствующих добавлению новой секции 
  //      изменениях: заголовок секции, атрибуты секции, поле NumberOfSections в IMAGE_FILE_HEADER и т.д.
  // После выбора места для размещения необходимо получить код для записи в файл. Для этого можно 
  // воспользоваться функцией GetEntryPointCodeSmall. Она возвращает структуру ENTRY_POINT_CODE, ее описание
  // находится в заголовочном файле. Необходимо проверить, что код был успешно сгенерирован. После чего
  // записать новую точку входа в выбранное место. После этого вызвать функцию WriteFileFromBuffer. Имя файла 
  // можно сформировать по имени исходного файла (originalFilename). 
  // 
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
    WORD nsec = fileHeader->NumberOfSections;
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);
    if ((unsigned int)section - (unsigned int)buffer + sizeof(IMAGE_SECTION_HEADER)*nsec > bufferSize) {
        printf(WRONG_NUMBER_OF_SECTIONS);
        return;
    }
    WORD i;
    for (i = 0; i < nsec; i++, section++) {
        DWORD virtAddress = section->VirtualAddress;
        DWORD size = section->Misc.VirtualSize;
        if (virtAddress <= *entryPoint && *entryPoint < virtAddress + size) {
            break;
        }
    }
    if (i == nsec) {
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
        unsigned int newbufSize = bufferSize + (code.sizeOfCode / rawAlign + 1) * rawAlign;
        *entryPoint = section->VirtualAddress + sizeRaw;
        FixSectionRawData(ntHeader, nsec, section->PointerToRawData + section->SizeOfRawData, (code.sizeOfCode / rawAlign + 1) * rawAlign);
        section->SizeOfRawData += (code.sizeOfCode / rawAlign + 1) * rawAlign;
        char* newbuf = (char*)malloc(newbufSize);
        memcpy(newbuf, buffer, section->PointerToRawData + sizeRaw);
        memcpy(newbuf + section->PointerToRawData + sizeRaw, code.code, code.sizeOfCode);
        memset(newbuf + section->PointerToRawData + sizeRaw + code.sizeOfCode, 0, rawAlign - code.sizeOfCode);
        memcpy(newbuf + section->PointerToRawData + sizeRaw + (code.sizeOfCode / rawAlign + 1) * rawAlign, buffer + section->PointerToRawData + sizeRaw, bufferSize - (section->PointerToRawData + sizeRaw));
        WriteNewFile(originalFilename, newbuf, newbufSize);
        free(newbuf);
        return;
    }
    //strategy3
    printf("Not implemented\n");
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