#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include "common.h"
#include <xpwn/libxpwn.h>
#include <xpwn/nor_files.h>
#include <dmg/dmg.h>
#include <dmg/filevault.h>
#include <xpwn/ibootim.h>
#include <xpwn/plist.h>
#include <xpwn/outputstate.h>
#include <hfs/hfslib.h>
#include <dmg/dmglib.h>
#include <xpwn/pwnutil.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef WIN32
#include <windows.h>
#endif

#include <pref.h>

char endianness;

static char* tmpFile = NULL;

static AbstractFile* openRoot(void** buffer, size_t* rootSize) {
    static char tmpFileBuffer[512];
    
    if((*buffer) != NULL) {
        return createAbstractFileFromMemoryFile(buffer, rootSize);
    } else {
        if(tmpFile == NULL) {
#ifdef WIN32
            char tmpFilePath[512];
            GetTempPath(512, tmpFilePath);
            GetTempFileName(tmpFilePath, "root", 0, tmpFileBuffer);
            CloseHandle(CreateFile(tmpFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL));
#else
            strcpy(tmpFileBuffer, "/tmp/rootXXXXXX");
            close(mkstemp(tmpFileBuffer));
            FILE* tFile = fopen(tmpFileBuffer, "wb");
            fclose(tFile);
#endif
            tmpFile = tmpFileBuffer;
        }
        return createAbstractFileFromFile(fopen(tmpFile, "r+b"));
    }
}

void closeRoot(void* buffer) {
    if(buffer != NULL) {
        free(buffer);
    }
    
    if(tmpFile != NULL) {
        unlink(tmpFile);
    }
}

int main(int argc, char* argv[]) {
    init_libxpwn(&argc, argv);
    
    Dictionary* info;
    Dictionary* firmwarePatches;
    Dictionary* patchDict;
    ArrayValue* patchArray;
    
    void* buffer;
    
    StringValue* actionValue;
    StringValue* pathValue;
    
    StringValue* fileValue;
    
    StringValue* patchValue;
    char* patchPath;
    
    char* rootFSPathInIPSW;
    io_func* rootFS;
    Volume* rootVolume;
    size_t rootSize;
    size_t preferredRootSize = 0;
    size_t preferredRootSizeAdd = 0;
    size_t minimumRootSize = 0;
    
    char* ramdiskFSPathInIPSW;
    unsigned int ramdiskKey[32];
    unsigned int ramdiskIV[16];
    unsigned int* pRamdiskKey = NULL;
    unsigned int* pRamdiskIV = NULL;
    io_func* ramdiskFS;
    Volume* ramdiskVolume;
    size_t ramdiskGrow = 0;
    
    Dictionary* manifest = NULL;
    AbstractFile *manifestFile;
    char manifestDirty = FALSE;
    AbstractFile *otaFile = NULL;
    
    char* updateRamdiskFSPathInIPSW = NULL;
    
    int i;
    
    OutputState* outputState;
    
    char* bundlePath;
    char* bundleRoot = "FirmwareBundles/";
    
    int mergePaths;
    char* outputIPSW;
    
    void* imageBuffer;
    size_t imageSize;
    
    char updateBB = FALSE;
    char useMemory = FALSE;
    
    char needPref = FALSE;
    char usedaibutsu = FALSE;
    
    unsigned int key[32];
    unsigned int iv[16];
    
    unsigned int* pKey = NULL;
    unsigned int* pIV = NULL;
    
    if(argc < 3) {
        XLOG(0, "usage %s <input.ipsw> <target.ipsw> [-daibutsu] [-s <system partition size>] [-S <system partition add>] [-memory] [-bbupdate] [-ota BuildManifest] [-e \"<action to exclude>\"] [-ramdiskgrow <blocks>]\n", argv[0]);
        return 0;
    }
    
    outputIPSW = argv[2];
    
    int* toRemove = NULL;
    int numToRemove = 0;
    
    for(i = 3; i < argc; i++) {
        if(argv[i][0] != '-') {
            break;
        }
        
        if(strcmp(argv[i], "-memory") == 0) {
            useMemory = TRUE;
            continue;
        }
        
        if(strcmp(argv[i], "-daibutsu") == 0) {
            usedaibutsu = TRUE;
            continue;
        }
        
        if(strcmp(argv[i], "-s") == 0) {
            int size;
            sscanf(argv[i + 1], "%d", &size);
            preferredRootSize = size;
            i++;
            continue;
        }
        
        if(strcmp(argv[i], "-S") == 0) {
            int size;
            sscanf(argv[i + 1], "%d", &size);
            preferredRootSizeAdd = size;
            i++;
            continue;
        }
        
        if(strcmp(argv[i], "-ramdiskgrow") == 0) {
            int size;
            sscanf(argv[i + 1], "%d", &size);
            ramdiskGrow = size;
            i++;
            continue;
        }
        
        if(strcmp(argv[i], "-bbupdate") == 0) {
            updateBB = TRUE;
            continue;
        }

        if(strcmp(argv[i], "-e") == 0) {
            numToRemove++;
            toRemove = realloc(toRemove, numToRemove * sizeof(int));
            toRemove[numToRemove - 1] = i + 1;
            i++;
            continue;
        }
        
        if(strcmp(argv[i], "-ota") == 0) {
            otaFile = createAbstractFileFromFile(fopen(argv[i + 1], "rb"));
            if(!otaFile) {
                XLOG(0, "cannot open %s\n", argv[i + 1]);
                exit(1);
            }
            i++;
            continue;
        }
    }
    
    mergePaths = i;
    
    info = parseIPSW2(argv[1], bundleRoot, &bundlePath, &outputState, useMemory);
    if(info == NULL) {
        XLOG(0, "error: Could not load IPSW\n");
        exit(1);
    }
    
    firmwarePatches = (Dictionary*)getValueByKey(info, "FilesystemPatches");
    
    int j;
    for(j = 0; j < numToRemove; j++) {
        removeKey(firmwarePatches, argv[toRemove[j]]);
    }
    free(toRemove);
    
    manifestFile = getFileFromOutputState(&outputState, "BuildManifest.plist");
    if (manifestFile) {
        size_t fileLength = manifestFile->getLength(manifestFile);
        char *plist = malloc(fileLength);
        manifestFile->read(manifestFile, plist, fileLength);
        manifestFile->close(manifestFile);
        manifest = createRoot(plist);
        free(plist);
    }
    
    if (otaFile) {
        if (mergeIdentities(manifest, otaFile) != 0) {
            XLOG(1, "cannot merge OTA BuildIdentity\n");
            exit(1);
        }
        otaFile->close(otaFile);
        manifestDirty = TRUE;
    }
    
    if(getValueByKey(info, "needPref")){
        needPref = ((BoolValue*) getValueByKey(info, "needPref"))->value;
        XLOG(0, "[+] needPref ? %d...\n", needPref);
    }
    
    firmwarePatches = (Dictionary*)getValueByKey(info, "FirmwarePatches");
    patchDict = (Dictionary*) firmwarePatches->values;
    while(patchDict != NULL) {
        fileValue = (StringValue*) getValueByKey(patchDict, "File");
        
        StringValue* keyValue = (StringValue*) getValueByKey(patchDict, "Key");
        StringValue* ivValue = (StringValue*) getValueByKey(patchDict, "IV");
        pKey = NULL;
        pIV = NULL;
        
        if(keyValue) {
            sscanf(keyValue->value, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
                   &key[0], &key[1], &key[2], &key[3], &key[4], &key[5], &key[6], &key[7], &key[8],
                   &key[9], &key[10], &key[11], &key[12], &key[13], &key[14], &key[15],
                   &key[16], &key[17], &key[18], &key[19], &key[20], &key[21], &key[22], &key[23], &key[24],
                   &key[25], &key[26], &key[27], &key[28], &key[29], &key[30], &key[31]);
            
            pKey = key;
        }
        
        if(ivValue) {
            sscanf(ivValue->value, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
                   &iv[0], &iv[1], &iv[2], &iv[3], &iv[4], &iv[5], &iv[6], &iv[7], &iv[8],
                   &iv[9], &iv[10], &iv[11], &iv[12], &iv[13], &iv[14], &iv[15]);
            pIV = iv;
        }
        
        BoolValue *isPlainValue = (BoolValue *)getValueByKey(patchDict, "IsPlain");
        int isPlain = (isPlainValue && isPlainValue->value);
        
        if(strcmp(patchDict->dValue.key, "Restore Ramdisk") == 0) {
            ramdiskFSPathInIPSW = fileValue->value;
            if(pKey) {
                memcpy(ramdiskKey, key, sizeof(key));
                memcpy(ramdiskIV, iv, sizeof(iv));
                pRamdiskKey = ramdiskKey;
                pRamdiskIV = ramdiskIV;
            } else {
                pRamdiskKey = NULL;
                pRamdiskIV = NULL;
            }
        }
        
        if(strcmp(patchDict->dValue.key, "Update Ramdisk") == 0) {
            updateRamdiskFSPathInIPSW = fileValue->value;
        }
        
        patchValue = (StringValue*) getValueByKey(patchDict, "Patch2");
        if(patchValue) {
            // none?
        }
        
        patchValue = (StringValue*) getValueByKey(patchDict, "Patch");
        if(patchValue) {
            XLOG(0, "%s: ", patchDict->dValue.key); fflush(stdout);
            doPatch(patchValue, fileValue, bundlePath, &outputState, pKey, pIV, useMemory, isPlain);
        }
        
        BoolValue *decryptValue = (BoolValue *)getValueByKey(patchDict, "Decrypt");
        StringValue *decryptPathValue = (StringValue*) getValueByKey(patchDict, "DecryptPath");
        if ((decryptValue && decryptValue->value) || decryptPathValue) {
            XLOG(0, "%s: ", patchDict->dValue.key); fflush(stdout);
            doDecrypt(decryptPathValue, fileValue, bundlePath, &outputState, pKey, pIV, useMemory);
            if(strcmp(patchDict->dValue.key, "Restore Ramdisk") == 0) {
                pRamdiskKey = NULL;
                pRamdiskIV = NULL;
            }
            if (decryptPathValue  && manifest) {
                ArrayValue *buildIdentities = (ArrayValue *)getValueByKey(manifest, "BuildIdentities");
                if (buildIdentities) {
                    for (i = 0; i < buildIdentities->size; i++) {
                        StringValue *path;
                        Dictionary *dict = (Dictionary *)buildIdentities->values[i];
                        if (!dict) continue;
                        dict = (Dictionary *)getValueByKey(dict, "Manifest");
                        if (!dict) continue;
                        dict = (Dictionary *)getValueByKey(dict, patchDict->dValue.key);
                        if (!dict) continue;
                        dict = (Dictionary *)getValueByKey(dict, "Info");
                        if (!dict) continue;
                        path = (StringValue *)getValueByKey(dict, "Path");
                        if (!path) continue;
                        free(path->value);
                        path->value = strdup(decryptPathValue->value);
                        manifestDirty = TRUE;
                    }
                }
            }
        }
        
        patchDict = (Dictionary*) patchDict->dValue.next;
    }
    
    if (manifestDirty && manifest) {
        manifestFile = getFileFromOutputStateForReplace(&outputState, "BuildManifest.plist");
        if (manifestFile) {
            char *plist = getXmlFromRoot(manifest);
            manifestFile->write(manifestFile, plist, strlen(plist));
            manifestFile->close(manifestFile);
            free(plist);
        }
        releaseDictionary(manifest);
    }
    
    fileValue = (StringValue*) getValueByKey(info, "RootFilesystem");
    rootFSPathInIPSW = fileValue->value;
    
    size_t defaultRootSize = ((IntegerValue*) getValueByKey(info, "RootFilesystemSize"))->value;
    for(j = mergePaths; j < argc; j++) {
        AbstractFile* tarFile = createAbstractFileFromFile(fopen(argv[j], "rb"));
        if(tarFile) {
            defaultRootSize += (tarFile->getLength(tarFile) + 1024 * 1024 - 1) / (1024 * 1024); // poor estimate
            tarFile->close(tarFile);
        }
    }
    
    // ramdisk utils
    size_t exploitSize;
    size_t tarPackageSize=0;
    size_t rebootBinSize=0;
    const char *tarFilePath;
    const char *exploitPath;
    const char *rebootBinPath;
    
    if(usedaibutsu){
        AbstractFile* tarFileFile;
        AbstractFile* exploitFile;
        AbstractFile* rebootBinFile;
        StringValue* tarFileValue;
        StringValue* exploitValue;
        StringValue* rebootBinValue;
        
        tarFileValue = (StringValue*) getValueByKey(info, "RamdiskPackage");
        if(tarFileValue) {
            tarFilePath = tarFileValue->value;
            tarFileFile = createAbstractFileFromFile(fopen(tarFilePath, "rb"));
            if(tarFileFile) {
                tarPackageSize = tarFileFile->getLength(tarFileFile);
                tarFileFile->close(tarFileFile);
                XLOG(0, "[*] Found: RamdiskPackage\n");
            }
        }
        
        rebootBinValue = (StringValue*) getValueByKey(info, "RamdiskReboot");
        if(rebootBinValue) {
            rebootBinPath = rebootBinValue->value;
            rebootBinFile = createAbstractFileFromFile(fopen(rebootBinPath, "rb"));
            if(rebootBinFile) {
                rebootBinSize = rebootBinFile->getLength(rebootBinFile);
                rebootBinFile->close(rebootBinFile);
                XLOG(0, "[*] Found: Hooker\n");
            }
        }
        
    }
    
    int hasCydia;
    int hasUntether;
    const char *untetherPath;
    const char *cydiaPath;
    AbstractFile* cydiaFile;
    AbstractFile* untetherFile;
    StringValue* cydiaValue;
    StringValue* untetherValue;
    StringValue* hwmodelValue;
    
    cydiaValue = (StringValue*) getValueByKey(info, "PackagePath");
    if(cydiaValue) {
        cydiaPath = cydiaValue->value;
        cydiaFile = createAbstractFileFromFile(fopen(cydiaPath, "rb"));
        if(cydiaFile) {
            hasCydia = 1;
            defaultRootSize += (cydiaFile->getLength(cydiaFile) + 1024 * 1024 - 1) / (1024 * 1024);
            cydiaFile->close(cydiaFile);
            XLOG(0, "[*] Found: Cydia\n");
        }
    }
    
    untetherValue = (StringValue*) getValueByKey(info, "UntetherPath");
    if(untetherValue) {
        untetherPath = untetherValue->value;
        
        untetherFile = createAbstractFileFromFile(fopen(untetherPath, "rb"));
        if(untetherFile) {
            hasUntether = 1;
            defaultRootSize += (untetherFile->getLength(untetherFile) + 1024 * 1024 - 1) / (1024 * 1024);
            untetherFile->close(untetherFile);
            XLOG(0, "[*] Found: Untether\n");
        }
    }
    
    minimumRootSize = defaultRootSize * 1024 * 1024;
    minimumRootSize -= minimumRootSize % 512;
    
    if(preferredRootSize == 0) {
        preferredRootSize = defaultRootSize + preferredRootSizeAdd;
    }
    
    rootSize =  preferredRootSize * 1024 * 1024;
    rootSize -= rootSize % 512;
    
    if(useMemory) {
        buffer = calloc(1, rootSize);
    } else {
        buffer = NULL;
    }
    
    if(buffer == NULL) {
        XLOG(2, "using filesystem backed temporary storage\n");
    }
    
    extractDmg(
               createAbstractFileFromFileVault(getFileFromOutputState(&outputState, rootFSPathInIPSW), ((StringValue*)getValueByKey(info, "RootFilesystemKey"))->value),
               openRoot((void**)&buffer, &rootSize), -1);
    
    rootFS = IOFuncFromAbstractFile(openRoot((void**)&buffer, &rootSize));
    rootVolume = openVolume(rootFS);
    XLOG(0, "Growing root to minimum: %ld\n", (long) defaultRootSize); fflush(stdout);
    grow_hfs(rootVolume, minimumRootSize);
    if(rootSize > minimumRootSize) {
        XLOG(0, "Growing root: %ld\n", (long) preferredRootSize); fflush(stdout);
        grow_hfs(rootVolume, rootSize);
    }
    
    firmwarePatches = (Dictionary*)getValueByKey(info, "FilesystemPatches");
    patchArray = (ArrayValue*) firmwarePatches->values;
    while(patchArray != NULL) {
        for(i = 0; i < patchArray->size; i++) {
            patchDict = (Dictionary*) patchArray->values[i];
            fileValue = (StringValue*) getValueByKey(patchDict, "File");
            
            actionValue = (StringValue*) getValueByKey(patchDict, "Action");
            if(strcmp(actionValue->value, "ReplaceKernel") == 0) {
                pathValue = (StringValue*) getValueByKey(patchDict, "Path");
                XLOG(0, "replacing kernel... %s -> %s\n", fileValue->value, pathValue->value); fflush(stdout);
                add_hfs(rootVolume, getFileFromOutputState(&outputState, fileValue->value), pathValue->value);
            } if(strcmp(actionValue->value, "Patch") == 0) {
                patchValue = (StringValue*) getValueByKey(patchDict, "Patch");
                patchPath = (char*) malloc(sizeof(char) * (strlen(bundlePath) + strlen(patchValue->value) + 2));
                strcpy(patchPath, bundlePath);
                strcat(patchPath, "/");
                strcat(patchPath, patchValue->value);
                
                XLOG(0, "patching %s (%s)... ", fileValue->value, patchPath);
                doPatchInPlace(rootVolume, fileValue->value, patchPath);
                free(patchPath);
            }
        }
        
        patchArray = (ArrayValue*) patchArray->dValue.next;
    }
    
    for(; mergePaths < argc; mergePaths++) {
        XLOG(0, "merging %s\n", argv[mergePaths]);
        AbstractFile* tarFile = createAbstractFileFromFile(fopen(argv[mergePaths], "rb"));
        if(tarFile == NULL) {
            XLOG(1, "cannot find %s, make sure your slashes are in the right direction\n", argv[mergePaths]);
            releaseOutput(&outputState);
            closeRoot(buffer);
            exit(0);
        }
        if (tarFile->getLength(tarFile)) hfs_untar(rootVolume, tarFile);
        tarFile->close(tarFile);
    }
    
    if(hasCydia){
        XLOG(0, "[*] Installing Cydia package\n");
        AbstractFile* cydiaTarFile;
        
        XLOG(0, "merging %s\n", cydiaPath);
        cydiaTarFile = createAbstractFileFromFile(fopen(cydiaPath, "rb"));
        if(cydiaTarFile == NULL) {
            XLOG(1, "cannot find %s, make sure your slashes are in the right direction\n", cydiaPath);
            releaseOutput(&outputState);
            closeRoot(buffer);
            exit(0);
        }
        if (cydiaTarFile->getLength(cydiaTarFile)) hfs_untar(rootVolume, cydiaTarFile);
        cydiaTarFile->close(cydiaTarFile);
    }
    
    const char *movingAllFiles[18];
    if(usedaibutsu) {
        XLOG(0, "[*] Moving LaunchDaemons for daibutsu untether\n");
        movingAllFiles[0] = "/usr/libexec/CrashHousekeeping";
        movingAllFiles[1] = "/usr/libexec/CrashHousekeeping_o";
        XLOG(0, "[+] Moving %s -> %s\n", movingAllFiles[0], movingAllFiles[1]);
        move(movingAllFiles[0], movingAllFiles[1], rootVolume);
        
        movingAllFiles[2] = "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist";
        movingAllFiles[3] = "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist";
        XLOG(0, "[+] Moving %s -> %s\n", movingAllFiles[2], movingAllFiles[3]);
        move(movingAllFiles[2], movingAllFiles[3], rootVolume);
        
        // Delete or put in /tmp
        // !!!! It will no longer be possible to incorporate LaunchDeamons beforehand !!!!
        movingAllFiles[4] = "/Library/LaunchDaemons";
        movingAllFiles[5] = "/tmp/.LaunchDaemons";
        XLOG(0, "[+] Moving dir: %s -> %s\n", movingAllFiles[4], movingAllFiles[5]);
        move(movingAllFiles[4], movingAllFiles[5], rootVolume);
    }
    
    if(hasUntether){
        XLOG(0, "[*] Installing untether package\n");
        AbstractFile* untetherTarFile;
        
        XLOG(0, "merging %s\n", untetherPath);
        untetherTarFile = createAbstractFileFromFile(fopen(untetherPath, "rb"));
        if(untetherTarFile == NULL) {
            XLOG(1, "cannot find %s, make sure your slashes are in the right direction\n", untetherPath);
            releaseOutput(&outputState);
            closeRoot(buffer);
            exit(0);
        }
        if (untetherTarFile->getLength(untetherTarFile)) hfs_untar(rootVolume, untetherTarFile);
        untetherTarFile->close(untetherTarFile);
    }
    
    if(usedaibutsu) {
        // by LukeZGD
        XLOG(0, "[*] Moving LaunchDaemons for daibutsu untether\n");
        const char *movingDir1 = "/System/Library/LaunchDaemons";
        const char *movingDir2 = "/Library/LaunchDaemons";
        const char *movingDir3 = "/System/Library/NanoLaunchDaemons";
        const char *movingDir4 = "/Library/NanoLaunchDaemons";
        movingAllFiles[6] = "/Library/LaunchDaemons/bootps.plist";
        movingAllFiles[7] = "/System/Library/LaunchDaemons/bootps.plist";
        movingAllFiles[8] = "/Library/LaunchDaemons/com.apple.CrashHousekeeping.plist";
        movingAllFiles[9] = "/System/Library/LaunchDaemons/com.apple.CrashHousekeeping.plist";
        movingAllFiles[10] = "/Library/LaunchDaemons/com.apple.MobileFileIntegrity.plist";
        movingAllFiles[11] = "/System/Library/LaunchDaemons/com.apple.MobileFileIntegrity.plist";
        movingAllFiles[12] = "/Library/LaunchDaemons/com.apple.mDNSResponder.plist";
        movingAllFiles[13] = "/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist_";
        movingAllFiles[14] = "/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist";
        movingAllFiles[15] = "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist_";
        movingAllFiles[16] = "/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist";
        movingAllFiles[17] = "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist_";
        
        XLOG(0, "[+] Moving dir: %s -> %s\n", movingDir1, movingDir2);
        move(movingDir1, movingDir2, rootVolume);
        XLOG(0, "[+] Moving dir: %s -> %s\n", movingDir3, movingDir4);
        move(movingDir3, movingDir4, rootVolume);
        
        XLOG(0, "[+] Create new folder /System/Library/LaunchDaemons\n");
        newFolder(movingDir1, rootVolume);
        chmodFile(movingDir1, 0755, rootVolume);
        
        XLOG(0, "[*] Proceeding to moving LaunchDaemons and CrashHousekeeping\n");
        for (int i = 6; i < 17; i++) {
            if (i % 2 == 0) {
                XLOG(0, "[+] Moving %s -> %s\n", movingAllFiles[i], movingAllFiles[i+1]);
                move(movingAllFiles[i], movingAllFiles[i+1], rootVolume);
            }
        }
        
        hwmodelValue = (StringValue*) getValueByKey(info, "hwmodel");
        if(hwmodelValue) {
            char str1[255];
            char str2[255];
            memset(&str1, 0x0, 255);
            memset(&str2, 0x0, 255);
            
            sprintf(str1, "/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", hwmodelValue->value);
            sprintf(str2, "/System/Library/LaunchDaemons/com.apple.jetsamproperties.%s.plist", hwmodelValue->value);
            
            XLOG(0, "[+] Moving %s -> %s\n", str1, str2);
            move(str1, str2, rootVolume);
            
        }
        
        if(hasUntether) {
            // ??
            chmodFile("/usr/libexec/CrashHousekeeping", 0755, rootVolume);
        }
    }
    
    if(needPref){
        XLOG(0, "[*] Executing needPref...\n");
        const char *prefPath = "/private/var/mobile/Library/Preferences/com.apple.springboard.plist";
        size_t pref_sz = _prefDataLen;
        void *prefBuf = malloc(pref_sz);
        memcpy(prefBuf, _prefData, pref_sz);
        AbstractFile* prefFile = createAbstractFileFromMemoryFile((void**)&prefBuf, &pref_sz);
        add_hfs(rootVolume, prefFile, prefPath);
        chmodFile(prefPath, 0600, rootVolume); // rw-/---/---
        chownFile(prefPath, 501, 501, rootVolume); // mobile:mobile
    }
    
    if(pRamdiskKey) {
        ramdiskFS = IOFuncFromAbstractFile(openAbstractFile2(getFileFromOutputStateForOverwrite(&outputState, ramdiskFSPathInIPSW), pRamdiskKey, pRamdiskIV));
    } else {
        XLOG(0, "unencrypted ramdisk\n");
        ramdiskFS = IOFuncFromAbstractFile(openAbstractFile(getFileFromOutputStateForOverwrite(&outputState, ramdiskFSPathInIPSW)));
    }
    ramdiskVolume = openVolume(ramdiskFS);
    
    if(usedaibutsu){
        XLOG(0, "[*] Growing ramdisk\n");
        size_t allSize;
        allSize = 1048576 + tarPackageSize + rebootBinSize;
        ramdiskGrow = ramdiskGrow + allSize/(ramdiskVolume->volumeHeader->blockSize) + 64;
    }
    
    XLOG(0, "growing ramdisk: %d -> %d\n", ramdiskVolume->volumeHeader->totalBlocks * ramdiskVolume->volumeHeader->blockSize, (ramdiskVolume->volumeHeader->totalBlocks + ramdiskGrow) * ramdiskVolume->volumeHeader->blockSize);
    grow_hfs(ramdiskVolume, (ramdiskVolume->volumeHeader->totalBlocks + ramdiskGrow) * ramdiskVolume->volumeHeader->blockSize);
    
    firmwarePatches = (Dictionary*)getValueByKey(info, "RamdiskPatches");
    if(firmwarePatches != NULL) {
        patchDict = (Dictionary*) firmwarePatches->values;
        while(patchDict != NULL) {
            fileValue = (StringValue*) getValueByKey(patchDict, "File");
            
            patchValue = (StringValue*) getValueByKey(patchDict, "Patch");
            if(patchValue) {
                patchPath = (char*) malloc(sizeof(char) * (strlen(bundlePath) + strlen(patchValue->value) + 2));
                strcpy(patchPath, bundlePath);
                strcat(patchPath, "/");
                strcat(patchPath, patchValue->value);
                
                XLOG(0, "patching %s (%s)... ", fileValue->value, patchPath);
                doPatchInPlace(ramdiskVolume, fileValue->value, patchPath);
                free(patchPath);
            }
            
            patchDict = (Dictionary*) patchDict->dValue.next;
        }
    }
    
    StringValue* optionsValue = (StringValue*) getValueByKey(info, "RamdiskOptionsPath");
    const char *optionsPlist = optionsValue ? optionsValue->value : "/usr/local/share/restore/options.plist";
    createRestoreOptions(ramdiskVolume, optionsPlist, preferredRootSize, updateBB);
    
    if(usedaibutsu){
        AbstractFile* tarFileFile;
        AbstractFile* rebootBinFile;
        
        // injecting hook via /sbin/reboot
        const char *rebootPath = "/sbin/reboot";
        const char *reRebootPath = "/sbin/reboot_";
        move(rebootPath, reRebootPath, ramdiskVolume);
        XLOG(0, "[+] ramdiskVolume ... Moved: %s -> %s\n", rebootPath, reRebootPath);
        
        XLOG(0, "injecting reboot hooker ...\n");
        rebootBinFile = createAbstractFileFromFile(fopen(rebootBinPath, "rb"));
        if(rebootBinFile == NULL) {
            XLOG(1, "cannot find %s, make sure your slashes are in the right direction\n", rebootBinPath);
            releaseOutput(&outputState);
            closeRoot(buffer);
            exit(0);
        }
        if (rebootBinFile->getLength(rebootBinFile)) add_hfs(ramdiskVolume, rebootBinFile, rebootPath);
        XLOG(0, "[+] ramdiskVolume ... Added: %s\n", rebootPath);
        
        XLOG(0, "merging %s\n", tarFilePath);
        tarFileFile = createAbstractFileFromFile(fopen(tarFilePath, "rb"));
        if(tarFileFile == NULL) {
            XLOG(1, "cannot find %s, make sure your slashes are in the right direction\n", tarFilePath);
            releaseOutput(&outputState);
            closeRoot(buffer);
            exit(0);
        }
        if (tarFileFile->getLength(tarFileFile)) hfs_untar(ramdiskVolume, tarFileFile);
        tarFileFile->close(tarFileFile);
        XLOG(0, "[+] ramdiskVolume ... Installed package\n");
        
        XLOG(0, "[*] ramdiskVolume ... chmod: %s -> -rwx/-r-x/-r-x\n", rebootPath);
        chmodFile(rebootPath, 0755, ramdiskVolume);
        XLOG(0, "[*] ramdiskVolume ... chown: %s -> root:wheel\n", rebootPath);
        chownFile(rebootPath, 0, 0, ramdiskVolume);
        
    }
    
    closeVolume(ramdiskVolume);
    CLOSE(ramdiskFS);
    
    if(updateRamdiskFSPathInIPSW)
        removeFileFromOutputState(&outputState, updateRamdiskFSPathInIPSW, TRUE);
    
    StringValue *removeBB = (StringValue*) getValueByKey(info, "DeleteBaseband");
    if (removeBB && removeBB->value[0])
        removeFileFromOutputState(&outputState, removeBB->value, FALSE);
    
    closeVolume(rootVolume);
    CLOSE(rootFS);
    
    buildDmg(openRoot((void**)&buffer, &rootSize), getFileFromOutputStateForReplace(&outputState, rootFSPathInIPSW), 2048);
    
    closeRoot(buffer);
    
    writeOutput(&outputState, outputIPSW);
    
    releaseDictionary(info);
    
    free(bundlePath);
    
    return 0;
}
