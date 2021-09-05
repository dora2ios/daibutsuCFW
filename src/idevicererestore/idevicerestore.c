/*
 * idevicerestore.c
 * Restore device firmware and filesystem
 *
 * Copyright (c) 2010-2015 Martin Szulecki. All Rights Reserved.
 * Copyright (c) 2012-2015 Nikias Bassen. All Rights Reserved.
 * Copyright (c) 2010 Joshua Hill. All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <plist/plist.h>
#include <zlib.h>
#include <libgen.h>

#include <curl/curl.h>

#include "dfu.h"
#include "tss.h"
#include "img3.h"
#include "img4.h"
#include "ipsw.h"
#include "common.h"
#include "normal.h"
#include "restore.h"
#include "download.h"
#include "recovery.h"
#include "idevicerestore.h"
#include "partial.h"

#include "locking.h"

#include "ubid_list.h"

#define VERSION_XML "version.xml"

#include <openssl/sha.h>

#ifndef IDEVICERESTORE_NOMAIN
static struct option longopts[] = {
    { "debug",              no_argument,    NULL, 'd' },
    { "ota-bbfw",           no_argument,    NULL, 'o' },
    { "old-ota-bbfw",       no_argument,    NULL, 'a' },
    { "force-latest-bbfw",  no_argument,    NULL, 'f' },
    { "help",               no_argument,    NULL, 'h' },
    { "rerestore",          no_argument,    NULL, 'r' },
    { "ota-blob",           no_argument,    NULL, 'b' },
    //{ "baseband", required_argument,    NULL,    'b' },
    //{ "manifest", required_argument,    NULL,    'm' },
    { NULL, 0, NULL, 0 }
};

void usage(int argc, char* argv[]) {
    char* name = strrchr(argv[0], '/');
    printf("Usage: %s [OPTIONS] IPSW\n\n", (name ? name + 1 : argv[0]));
    printf("  -r, --rerestore\t\ttake advantage of the 9.x 32 bit re-restore bug\n");
    //printf("  -b, --baseband\tspecify baseband to use instead of the latest OTA baseband\n");
    //printf("  -m, --manifest\tspecify manifest to use with the specified baseband\n");
    printf("  -b, --ota-blob\t\tuse 8.4.1 OTA SHSH blob for 32 bit devices and restore with custom firmware. (Except for iPhone 5c).\n");
    printf("  -o, --ota-bbfw\t\tuse 8.4.1 OTA baseband for 32-bit devices (except iPhone 5c)\n");
    printf("  -a, --old-ota-bbfw\t\tuse 6.1.3 OTA baseband for A5 (s5l8940x) devices\n");
    printf("  -f, --force-latest-bbfw\tuse the latest baseband provided for Qualcomm MDM9615M (Mav7Mav8) baseband chip. [dangerous]\n");
    printf("  -d, --debug\t\t\tprint debug information\n");
    printf("\n");
    printf("Homepage: https://downgrade.party\n");
    printf("Based on idevicerestore by libimobiledevice.\n");
}
#endif

// fw-lists
static const char *ota_bm_path = "AssetData/boot/BuildManifest.plist";
static const char *ipsw_bm_path = "BuildManifest.plist";

static const char *n92_fw      = "https://secure-appldnld.apple.com/iOS7.1/031-4768.20140627.DXmmp/iPhone3,3_7.1.2_11D257_Restore.ipsw";
static const char *k94_fw      = "https://secure-appldnld.apple.com/iOS9.3.5/031-74153-20160825-1250B23E-6717-11E6-AB83-973F34D2D062/iPad2,2_9.3.5_13G36_Restore.ipsw";
static const char *n94_fw      = "https://updates.cdn-apple.com/2019/ios/041-80043-20190722-6C65AD27-69D8-499C-BC15-DE7AC74DE2BD/iPhone4,1_9.3.6_13G37_Restore.ipsw";
static const char *k95_fw      = "https://updates.cdn-apple.com/2019/ios/041-80042-20190722-68F07B91-8EA1-4A3B-A930-35314A006ECB/iPad2,3_9.3.6_13G37_Restore.ipsw";
static const char *p106_fw     = "https://updates.cdn-apple.com/2019/ios/041-80040-20190722-B1E89CC8-5209-40C3-AEE9-63C29D38BDEB/iPad2,6_9.3.6_13G37_Restore.ipsw";
static const char *p107_fw     = "https://updates.cdn-apple.com/2019/ios/041-80041-20190722-673B8756-0A63-4BB6-9855-ACE2381695AF/iPad2,7_9.3.6_13G37_Restore.ipsw";
static const char *j2_fw       = "https://updates.cdn-apple.com/2019/ios/041-80039-20190722-E632D5D2-2F3C-498F-B83F-7067D9D90B33/iPad3,2_9.3.6_13G37_Restore.ipsw";
static const char *j3_fw       = "https://updates.cdn-apple.com/2019/ios/041-80044-20190722-6C65AD27-69D8-499C-BC15-DE7AC74DE2BD/iPad3,3_9.3.6_13G37_Restore.ipsw";
static const char *n48n49_fw   = "http://appldnld.apple.com/ios10.3.3/091-23384-20170719-CA966D80-6977-11E7-9F96-3E9100BA0AE3/iPhone_4.0_32bit_10.3.3_14G60_Restore.ipsw";
static const char *n41n42_fw   = "https://updates.cdn-apple.com/2019/ios/091-25277-20190722-0C1B94DE-992C-11E9-A2EE-E2C9A77C2E40/iPhone_4.0_32bit_10.3.4_14G61_Restore.ipsw";
static const char *p102p103_fw = "https://updates.cdn-apple.com/2019/ios/091-25014-20190722-0C1B95A6-992C-11E9-A2EE-E1C9A77C2E40/iPad_32bit_10.3.4_14G61_Restore.ipsw";
// bbfw-list
static const char *ice3_path     = "Firmware/ICE3_04.12.09_BOOT_02.13.Release.bbfw";
static const char *phoenix_path  = "Firmware/Phoenix-3.6.03.Release.bbfw";
static const char *trek_path     = "Firmware/Trek-6.7.00.Release.bbfw";
static const char *mav4_path     = "Firmware/Mav4-6.7.00.Release.bbfw";
static const char *mav5_path     = "Firmware/Mav5-11.80.00.Release.bbfw";
static const char *mav7mav8_path = "Firmware/Mav7Mav8-7.60.00.Release.bbfw";

// 8.4.1 fw-lists
static const char *n94_841_fw  = "https://secure-appldnld.apple.com/ios8.4.1/031-31129-20150812-751A3CB8-3C8F-11E5-A8A5-A91A3A53DB92/iPhone4,1_8.4.1_12H321_Restore.ipsw";
static const char *n41_841_fw  = "https://secure-appldnld.apple.com/ios8.4.1/031-31186-20150812-751D243C-3C8F-11E5-8E4F-B51A3A53DB92/iPhone5,1_8.4.1_12H321_Restore.ipsw";
static const char *n42_841_fw  = "https://secure-appldnld.apple.com/ios8.4.1/031-31065-20150812-7518F132-3C8F-11E5-A96A-A11A3A53DB92/iPhone5,2_8.4.1_12H321_Restore.ipsw";
static const char *k94_841_fw  = "https://secure-appldnld.apple.com/ios8.4.1/031-31288-20150812-4490750C-3C90-11E5-84FD-231C3A53DB92/iPad2,2_8.4.1_12H321_Restore.ipsw";
static const char *k95_841_fw  = "https://secure-appldnld.apple.com/ios8.4.1/031-31281-20150812-40590580-3C90-11E5-92A1-011C3A53DB92/iPad2,3_8.4.1_12H321_Restore.ipsw";
static const char *p106_841_fw = "https://secure-appldnld.apple.com/ios8.4.1/031-31278-20150812-751FA1F8-3C8F-11E5-9856-BF1A3A53DB92/iPad2,6_8.4.1_12H321_Restore.ipsw";
static const char *p107_841_fw = "https://secure-appldnld.apple.com/ios8.4.1/031-30932-20150812-7516F936-3C8F-11E5-849C-911A3A53DB92/iPad2,7_8.4.1_12H321_Restore.ipsw";
static const char *j2_841_fw   = "https://secure-appldnld.apple.com/ios8.4.1/031-30995-20150812-7517C906-3C8F-11E5-AEB0-971A3A53DB92/iPad3,2_8.4.1_12H321_Restore.ipsw";
static const char *j3_841_fw   = "https://secure-appldnld.apple.com/ios8.4.1/031-31372-20150812-767B933A-3C90-11E5-9E13-FF1C3A53DB92/iPad3,3_8.4.1_12H321_Restore.ipsw";
static const char *p102_841_fw = "https://secure-appldnld.apple.com/ios8.4.1/031-31092-20150812-7518CFB8-3C8F-11E5-B849-A51A3A53DB92/iPad3,5_8.4.1_12H321_Restore.ipsw";
static const char *p103_841_fw = "https://secure-appldnld.apple.com/ios8.4.1/031-31187-20150812-751A8A7E-3C8F-11E5-B300-B71A3A53DB92/iPad3,6_8.4.1_12H321_Restore.ipsw";
// 8.4.1 bbfw-list
static const char *phoenix_841_path = "Firmware/Phoenix-3.0.04.Release.bbfw";
static const char *trek_841_path    = "Firmware/Trek-5.5.00.Release.bbfw";
static const char *mav4_841_path    = "Firmware/Mav4-5.4.00.Release.bbfw";
static const char *mav5_841_path    = "Firmware/Mav5-8.02.00.Release.bbfw";

// 6.1.3 fw-lists
static const char *n94_613_fw  = "https://secure-appldnld.apple.com/iOS6.1/091-2611.20130319.Fr54r/iPhone4,1_6.1.3_10B329_Restore.ipsw";
static const char *k94_613_fw  = "https://secure-appldnld.apple.com/iOS6.1/091-2472.20130319.Ta4rt/iPad2,2_6.1.3_10B329_Restore.ipsw";
static const char *k95_613_fw  = "https://secure-appldnld.apple.com/iOS6.1/091-2464.20130319.KF6yt/iPad2,3_6.1.3_10B329_Restore.ipsw";
// 6.1.3 bbfw-list
static const char *trek_613_path    = "Firmware/Trek-3.4.03.Release.bbfw";

// 12.5.4
static const char *n51_fw = "https://updates.cdn-apple.com/2021WinterFCS/fullrestores/071-54188/5BD15EF8-7459-4DB6-A5F0-F819F0A32781/iPhone_4.0_64bit_12.5.4_16H50_Restore.ipsw";
static const char *mav7mav8_1254_path = "Firmware/Mav7Mav8-10.80.02.Release.bbfw";

static const char *phoenix_712_path = "Firmware/Phoenix-3.0.04.Release.bbfw";

static int idevicerestore_keep_pers = 0;


static void get_ubid(const char* product, unsigned char** data, size_t* size) {
    
    // s5l8940x
    if (!strcmp(product, "iPhone4,1")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, n94_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPad2,1")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, k93_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPad2,2")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, k94_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPad2,3")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, k95_841_ubid, *size);
        return;
    }
    
    // s5l8942x
    if (!strcmp(product, "iPad2,4")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, k93a_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPod5,1")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, n78_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPad2,5")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, p105_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPad2,6")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, p106_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPad2,7")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, p107_841_ubid, *size);
        return;
    }
    
    // s5l8945x
    if (!strcmp(product, "iPad3,1")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, j1_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPad3,2")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, j2_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPad3,3")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, j2a_841_ubid, *size);
        return;
    }
    
    // s5l8950x
    if (!strcmp(product, "iPhone5,1")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, n41_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPhone5,2")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, n42_841_ubid, *size);
        return;
    }
    
    //s5l8955x
    if (!strcmp(product, "iPad3,4")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, p101_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPad3,5")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, p102_841_ubid, *size);
        return;
    }
    
    if (!strcmp(product, "iPad3,6")) {
        *size = 20;
        *data = malloc(*size);
        memcpy(*data, p103_841_ubid, *size);
        return;
    }
    
    return;
}


static int load_version_data(struct idevicerestore_client_t* client)
{
    if (!client) {
        return -1;
    }
    
    struct stat fst;
    int cached = 0;
    
    char version_xml[1024];
    
    if (client->cache_dir) {
        if (stat(client->cache_dir, &fst) < 0) {
            mkdir_with_parents(client->cache_dir, 0755);
        }
        strcpy(version_xml, client->cache_dir);
        strcat(version_xml, "/");
        strcat(version_xml, VERSION_XML);
    } else {
        strcpy(version_xml, VERSION_XML);
    }
    
    if ((stat(version_xml, &fst) < 0) || ((time(NULL)-86400) > fst.st_mtime)) {
        char version_xml_tmp[1024];
        strcpy(version_xml_tmp, version_xml);
        strcat(version_xml_tmp, ".tmp");
        
        if (download_to_file("http://itunes.apple.com/check/version",  version_xml_tmp, 0) == 0) {
            remove(version_xml);
            if (rename(version_xml_tmp, version_xml) < 0) {
                error("ERROR: Could not update '%s'\n", version_xml);
            } else {
                info("NOTE: Updated version data.\n");
            }
        }
    } else {
        cached = 1;
    }
    
    char *verbuf = NULL;
    size_t verlen = 0;
    read_file(version_xml, (void**)&verbuf, &verlen);
    
    if (!verbuf) {
        error("ERROR: Could not load '%s'\n", version_xml);
        return -1;
    }
    
    client->version_data = NULL;
    plist_from_xml(verbuf, verlen, &client->version_data);
    free(verbuf);
    
    if (!client->version_data) {
        remove(version_xml);
        error("ERROR: Cannot parse plist data from '%s'.\n", version_xml);
        return -1;
    }
    
    if (cached) {
        info("NOTE: using cached version data\n");
    }
    
    return 0;
}

int idevicerestore_start(struct idevicerestore_client_t* client)
{
    int tss_enabled = 0;
    int result = 0;
    
    if (!client) {
        return -1;
    }
    
    if (client->flags & FLAG_RERESTORE) {
        if (!(client->flags & FLAG_ERASE) && !(client->flags & FLAG_UPDATE)) {
            
            /* Set FLAG_ERASE for now, code later on handles switching to FLAG_UPDATE if needed. */
            
            client->flags |= FLAG_ERASE;
            
#if 0
            error("ERROR: FLAG_RERESTORE must be used with either FLAG_ERASE or FLAG_UPDATE\n");
            return -1;
#endif
            
        }
    }
    
    if ((client->flags & FLAG_LATEST) && (client->flags & FLAG_CUSTOM)) {
        error("ERROR: FLAG_LATEST cannot be used with FLAG_CUSTOM.\n");
        return -1;
    }
    
    if (!client->ipsw && !(client->flags & FLAG_PWN) && !(client->flags & FLAG_LATEST)) {
        error("ERROR: no ipsw file given\n");
        return -1;
    }
    
    if (client->flags & FLAG_DEBUG) {
        idevice_set_debug_level(1);
        irecv_set_debug_level(1);
        idevicerestore_debug = 1;
    }
    
    idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.0);
    
    // update version data (from cache, or apple if too old)
    load_version_data(client);
    
    // check which mode the device is currently in so we know where to start
    
    
    
    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
    if (check_mode(client) < 0) {
        error("ERROR: Unable to discover device mode. Please make sure a device is attached.\n");
        return -1;
    }
    idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.1);
    
    info("Found device in %s mode\n", client->mode->string);
    
    
    if (client->mode->index == MODE_WTF) {
        unsigned int cpid = 0;
        
        if (dfu_client_new(client) != 0) {
            error("ERROR: Could not open device in WTF mode\n");
            return -1;
        }
        if ((dfu_get_cpid(client, &cpid) < 0) || (cpid == 0)) {
            error("ERROR: Could not get CPID for WTF mode device\n");
            dfu_client_free(client);
            return -1;
        }
        
        char wtfname[256];
        sprintf(wtfname, "Firmware/dfu/WTF.s5l%04xxall.RELEASE.dfu", cpid);
        unsigned char* wtftmp = NULL;
        unsigned int wtfsize = 0;
        
        // Prefer to get WTF file from the restore IPSW
        ipsw_extract_to_memory(client->ipsw, wtfname, &wtftmp, &wtfsize);
        if (!wtftmp) {
            // Download WTF IPSW
            char* s_wtfurl = NULL;
            plist_t wtfurl = plist_access_path(client->version_data, 7, "MobileDeviceSoftwareVersionsByVersion", "5", "RecoverySoftwareVersions", "WTF", "304218112", "5", "FirmwareURL");
            if (wtfurl && (plist_get_node_type(wtfurl) == PLIST_STRING)) {
                plist_get_string_val(wtfurl, &s_wtfurl);
            }
            if (!s_wtfurl) {
                info("Using hardcoded x12220000_5_Recovery.ipsw URL\n");
                s_wtfurl = strdup("http://appldnld.apple.com.edgesuite.net/content.info.apple.com/iPhone/061-6618.20090617.Xse7Y/x12220000_5_Recovery.ipsw");
            }
            
            // make a local file name
            char* fnpart = strrchr(s_wtfurl, '/');
            if (!fnpart) {
                fnpart = (char*)"x12220000_5_Recovery.ipsw";
            }
            else {
                fnpart++;
            }
            struct stat fst;
            char wtfipsw[1024];
            if (client->cache_dir) {
                if (stat(client->cache_dir, &fst) < 0) {
                    mkdir_with_parents(client->cache_dir, 0755);
                }
                strcpy(wtfipsw, client->cache_dir);
                strcat(wtfipsw, "/");
                strcat(wtfipsw, fnpart);
            }
            else {
                strcpy(wtfipsw, fnpart);
            }
            if (stat(wtfipsw, &fst) != 0) {
                download_to_file(s_wtfurl, wtfipsw, 0);
            }
            
            ipsw_extract_to_memory(wtfipsw, wtfname, &wtftmp, &wtfsize);
            if (!wtftmp) {
                error("ERROR: Could not extract WTF\n");
            }
        }
        
        if (wtftmp) {
            if (dfu_send_buffer(client, wtftmp, wtfsize) != 0) {
                error("ERROR: Could not send WTF...\n");
            }
        }
        dfu_client_free(client);
        
        sleep(1);
        
        free(wtftmp);
        client->mode = &idevicerestore_modes[MODE_DFU];
    }
    
    // discover the device type
    if (check_hardware_model(client) == NULL || client->device == NULL) {
        error("ERROR: Unable to discover device model\n");
        return -1;
    }
    idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.2);
    info("Identified device as %s, %s\n", client->device->hardware_model, client->device->product_type);
    
    if ((client->flags & FLAG_PWN) && (client->mode->index != MODE_DFU)) {
        error("ERROR: you need to put your device into DFU mode to pwn it.\n");
        return -1;
    }
    
    if (client->flags & FLAG_LATEST) {
        char* ipsw = NULL;
        int res = ipsw_download_latest_fw(client->version_data, client->device->product_type, client->cache_dir, &ipsw);
        if (res != 0) {
            if (ipsw) {
                free(ipsw);
            }
            return res;
        }
        else {
            client->ipsw = ipsw;
        }
    }
    idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.6);
    
    if (client->flags & FLAG_NOACTION) {
        return 0;
    }
    
    if (client->mode->index == MODE_RESTORE) {
        if (restore_reboot(client) < 0) {
            error("ERROR: Unable to exit restore mode\n");
            return -2;
        }
        
        // we need to refresh the current mode again
        if (check_mode(client) < 0) {
            error("ERROR: Unable to discover device mode. Please make sure a device is attached.\n");
            return -1;
        }
        info("Found device in %s mode\n", client->mode->string);
    }
    
    // verify if ipsw file exists
    if (access(client->ipsw, F_OK) < 0) {
        error("ERROR: Firmware file %s does not exist.\n", client->ipsw);
        return -1;
    }
    
    // extract buildmanifest
    plist_t buildmanifest = NULL;
    if (client->flags & FLAG_CUSTOM) {
        info("Extracting Restore.plist from IPSW\n");
        if (ipsw_extract_restore_plist(client->ipsw, &buildmanifest) < 0) {
            error("ERROR: Unable to extract Restore.plist from %s. Firmware file might be corrupt.\n", client->ipsw);
            return -1;
        }
    }
    else {
        info("Extracting BuildManifest from IPSW\n");
        if (ipsw_extract_build_manifest(client->ipsw, &buildmanifest, &tss_enabled) < 0) {
            error("ERROR: Unable to extract BuildManifest from %s. Firmware file might be corrupt.\n", client->ipsw);
            return -1;
        }
    }
    idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.8);
    
    
    /* check if device type is supported by the given build manifest */
    if (build_manifest_check_compatibility(buildmanifest, client->device->product_type) < 0) {
        error("ERROR: Could not make sure this firmware is suitable for the current device. Refusing to continue.\n");
        return -1;
    }
    
    /* print iOS information from the manifest */
    build_manifest_get_version_information(buildmanifest, client);
    
    info("Product Version: %s\n", client->version);
    info("Product Build: %s Major: %d\n", client->build, client->build_major);
    
    client->image4supported = is_image4_supported(client);
    debug("Device supports Image4: %s\n", (client->image4supported) ? "true" : "false");
    
    if (client->image4supported) {
        error("This copy of iDeviceReRestore does not support Image4 devices. Use iDeviceRestore instead (https://github.com/libimobiledevice/idevicerestore)\n");
        return -1;
    }
    
    if (client->flags & FLAG_CUSTOM) {
        /* prevent signing custom firmware */
        tss_enabled = 0;
        info("Custom firmware requested. Disabled TSS request.\n");
    }
    
    // choose whether this is an upgrade or a restore (default to upgrade)
    client->tss = NULL;
    plist_t build_identity = NULL;
    if (client->flags & FLAG_CUSTOM) {
        build_identity = plist_new_dict();
        {
            plist_t node;
            plist_t comp;
            plist_t inf;
            plist_t manifest;
            
            char tmpstr[256];
            char p_all_flash[128];
            char lcmodel[8];
            strcpy(lcmodel, client->device->hardware_model);
            int x = 0;
            while (lcmodel[x]) {
                lcmodel[x] = tolower(lcmodel[x]);
                x++;
            }
            
            sprintf(p_all_flash, "Firmware/all_flash/all_flash.%s.%s", lcmodel, "production");
            strcpy(tmpstr, p_all_flash);
            strcat(tmpstr, "/manifest");
            
            // get all_flash file manifest
            char *files[16];
            char *fmanifest = NULL;
            uint32_t msize = 0;
            if (ipsw_extract_to_memory(client->ipsw, tmpstr, (unsigned char**)&fmanifest, &msize) < 0) {
                error("ERROR: could not extract %s from IPSW\n", tmpstr);
                return -1;
            }
            
            char *tok = strtok(fmanifest, "\r\n");
            int fc = 0;
            while (tok) {
                files[fc++] = strdup(tok);
                if (fc >= 16) {
                    break;
                }
                tok = strtok(NULL, "\r\n");
            }
            free(fmanifest);
            
            manifest = plist_new_dict();
            
            for (x = 0; x < fc; x++) {
                inf = plist_new_dict();
                strcpy(tmpstr, p_all_flash);
                strcat(tmpstr, "/");
                strcat(tmpstr, files[x]);
                plist_dict_set_item(inf, "Path", plist_new_string(tmpstr));
                comp = plist_new_dict();
                plist_dict_set_item(comp, "Info", inf);
                const char* compname = get_component_name(files[x]);
                if (compname) {
                    plist_dict_set_item(manifest, compname, comp);
                    if (!strncmp(files[x], "DeviceTree", 10)) {
                        plist_dict_set_item(manifest, "RestoreDeviceTree", plist_copy(comp));
                    }
                }
                else {
                    error("WARNING: unhandled component %s\n", files[x]);
                    plist_free(comp);
                }
                free(files[x]);
                files[x] = NULL;
            }
            
            // add iBSS
            sprintf(tmpstr, "Firmware/dfu/iBSS.%s.%s.dfu", lcmodel, "RELEASE");
            inf = plist_new_dict();
            plist_dict_set_item(inf, "Path", plist_new_string(tmpstr));
            comp = plist_new_dict();
            plist_dict_set_item(comp, "Info", inf);
            plist_dict_set_item(manifest, "iBSS", comp);
            
            // add iBEC
            sprintf(tmpstr, "Firmware/dfu/iBEC.%s.%s.dfu", lcmodel, "RELEASE");
            inf = plist_new_dict();
            plist_dict_set_item(inf, "Path", plist_new_string(tmpstr));
            comp = plist_new_dict();
            plist_dict_set_item(comp, "Info", inf);
            plist_dict_set_item(manifest, "iBEC", comp);
            
            // add kernel cache
            plist_t kdict = NULL;
            
            node = plist_dict_get_item(buildmanifest, "KernelCachesByTarget");
            if (node && (plist_get_node_type(node) == PLIST_DICT)) {
                char tt[4];
                strncpy(tt, lcmodel, 3);
                tt[3] = 0;
                kdict = plist_dict_get_item(node, tt);
            }
            else {
                // Populated in older iOS IPSWs
                kdict = plist_dict_get_item(buildmanifest, "RestoreKernelCaches");
            }
            if (kdict && (plist_get_node_type(kdict) == PLIST_DICT)) {
                plist_t kc = plist_dict_get_item(kdict, "Release");
                if (kc && (plist_get_node_type(kc) == PLIST_STRING)) {
                    inf = plist_new_dict();
                    plist_dict_set_item(inf, "Path", plist_copy(kc));
                    comp = plist_new_dict();
                    plist_dict_set_item(comp, "Info", inf);
                    plist_dict_set_item(manifest, "KernelCache", comp);
                    plist_dict_set_item(manifest, "RestoreKernelCache", plist_copy(comp));
                }
            }
            
            // add ramdisk
            node = plist_dict_get_item(buildmanifest, "RestoreRamDisks");
            if (node && (plist_get_node_type(node) == PLIST_DICT)) {
                plist_t rd = plist_dict_get_item(node, (client->flags & FLAG_ERASE) ? "User" : "Update");
                // if no "Update" ram disk entry is found try "User" ram disk instead
                if (!rd && !(client->flags & FLAG_ERASE)) {
                    rd = plist_dict_get_item(node, "User");
                    // also, set the ERASE flag since we actually change the restore variant
                    client->flags |= FLAG_ERASE;
                }
                if (rd && (plist_get_node_type(rd) == PLIST_STRING)) {
                    inf = plist_new_dict();
                    plist_dict_set_item(inf, "Path", plist_copy(rd));
                    comp = plist_new_dict();
                    plist_dict_set_item(comp, "Info", inf);
                    plist_dict_set_item(manifest, "RestoreRamDisk", comp);
                }
            }
            
            // add OS filesystem
            node = plist_dict_get_item(buildmanifest, "SystemRestoreImages");
            if (!node) {
                error("ERROR: missing SystemRestoreImages in Restore.plist\n");
            }
            plist_t os = plist_dict_get_item(node, "User");
            if (!os) {
                error("ERROR: missing filesystem in Restore.plist\n");
            }
            else {
                inf = plist_new_dict();
                plist_dict_set_item(inf, "Path", plist_copy(os));
                comp = plist_new_dict();
                plist_dict_set_item(comp, "Info", inf);
                plist_dict_set_item(manifest, "OS", comp);
            }
            
            // add info
            inf = plist_new_dict();
            plist_dict_set_item(inf, "RestoreBehavior", plist_new_string((client->flags & FLAG_ERASE) ? "Erase" : "Update"));
            plist_dict_set_item(inf, "Variant", plist_new_string((client->flags & FLAG_ERASE) ? "Customer Erase Install (IPSW)" : "Customer Upgrade Install (IPSW)"));
            plist_dict_set_item(build_identity, "Info", inf);
            
            // finally add manifest
            plist_dict_set_item(build_identity, "Manifest", manifest);
        }
    }
    else if (client->flags & FLAG_ERASE) {
        build_identity = build_manifest_get_build_identity_for_model_with_restore_behavior(buildmanifest, client->device->hardware_model, "Erase");
        if (build_identity == NULL) {
            error("ERROR: Unable to find any build identities\n");
            plist_free(buildmanifest);
            return -1;
        }
    }
    else if (client->flags & FLAG_UPDATE) {
        build_identity = build_manifest_get_build_identity_for_model_with_restore_behavior(buildmanifest, client->device->hardware_model, "Update");
        if (!build_identity) {
            build_identity = build_manifest_get_build_identity_for_model(buildmanifest, client->device->hardware_model);
        }
    }
    else {
        error("No install option chosen.\n");
        exit(1);
    }
    
    plist_t buildmanifest2 = NULL;
    plist_t build_identity2 = NULL;
    
    
    idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.0);
    /* retrieve shsh blobs if required */
    if (tss_enabled) {
        debug("Getting device's ECID for TSS request\n");
        /* fetch the device's ECID for the TSS request */
        if (get_ecid(client, &client->ecid) < 0) {
            error("ERROR: Unable to find device ECID\n");
            return -1;
        }
        info("Found ECID " FMT_qu "\n", (long long unsigned int)client->ecid);
        
        if (client->build_major > 8) {
            unsigned char* nonce = NULL;
            int nonce_size = 0;
            if (get_ap_nonce(client, &nonce, &nonce_size) < 0) {
                /* the first nonce request with older firmware releases can fail and it's OK */
                info("NOTE: Unable to get nonce from device\n");
            }
            
            if (!client->nonce || (nonce_size != client->nonce_size) || (memcmp(nonce, client->nonce, nonce_size) != 0)) {
                if (client->nonce) {
                    free(client->nonce);
                }
                client->nonce = nonce;
                client->nonce_size = nonce_size;
            }
            else {
                free(nonce);
            }
        }
        
        if (get_tss_response(client, build_identity, &client->tss) < 0) {
            error("ERROR: Unable to get SHSH blobs for this device\n");
            return -1;
        }
    }
    
    if (client->flags & FLAG_SHSHONLY) {
        if (!tss_enabled) {
            info("This device does not require a TSS record\n");
            return 0;
        }
        if (!client->tss) {
            error("ERROR: could not fetch TSS record\n");
            plist_free(buildmanifest);
            return -1;
        }
        else {
            char *bin = NULL;
            uint32_t blen = 0;
            plist_to_bin(client->tss, &bin, &blen);
            if (bin) {
                char zfn[1024];
                if (client->cache_dir) {
                    strcpy(zfn, client->cache_dir);
                    strcat(zfn, "/shsh");
                }
                else {
                    strcpy(zfn, "shsh");
                }
                mkdir_with_parents(zfn, 0755);
                sprintf(zfn + strlen(zfn), "/" FMT_qu "-%s-%s-%s.shsh", (long long int)client->ecid, client->device->product_type, client->version, client->build);
                struct stat fst;
                if (stat(zfn, &fst) != 0) {
                    gzFile zf = gzopen(zfn, "wb");
                    gzwrite(zf, bin, blen);
                    gzclose(zf);
                    info("SHSH saved to '%s'\n", zfn);
                }
                else {
                    info("SHSH '%s' already present.\n", zfn);
                }
                free(bin);
            }
            else {
                error("ERROR: could not get TSS record data\n");
            }
            plist_free(client->tss);
            plist_free(buildmanifest);
            return 0;
        }
    }
    
    /* For a re-restore, check the APTicket for a hash of the RestoreRamDisk in the BuildManifest,
     * try to automatically detect if it contains an Erase or Update ramdisk hash, then
     * update the client flags if required.
     */
    if (tss_enabled && (client->flags & FLAG_RERESTORE)) {
        
        unsigned int ticketSize = 0;
        unsigned char *ticketData = 0;
        
        int ret = 0;
        
        /* Try to get the APTicket from the TSS response */
        ret = tss_response_get_ap_ticket(client->tss, &ticketData, &ticketSize);
        
        /* Check if an error was returned, or if no data was returned */
        if (!(ticketSize && ticketData) || ret) {
            printf("Error getting APTicket from TSS response\n");
            goto rdcheckdone;
        }
        
        int tries = 0;
        
    retry:;
        
        char *component = "RestoreRamDisk";
        char *path = 0;
        
        /* Try to get the path of the RestoreRamDisk for the current build identity */
        if (build_identity_get_component_path(build_identity, component, &path) < 0) {
            error("ERROR: Unable to get path for component '%s'\n", component);
            
            if (path) {
                free(path);
            }
            
            free(ticketData);
            goto rdcheckdone;
        }
        
        unsigned char *ramdiskData = 0;
        unsigned int ramdiskSize = 0;
        
        /* Try to get a buffer with the RestoreRamDisk */
        ret = extract_component(client->ipsw, path, &ramdiskData, &ramdiskSize);
        
        free(path);
        
        if (ret < 0 || !(ramdiskSize && ramdiskData)) {
            error("ERROR: Unable to extract component: %s\n", component);
            free(ticketData);
            goto rdcheckdone;
        }
        
        if (ramdiskSize < 0x14) {
            debug("Ramdisk data was not large enough to be an Image3\n");
            free(ramdiskData);
            free(ticketData);
            goto rdcheckdone;
        }
        
        /* If an unsigned RestoreRamDisk image is encountered, this is probably a custom restore. Move on from here. */
        if (*(uint32_t*)(void*)(ramdiskData+0xC) == 0x0) {
            free(ticketData);
            free(ramdiskData);
            client->isCustom = 1;
            goto rdcheckdone;
        }
        
        /* Create a buffer for the RestoreRamDisk digest */
        void *hashBuf = malloc(0x14);
        
        if (!hashBuf) {
            goto rdcheckdone;
        }
        
        bzero(hashBuf, 0x14);
        
        /* Hash the signed Image3 contents */
        SHA1(ramdiskData+0xC, (ramdiskSize-0xC), hashBuf);
        
        free(ramdiskData);
        
        int foundHash = 0;
        
        /* Search the ticket for the computed RestoreRamDisk digest */
        for (int i=0; i < (ticketSize-0x14); i++) {
            if (!memcmp(ticketData+i, hashBuf, 0x14)) {
                debug("Found ramdisk hash in ticket\n");
                foundHash = 1;
                break;
            }
        }
        
        /* Free the hash */
        free(hashBuf);
        
        /* If the RestoreRamDisk digest hash wasn't found in the APTicket, change the build identity and try again. */
        if (!foundHash) {
            
            /* Only change build identity if we haven't already */
            if (!tries) {
                if (client->flags & FLAG_ERASE) {
                    /* Remove FLAG_ERASE */
                    client->flags &= ~FLAG_ERASE;
                    
                    /* Set build_identity to Update */
                    build_identity = build_manifest_get_build_identity_for_model_with_restore_behavior(buildmanifest, client->device->hardware_model, "Update");
                    
                    /* If build_identity comes back NULL, there might not be an Update identity in the manifest. */
                    if (!build_identity) {
                        /* Set FLAG_ERASE */
                        client->flags |= FLAG_ERASE;
                        
                        /* Switch build identity back to Erase */
                        build_identity = build_manifest_get_build_identity_for_model_with_restore_behavior(buildmanifest, client->device->hardware_model, "Erase");
                        
                        /* Free the ticket data */
                        free(ticketData);
                        
                        /* Continue from here */
                        goto rdcheckdone;
                    }
                }
                else {
                    /* Set FLAG_ERASE */
                    client->flags |= FLAG_ERASE;
                    
                    /* Change build_identity to Erase */
                    build_identity = build_manifest_get_build_identity_for_model_with_restore_behavior(buildmanifest, client->device->hardware_model, "Erase");
                }
            }
            
            /* Didn't find the hash in the attempted build_identities, set to Erase and continue the restore. */
            else {
                /* Set FLAG_ERASE */
                client->flags |= FLAG_ERASE;
                
                /* Change build_identity to Erase */
                build_identity = build_manifest_get_build_identity_for_model_with_restore_behavior(buildmanifest, client->device->hardware_model, "Erase");
                
                /* Free the ticket data */
                free(ticketData);
                
                /* We can probably safely assume here that this is a custom restore if we haven't found the RestoreRamDisk hashes in the ticket */
                client->isCustom = 1;
                
                /* Continue from here */
                goto rdcheckdone;
            }
            
            debug("Didn't find ramdisk hash in ticket, checking for other ramdisk hash\n");
            
            /* Increment the tries counter */
            tries+=1;
            
            /* Retry */
            goto retry;
        }
        
    }
    
rdcheckdone:
    
    /* The build_identity may have been changed, print information about it here */
    build_identity_print_information(build_identity);
    
    /* Verify if we have tss records if required */
    if ((tss_enabled) && (client->tss == NULL)) {
        error("ERROR: Unable to proceed without a TSS record.\n");
        plist_free(buildmanifest);
        return -1;
    }
    
    if ((tss_enabled) && client->tss) {
        /* fix empty dicts */
        fixup_tss(client->tss);
    }
    idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.1);
    
    // Get filesystem name from build identity
    char* fsname = NULL;
    if (build_identity_get_component_path(build_identity, "OS", &fsname) < 0) {
        error("ERROR: Unable get path for filesystem component\n");
        return -1;
    }
    
    // check if we already have an extracted filesystem
    int delete_fs = 0;
    char* filesystem = NULL;
    struct stat st;
    memset(&st, '\0', sizeof(struct stat));
    char tmpf[1024];
    if (client->cache_dir) {
        if (stat(client->cache_dir, &st) < 0) {
            mkdir_with_parents(client->cache_dir, 0755);
        }
        strcpy(tmpf, client->cache_dir);
        strcat(tmpf, "/");
        char *ipswtmp = strdup(client->ipsw);
        strcat(tmpf, basename(ipswtmp));
        free(ipswtmp);
    }
    else {
        strcpy(tmpf, client->ipsw);
    }
    char* p = strrchr((const char*)tmpf, '.');
    if (p) {
        *p = '\0';
    }
    
    if (stat(tmpf, &st) < 0) {
        mkdir(tmpf, 0755);
    }
    strcat(tmpf, "/");
    strcat(tmpf, fsname);
    
    memset(&st, '\0', sizeof(struct stat));
    if (stat(tmpf, &st) == 0) {
        off_t fssize = 0;
        ipsw_get_file_size(client->ipsw, fsname, &fssize);
        if ((fssize > 0) && (st.st_size == fssize)) {
            info("Using cached filesystem from '%s'\n", tmpf);
            filesystem = strdup(tmpf);
        }
    }
    
    if (!filesystem) {
        char extfn[1024];
        strcpy(extfn, tmpf);
        strcat(extfn, ".extract");
        char lockfn[1024];
        strcpy(lockfn, tmpf);
        strcat(lockfn, ".lock");
        lock_info_t li;
        
        lock_file(lockfn, &li);
        FILE* extf = NULL;
        if (access(extfn, F_OK) != 0) {
            extf = fopen(extfn, "w");
        }
        unlock_file(&li);
        if (!extf) {
            // use temp filename
            filesystem = tempnam(NULL, "ipsw_");
            if (!filesystem) {
                error("WARNING: Could not get temporary filename, using '%s' in current directory\n", fsname);
                filesystem = strdup(fsname);
            }
            delete_fs = 1;
        }
        else {
            // use <fsname>.extract as filename
            filesystem = strdup(extfn);
            fclose(extf);
        }
        remove(lockfn);
        
        // Extract filesystem from IPSW
        info("Extracting filesystem from IPSW\n");
        if (ipsw_extract_to_file_with_progress(client->ipsw, fsname, filesystem, 1) < 0) {
            error("ERROR: Unable to extract filesystem from IPSW\n");
            if (client->tss)
                plist_free(client->tss);
            plist_free(buildmanifest);
            return -1;
        }
        
        if (strstr(filesystem, ".extract")) {
            // rename <fsname>.extract to <fsname>
            remove(tmpf);
            rename(filesystem, tmpf);
            free(filesystem);
            filesystem = strdup(tmpf);
        }
    }
    
    
    // if the device is in normal mode, place device into recovery mode
    if (client->mode->index == MODE_NORMAL) {
        info("Entering recovery mode...\n");
        if (normal_enter_recovery(client) < 0) {
            error("ERROR: Unable to place device into recovery mode from %s mode\n", client->mode->string);
            if (client->tss)
                plist_free(client->tss);
            plist_free(buildmanifest);
            return -5;
        }
    }
    
    idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.3);
    
    // if the device is in DFU mode, place device into recovery mode
    if (client->mode->index == MODE_DFU) {
        dfu_client_free(client);
        recovery_client_free(client);
        if (dfu_enter_recovery(client, build_identity) < 0) {
            error("ERROR: Unable to place device into recovery mode from %s mode\n", client->mode->string);
            plist_free(buildmanifest);
            if (client->tss)
                plist_free(client->tss);
            if (delete_fs && filesystem)
                unlink(filesystem);
            return -2;
        }
    }
    else {
        if ((client->build_major > 8) && !(client->flags & FLAG_CUSTOM)) {
            if (!client->image4supported) {
                /* send ApTicket */
                if (recovery_send_ticket(client) < 0) {
                    error("WARNING: Unable to send APTicket\n");
                }
            }
        }
        
        /* now we load the iBEC */
        if (recovery_send_ibec(client, build_identity) < 0) {
            error("ERROR: Unable to send iBEC\n");
            if (delete_fs && filesystem)
                unlink(filesystem);
            return -2;
        }
        
        recovery_client_free(client);
        
        /* Wait 2s after attempting to boot the image */
        sleep(2);
        
        int mode = 0;
        
        /* Try checking for the device's mode for about 10 seconds until it's in recovery again */
        for (int i=0; i < 20; i++) {
            
            /* Get the current mode */
            mode = check_mode(client);
            
            /* If mode came back NULL, wait 0.5s and try again */
            if (!mode) {
                usleep(500000);
                continue;
            }
            
            /* If the current mode is not recovery, wait 0.5s and try again */
            if (mode != MODE_RECOVERY) {
                usleep(500000);
                continue;
            }
            
            /* Hello recovery */
            
            if (recovery_client_new(client)) {
                error("Failed to connect to device\n");
                return -1;
            }
            
            break;
        }
    }
    
    /* Check the IBFL to see if we've successfully entered iBEC */
    const struct irecv_device_info *device_info = irecv_get_device_info(client->recovery->client);
    
    if (!device_info) {
        error("Couldn't query device info\n");
        return -1;
    }
    
    switch (device_info->ibfl) {
        case 0x03:
        case 0x1B:
            
            if (client->isCustom || !(client->build_major == 9 || client->build_major == 13)) {
                error("Failed to enter iBEC.\n");
            }
            else {
                error("Failed to enter iBEC. Your APTicket might not be usable for re-restoring.\n");
            }
            
            return -1;
        case 0x1A:
        case 0x02:
            printf("Successfully entered iBEC\n");
            
        default:
            break;
    }
    
    recovery_client_free(client);
    
    idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.5);
    
    if (client->flags & FLAG_RERESTORE) {
        char* fwurl = NULL;
        unsigned char isha1[20];
        
        if ((ipsw_get_latest_fw(client->version_data, client->device->product_type, &fwurl, isha1) < 0) || !fwurl) {
            error("ERROR: can't get URL for latest firmware\n");
            return -1;
        }
        
        if (!client->manifestPath) {
            
            if (!strcmp(client->device->product_type, "iPhone3,3")) {
                /*
                 device_name  : iPhone 4
                 product_type : iPhone3,3
                 Baseband     : Phoenix
                 signed fw    : 7.1.2
                 signed otafw :
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use iOS 7.1.2 BuildManifest.\n");
                    partialzip_download_file(n92_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    error("ERROR: 8.4.1 OTA SHSH is not provided for this device. Download and use iOS 7.1.2 BuildManifest.\n");
                    partialzip_download_file(n92_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_UNOFFICIAL_BBFW){
                    partialzip_download_file(k95_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else {
                    partialzip_download_file(n92_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPhone4,1")) {
                /*
                 device_name  : iPhone 4s
                 product_type : iPhone4,1
                 Baseband     : Trek
                 signed fw    : 9.3.6
                 signed otafw : 6.1.3, 8.4.1
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    // 6.1.3 ota
                    partialzip_download_file("http://appldnld.apple.com/iOS6.1/091-3360.20130311.BmfR4/com_apple_MobileAsset_SoftwareUpdate/82b056c7a9e455ad4f00d1b5169e5b56ab8c2cc7.zip", ota_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    // 8.4.1 ota
                    partialzip_download_file("http://appldnld.apple.com/ios8.4.1/031-31215-20150812-CFBCEB38-3D03-11E5-BCA3-03413A53DB92/com_apple_MobileAsset_SoftwareUpdate/811881b14b0e940233c77e7fc5f9719c7944c132.zip", ota_bm_path, "BuildManifest_New.plist");
                } else {
                    // 9.3.6 ipsw
                    partialzip_download_file(n94_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPad2,2")) {
                /*
                 device_name  : iPad 2
                 product_type : iPad2,2
                 Baseband     : ICE3
                 signed fw    : 9.3.5
                 signed otafw : 6.1.3, 8.4.1
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    // 6.1.3 ota
                    partialzip_download_file("http://appldnld.apple.com/iOS6.1/091-3360.20130311.BmfR4/com_apple_MobileAsset_SoftwareUpdate/bbfca2293088712e39f58caf76708fbd6a53e7a7.zip", ota_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    // 8.4.1 ota
                    partialzip_download_file("http://appldnld.apple.com/ios8.4.1/031-31146-20150812-33AD9B20-3D03-11E5-A2FB-CD3A3A53DB92/com_apple_MobileAsset_SoftwareUpdate/ca4d6ad210c5a4156e8564c60d336bd2b701ca9a.zip", ota_bm_path, "BuildManifest_New.plist");
                } else {
                    // 9.3.5 ipsw
                    partialzip_download_file(k94_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPad2,3")) {
                /*
                 device_name  : iPad 2
                 product_type : iPad2,3
                 Baseband     : Phoenix
                 signed fw    : 9.3.6
                 signed otafw : 6.1.3, 8.4.1
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    // 6.1.3 ota
                    partialzip_download_file("http://appldnld.apple.com/iOS6.1/091-3360.20130311.BmfR4/com_apple_MobileAsset_SoftwareUpdate/e1b90d0d74353756962990b9df74a2416d9b058f.zip", ota_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    // 8.4.1 ota
                    partialzip_download_file("http://appldnld.apple.com/ios8.4.1/031-31090-20150812-03686E1A-3D01-11E5-80C0-77323A53DB92/com_apple_MobileAsset_SoftwareUpdate/c121690f77afbd762b0c993ada682c4ce2e20704.zip", ota_bm_path, "BuildManifest_New.plist");
                } else {
                    // 9.3.6 ipsw
                    partialzip_download_file(k95_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPhone5,1")) {
                /*
                 device_name  : iPhone 5
                 product_type : iPhone5,1
                 Baseband     : Mav5
                 signed fw    : 10.3.4
                 signed otafw : 8.4.1
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use iOS 10.3.4 BuildManifest.\n");
                    partialzip_download_file(n41n42_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    // 8.4.1 ota
                    partialzip_download_file("http://appldnld.apple.com/ios8.4.1/031-31255-20150812-397905A2-3D04-11E5-A980-F7443A53DB92/com_apple_MobileAsset_SoftwareUpdate/b05418a539a1b91fbfc56ea19863dacc88563d79.zip", ota_bm_path, "BuildManifest_New.plist");
                } else {
                    // 10.3.4 ipsw
                    partialzip_download_file(n41n42_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPhone5,2")) {
                /*
                 device_name  : iPhone 5
                 product_type : iPhone5,2
                 Baseband     : Mav5
                 signed fw    : 10.3.4
                 signed otafw : 8.4.1
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use iOS 10.3.4 BuildManifest.\n");
                    partialzip_download_file(n41n42_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    // 8.4.1 ota
                    partialzip_download_file("http://appldnld.apple.com/ios8.4.1/031-31072-20150812-BBD41004-3D00-11E5-B0D8-0C303A53DB92/com_apple_MobileAsset_SoftwareUpdate/46b2fa23b1d819a4bebfd424cc7078936c3e2d6e.zip", ota_bm_path, "BuildManifest_New.plist");
                } else {
                    // 10.3.4 ipsw
                    partialzip_download_file(n41n42_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPad2,6")) {
                /*
                 device_name  : iPad mini
                 product_type : iPad2,6
                 Baseband     : Mav5
                 signed fw    : 9.3.6
                 signed otafw : 8.4.1
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use iOS 9.3.6 BuildManifest.\n");
                    partialzip_download_file(p106_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    // 8.4.1 ota
                    partialzip_download_file("http://appldnld.apple.com/ios8.4.1/031-30997-20150812-99F14F9E-3CFE-11E5-91E9-72273A53DB92/com_apple_MobileAsset_SoftwareUpdate/78d4991d74ec2f0a82eefb817fb228f798b27923.zip", ota_bm_path, "BuildManifest_New.plist");
                } else {
                    // 9.3.6 ipsw
                    partialzip_download_file(p106_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPad2,7")) {
                /*
                 device_name  : iPad mini
                 product_type : iPad2,7
                 Baseband     : Mav5
                 signed fw    : 9.3.6
                 signed otafw : 8.4.1
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use iOS 9.3.6 BuildManifest.\n");
                    partialzip_download_file(p107_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    // 8.4.1 ota
                    partialzip_download_file("http://appldnld.apple.com/ios8.4.1/031-31110-20150812-45750DAE-3D01-11E5-B0D1-DD343A53DB92/com_apple_MobileAsset_SoftwareUpdate/927f3aa82bac01147aca334104c7fc4d7f18cd0d.zip", ota_bm_path, "BuildManifest_New.plist");
                } else {
                    // 9.3.6 ipsw
                    partialzip_download_file(p107_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPad3,2")) {
                /*
                 device_name  : iPad 3rd generation
                 product_type : iPad3,2
                 Baseband     : Mav4
                 signed fw    : 9.3.6
                 signed otafw : 8.4.1
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use iOS 9.3.6 BuildManifest.\n");
                    partialzip_download_file(j2_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    // 8.4.1 ota
                    partialzip_download_file("http://appldnld.apple.com/ios8.4.1/031-31082-20150812-E0B48A66-3D00-11E5-A10B-52313A53DB92/com_apple_MobileAsset_SoftwareUpdate/f2e239e008b9d6354d21ef28a22731ebd53b6949.zip", ota_bm_path, "BuildManifest_New.plist");
                } else {
                    // 9.3.6 ipsw
                    partialzip_download_file(j2_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPad3,3")) {
                /*
                 device_name  : iPad 3rd generation
                 product_type : iPad3,3
                 Baseband     : Mav4
                 signed fw    : 9.3.6
                 signed otafw : 8.4.1
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use iOS 9.3.6 BuildManifest.\n");
                    partialzip_download_file(j3_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    // 8.4.1 ota
                    partialzip_download_file("http://appldnld.apple.com/ios8.4.1/031-31052-20150812-907C7F22-3D00-11E5-AF16-F22D3A53DB92/com_apple_MobileAsset_SoftwareUpdate/eeeb6a55a5c754da89bdec813113eef18fc52e8f.zip", ota_bm_path, "BuildManifest_New.plist");
                } else {
                    // 9.3.6 ipsw
                    partialzip_download_file(j3_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPad3,5")) {
                /*
                 device_name  : iPad 4th generation
                 product_type : iPad3,5
                 Baseband     : Mav5
                 signed fw    : 10.3.4
                 signed otafw : 8.4.1
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use iOS 10.3.4 BuildManifest.\n");
                    partialzip_download_file(p102p103_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    // 8.4.1 ota
                    partialzip_download_file("http://appldnld.apple.com/ios8.4.1/031-31063-20150812-A647D798-3D00-11E5-AC3E-4E2F3A53DB92/com_apple_MobileAsset_SoftwareUpdate/eefcdf6c2c55f9280a643d5da35039018f162c29.zip", ota_bm_path, "BuildManifest_New.plist");
                } else {
                    // 10.3.4 ipsw
                    partialzip_download_file(p102p103_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPad3,6")) {
                /*
                 device_name  : iPad 4th generation
                 product_type : iPad3,6
                 Baseband     : Mav5
                 signed fw    : 10.3.4
                 signed otafw : 8.4.1
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use iOS 10.3.4 BuildManifest.\n");
                    partialzip_download_file(p102p103_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    // 8.4.1 ota
                    partialzip_download_file("http://appldnld.apple.com/ios8.4.1/031-31343-20150812-21F639F2-3D06-11E5-BC83-3D4F3A53DB92/com_apple_MobileAsset_SoftwareUpdate/f37464602fd52f2468b0146e17a6d117b201d0bf.zip", ipsw_bm_path, "BuildManifest_New.plist");
                } else {
                    // 10.3.4 ipsw
                    partialzip_download_file(p102p103_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPhone5,3")) {
                /*
                 device_name  : iPhone 5c
                 product_type : iPhone5,3
                 Baseband     : Mav7Mav8
                 signed fw    : 10.3.3
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use iOS 10.3.3 BuildManifest.\n");
                    partialzip_download_file(n48n49_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    error("ERROR: 8.4.1 OTA SHSH is not provided for this device. Download and use iOS 10.3.3 BuildManifest.\n");
                    partialzip_download_file(n48n49_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_UNOFFICIAL_BBFW) {
                    // 12.5.4 ipsw
                    partialzip_download_file(n51_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else {
                    // 10.3.3 ipsw
                    partialzip_download_file(n48n49_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else if (!strcmp(client->device->product_type, "iPhone5,4")) {
                /*
                 device_name  : iPhone 5c
                 product_type : iPhone5,4
                 Baseband     : Mav7Mav8
                 signed fw    : 10.3.3
                 */
                if (client->flags & FLAG_OLD_OTA_BBFW){
                    error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use iOS 10.3.3 BuildManifest.\n");
                    partialzip_download_file(n48n49_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_OTA_BBFW){
                    error("ERROR: 8.4.1 OTA SHSH is not provided for this device. Download and use iOS 10.3.3 BuildManifest.\n");
                    partialzip_download_file(n48n49_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else if (client->flags & FLAG_UNOFFICIAL_BBFW) {
                    // 12.5.4 ipsw
                    partialzip_download_file(n51_fw, ipsw_bm_path, "BuildManifest_New.plist");
                } else {
                    // 10.3.3 ipsw
                    partialzip_download_file(n48n49_fw, ipsw_bm_path, "BuildManifest_New.plist");
                }
                
            } else {
                /* Download latest manifest if not any of the above devices */
                error("ERROR: No device information was found. Download and use the latest baseband.\n");
                partialzip_download_file(fwurl, ipsw_bm_path, "BuildManifest_New.plist");
            }
            client->otamanifest = "BuildManifest_New.plist";
        } else {
            client->otamanifest = client->manifestPath;
        }
        
        FILE *ofp = fopen(client->otamanifest, "rb");
        struct stat *ostat = (struct stat*) malloc(sizeof(struct stat));
        stat(client->otamanifest, ostat);
        char *opl = (char *)malloc(sizeof(char) *(ostat->st_size + 1));
        fread(opl, sizeof(char), ostat->st_size, ofp);
        fclose(ofp);
        
        if (memcmp(opl, "bplist00", 8) == 0)
            plist_from_bin(opl, (uint32_t)ostat->st_size, &buildmanifest2);
        else
            plist_from_xml(opl, (uint32_t)ostat->st_size, &buildmanifest2);
        free(ostat);
        const char *device = client->device->product_type;
        
        int indexCount = -1;
        
        if (!strcmp(device, "iPhone5,2") || !strcmp(device, "iPad3,5"))
            indexCount = 0;
        
        else if (!strcmp(device, "iPhone5,4") || !strcmp(device, "iPad3,6"))
            indexCount = 2;
        
        else if (!strcmp(device, "iPhone5,1") || !strcmp(device, "iPad3,4"))
            indexCount = 4;
        
        else if (!strcmp(device, "iPhone5,3"))
            indexCount = 6;
        
        plist_t node = NULL;
        char *version = 0;
        char *build = 0;
        node = plist_dict_get_item(buildmanifest2, "ProductVersion");
        plist_get_string_val(node, &version);
        
        node = plist_dict_get_item(buildmanifest2, "ProductBuildVersion");
        plist_get_string_val(node, &build);
        
        unsigned long major = strtoul(build, NULL, 10);
        
        if (major == 14 && indexCount == -1) {
            error("Error parsing BuildManifest.\n");
            exit(-1);
        }
        else if (major == 14)
            build_identity2 = build_manifest_get_build_identity(buildmanifest2, indexCount);
        else build_identity2 = build_manifest_get_build_identity(buildmanifest2, 0);
        
        /* if buildmanifest not specified, download the baseband firmware */
        if (!client->manifestPath) {
            char* bbfwpath = NULL;
            printf("Device: %s\n", device);
            plist_t bbfw_path = plist_access_path(build_identity2, 4, "Manifest", "BasebandFirmware", "Info", "Path");
            
            if (!bbfw_path) {
                printf("No BasebandFirmware in manifest\n");
                goto bbdlout;
            }
            
            if (plist_get_node_type(bbfw_path) != PLIST_STRING) {
                goto bbdownload;
            }
            
            plist_get_string_val(bbfw_path, &bbfwpath);
            
            plist_t bbfw_digestIPSW = plist_access_path(build_identity, 2, "Manifest", "BasebandFirmware");
            plist_t bbfw_digestNew = plist_access_path(build_identity2, 2, "Manifest", "BasebandFirmware");
            
            int bbfwIPSWDictCount = plist_dict_get_size(bbfw_digestIPSW);
            int bbfwNewDictCount = plist_dict_get_size(bbfw_digestNew);
            
            if (bbfwIPSWDictCount != bbfwNewDictCount) {
                goto bbdownload;
            }
            
            if (bbfwNewDictCount == 0) {
                goto bbdlout;
            }
            
            plist_dict_iter iter = 0;
            plist_dict_new_iter(bbfw_digestIPSW, &iter);
            
            for (int i=0; i < bbfwNewDictCount; i++) {
                void *item = 0;
                plist_t itemPlistIPSW = 0;
                plist_dict_next_item(bbfw_digestIPSW, iter, (char**)&item, &itemPlistIPSW);
                
                if (!item) {
                    continue;
                }
                
                mode_t currentItemModeIPSW = plist_get_node_type(itemPlistIPSW);
                
                plist_t itemPlistNew = plist_dict_get_item(bbfw_digestNew, item);
                
                if (!itemPlistNew) {
                    debug("Couldn't find %s in new manifest\n", item);
                    free(item);
                    goto bbdownload;
                }
                
                mode_t currentItemModeNew = plist_get_node_type(itemPlistNew);
                
                if (currentItemModeIPSW != currentItemModeNew) {
                    debug("%s does not match the type in new manifest\n", item);
                    free(item);
                    goto bbdownload;
                }
                
                switch (currentItemModeIPSW) {
                    case PLIST_DATA:;
                        
                        void *currentItemIPSW = 0;
                        uint64_t currentItemSizeIPSW = 0;
                        void *currentItemNew = 0;
                        uint64_t currentItemSizeNew = 0;
                        
                        plist_get_data_val(itemPlistIPSW, (char**)&currentItemIPSW, &currentItemSizeIPSW);
                        plist_get_data_val(itemPlistNew, (char**)&currentItemNew, &currentItemSizeNew);
                        
                        if (currentItemSizeIPSW != currentItemSizeNew) {
                            debug("IPSW %s size did not match the new manifest's entry\n", item);
                            free(item);
                            goto bbdownload;
                        }
                        
                        if (!memcmp(currentItemIPSW, currentItemNew, currentItemSizeIPSW)) {
                            debug("IPSW %s matches new manifest item\n", item);
                            free(currentItemIPSW);
                            free(currentItemNew);
                            free(item);
                            continue;
                        }
                        
                        free(currentItemIPSW);
                        free(currentItemNew);
                        free(item);
                        
                        goto bbdownload;
                        
                    case PLIST_UINT:;
                        
                        uint64_t currentUintItemIPSW = 0;
                        uint64_t currentUintItemNew = 0;
                        
                        plist_get_uint_val(itemPlistIPSW, &currentUintItemIPSW);
                        plist_get_uint_val(itemPlistNew, &currentUintItemNew);
                        
                        if (currentUintItemIPSW == currentUintItemNew) {
                            debug("IPSW %s matches new manifest item\n", item);
                            free(item);
                            continue;
                        }
                        
                        printf("IPSW %s did not match manifest item\n", item);
                        
                        free(item);
                        goto bbdownload;
                        
                    case PLIST_DICT:;
                        
                        if (!strcmp(item, "Info")) {
                            free(item);
                            continue;
                        }
                        
                    default:
                        debug("Unhandled item %s\n", item);
                        free(item);
                        goto bbdownload;
                }
                
            }
            
            /* All items in the IPSW bbfw entry match the new manifest, use the bbfw from the ipsw */
            debug("Provided IPSW BasebandFirmware matches the entry found in new manifest, using local file\n");
            
            void *bbfwData = 0;
            size_t bbfwSz = 0;
            
            extract_component(client->ipsw, bbfwpath, (unsigned char**)&bbfwData, (unsigned int*)&bbfwSz);
            
            if (!bbfwSz || !bbfwData) {
                debug("Failed to extract BasebandFirmware from IPSW\n");
                goto bbdownload;
            }
            
            client->basebandPath = "bbfw.tmp";
            
            FILE *bbfwFd = fopen(client->basebandPath, "w");
            fwrite(bbfwData, bbfwSz, 1, bbfwFd);
            fflush(bbfwFd);
            fclose(bbfwFd);
            
            free(bbfwData);
            
            goto bbdlout;
            
        bbdownload:
            
            if (bbfw_path || plist_get_node_type(bbfw_path) != PLIST_STRING) {
                printf("Downloading baseband firmware.\n");
                plist_get_string_val(bbfw_path, &bbfwpath);
                
                
                if (!strcmp(client->device->product_type, "iPhone3,3")) {
                    /*
                     device_name  : iPhone 4
                     product_type : iPhone3,3
                     Baseband     : Phoenix
                     signed fw    : 7.1.2
                     signed otafw :
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use Phoenix-3.0.04.\n");
                        partialzip_download_file(n92_fw, phoenix_712_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        error("ERROR: 8.4.1 OTA SHSH is not provided for this device. Download and use Phoenix-3.0.04.\n");
                        partialzip_download_file(n92_fw, phoenix_712_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_UNOFFICIAL_BBFW){
                        partialzip_download_file(k95_fw, phoenix_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(n92_fw, phoenix_712_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPhone4,1")) {
                    /*
                     device_name  : iPhone 4s
                     product_type : iPhone4,1
                     Baseband     : Trek
                     signed fw    : 9.3.6
                     signed otafw : 6.1.3, 8.4.1
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        partialzip_download_file(n94_613_fw, trek_613_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        partialzip_download_file(n94_841_fw, trek_841_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(n94_fw, trek_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPad2,2")) {
                    /*
                     device_name  : iPad 2
                     product_type : iPad2,2
                     Baseband     : ICE3
                     signed fw    : 9.3.5
                     signed otafw : 6.1.3, 8.4.1
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        partialzip_download_file(k94_613_fw, ice3_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        partialzip_download_file(k94_841_fw, ice3_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(k94_fw, ice3_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPad2,3")) {
                    /*
                     device_name  : iPad 2
                     product_type : iPad2,3
                     Baseband     : Phoenix
                     signed fw    : 9.3.6
                     signed otafw : 6.1.3, 8.4.1
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        partialzip_download_file(k95_613_fw, phoenix_841_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        partialzip_download_file(k95_841_fw, phoenix_841_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(k95_fw, phoenix_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPhone5,1")) {
                    /*
                     device_name  : iPhone 5
                     product_type : iPhone5,1
                     Baseband     : Mav5
                     signed fw    : 10.3.4
                     signed otafw : 8.4.1
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use Mav5-11.80.00.\n");
                        partialzip_download_file(n41n42_fw, mav5_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        partialzip_download_file(n41_841_fw, mav5_841_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(n41n42_fw, mav5_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPhone5,2")) {
                    /*
                     device_name  : iPhone 5
                     product_type : iPhone5,2
                     Baseband     : Mav5
                     signed fw    : 10.3.4
                     signed otafw : 8.4.1
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use Mav5-11.80.00.\n");
                        partialzip_download_file(n41n42_fw, mav5_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        partialzip_download_file(n42_841_fw, mav5_841_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(n41n42_fw, mav5_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPad2,6")) {
                    /*
                     device_name  : iPad mini
                     product_type : iPad2,6
                     Baseband     : Mav5
                     signed fw    : 9.3.6
                     signed otafw : 8.4.1
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use Mav5-11.80.00.\n");
                        partialzip_download_file(p106_fw, mav5_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        partialzip_download_file(p106_841_fw, mav5_841_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(p106_fw, mav5_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPad2,7")) {
                    /*
                     device_name  : iPad mini
                     product_type : iPad2,7
                     Baseband     : Mav5
                     signed fw    : 9.3.6
                     signed otafw : 8.4.1
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use Mav5-11.80.00.\n");
                        partialzip_download_file(p107_fw, mav5_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        partialzip_download_file(p107_841_fw, mav5_841_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(p107_fw, mav5_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPad3,2")) {
                    /*
                     device_name  : iPad 3rd generation
                     product_type : iPad3,2
                     Baseband     : Mav4
                     signed fw    : 9.3.6
                     signed otafw : 8.4.1
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use Mav4-6.7.00.\n");
                        partialzip_download_file(j2_fw, mav4_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        partialzip_download_file(j2_841_fw, mav4_841_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(j2_fw, mav4_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPad3,3")) {
                    /*
                     device_name  : iPad 3rd generation
                     product_type : iPad3,3
                     Baseband     : Mav4
                     signed fw    : 9.3.6
                     signed otafw : 8.4.1
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use Mav4-6.7.00.\n");
                        partialzip_download_file(j3_fw, mav4_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        partialzip_download_file(j3_841_fw, mav4_841_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(j3_fw, mav4_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPad3,5")) {
                    /*
                     device_name  : iPad 4th generation
                     product_type : iPad3,5
                     Baseband     : Mav5
                     signed fw    : 10.3.4
                     signed otafw : 8.4.1
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use Mav5-11.80.00.\n");
                        partialzip_download_file(p102p103_fw, mav5_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        partialzip_download_file(p102_841_fw, mav5_841_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(p102p103_fw, mav5_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPad3,6")) {
                    /*
                     device_name  : iPad 4th generation
                     product_type : iPad3,6
                     Baseband     : Mav5
                     signed fw    : 10.3.4
                     signed otafw : 8.4.1
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use Mav5-11.80.00.\n");
                        partialzip_download_file(p102p103_fw, mav5_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        partialzip_download_file(p103_841_fw, mav5_841_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(p102p103_fw, mav5_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPhone5,3")) {
                    /*
                     device_name  : iPhone 5c
                     product_type : iPhone5,3
                     Baseband     : Mav7Mav8
                     signed fw    : 10.3.3
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use Mav7Mav8-7.60.00.\n");
                        partialzip_download_file(n48n49_fw, mav7mav8_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        error("ERROR: 8.4.1 OTA SHSH is not provided for this device. Download and use Mav7Mav8-7.60.00.\n");
                        partialzip_download_file(n48n49_fw, mav7mav8_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_UNOFFICIAL_BBFW){
                        partialzip_download_file(n51_fw, mav7mav8_1254_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(n48n49_fw, mav7mav8_path, "bbfw.tmp");
                    }
                    
                } else if (!strcmp(client->device->product_type, "iPhone5,4")) {
                    /*
                     device_name  : iPhone 5c
                     product_type : iPhone5,4
                     Baseband     : Mav7Mav8
                     signed fw    : 10.3.3
                     */
                    if (client->flags & FLAG_OLD_OTA_BBFW){
                        error("ERROR: 6.1.3 OTA SHSH is not provided for this device. Download and use Mav7Mav8-7.60.00.\n");
                        partialzip_download_file(n48n49_fw, mav7mav8_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_OTA_BBFW){
                        error("ERROR: 8.4.1 OTA SHSH is not provided for this device. Download and use Mav7Mav8-7.60.00.\n");
                        partialzip_download_file(n48n49_fw, mav7mav8_path, "bbfw.tmp");
                    } else if (client->flags & FLAG_UNOFFICIAL_BBFW){
                        partialzip_download_file(n51_fw, mav7mav8_1254_path, "bbfw.tmp");
                    } else {
                        partialzip_download_file(n48n49_fw, mav7mav8_path, "bbfw.tmp");
                    }
                    
                } else {
                    /* Download latest BasebandFirmware instead */
                    error("ERROR: No device information was found. Download and use the latest baseband.\n");
                    partialzip_download_file(fwurl, bbfwpath, "bbfw.tmp");
                }
                client->basebandPath = "bbfw.tmp";
            }
        } else {
            /* user specified a manifest to use */
            printf("Using pre-defined BuildManifest.\n");
        }
    }
    
bbdlout:
    
    if (!client->image4supported && (client->build_major > 8)) {
        // we need another tss request with nonce.
        unsigned char* nonce = NULL;
        int nonce_size = 0;
        int nonce_changed = 0;
        if (get_ap_nonce(client, &nonce, &nonce_size) < 0) {
            error("ERROR: Unable to get nonce from device!\n");
            recovery_send_reset(client);
            if (delete_fs && filesystem)
                unlink(filesystem);
            return -2;
        }
        
        if (!client->nonce || (nonce_size != client->nonce_size) || (memcmp(nonce, client->nonce, nonce_size) != 0)) {
            nonce_changed = 1;
            if (client->nonce) {
                free(client->nonce);
            }
            client->nonce = nonce;
            client->nonce_size = nonce_size;
        } else {
            free(nonce);
        }
        
        if (nonce_changed && !(client->flags & FLAG_CUSTOM)) {
            // Welcome iOS5. We have to re-request the TSS with our nonce.
            plist_free(client->tss);
            if (get_tss_response(client, build_identity, &client->tss) < 0) {
                error("ERROR: Unable to get SHSH blobs for this device\n");
                if (delete_fs && filesystem)
                    unlink(filesystem);
                return -1;
            }
            if (!client->tss) {
                error("ERROR: can't continue without TSS\n");
                if (delete_fs && filesystem)
                    unlink(filesystem);
                return -1;
            }
            fixup_tss(client->tss);
        }
    }
    idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.7);
    
    // now finally do the magic to put the device into restore mode
    if (client->mode->index == MODE_RECOVERY) {
        if (client->srnm == NULL) {
            error("ERROR: could not retrieve device serial number. Can't continue.\n");
            if (delete_fs && filesystem)
                unlink(filesystem);
            return -1;
        }
        if (recovery_enter_restore(client, build_identity) < 0) {
            error("ERROR: Unable to place device into restore mode\n");
            plist_free(buildmanifest);
            if (client->tss)
                plist_free(client->tss);
            if (delete_fs && filesystem)
                unlink(filesystem);
            return -2;
        }
        recovery_client_free(client);
    }
    idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.9);
    
    // device is finally in restore mode, let's do this
    if (client->mode->index == MODE_RESTORE) {
        info("About to restore device... \n");
        result = restore_device(client, build_identity, filesystem);
        if (result < 0) {
            error("ERROR: Unable to restore device\n");
            if (delete_fs && filesystem)
                unlink(filesystem);
            return result;
        }
    }
    
    info("Cleaning up...\n");
    if (delete_fs && filesystem)
        unlink(filesystem);
    
    /* special handling of AppleTVs */
    if (strncmp(client->device->product_type, "AppleTV", 7) == 0) {
        if (recovery_client_new(client) == 0) {
            if (recovery_set_autoboot(client, 1) == 0) {
                recovery_send_reset(client);
            } else {
                error("Setting auto-boot failed?!\n");
            }
        } else {
            error("Could not connect to device in recovery mode.\n");
        }
    }
    
    info("DONE\n");
    
    if (result == 0) {
        idevicerestore_progress(client, RESTORE_NUM_STEPS-1, 1.0);
    }
    
    if (buildmanifest)
        plist_free(buildmanifest);
    
    if (build_identity)
        plist_free(build_identity);
    
    return result;
}

struct idevicerestore_client_t* idevicerestore_client_new(void)
{
    struct idevicerestore_client_t* client = (struct idevicerestore_client_t*) malloc(sizeof(struct idevicerestore_client_t));
    if (client == NULL) {
        error("ERROR: Out of memory\n");
        return NULL;
    }
    memset(client, '\0', sizeof(struct idevicerestore_client_t));
    return client;
}

void idevicerestore_client_free(struct idevicerestore_client_t* client)
{
    if (!client) {
        return;
    }
    
    if (client->tss_url) {
        free(client->tss_url);
    }
    if (client->version_data) {
        plist_free(client->version_data);
    }
    if (client->nonce) {
        free(client->nonce);
    }
    if (client->udid) {
        free(client->udid);
    }
    if (client->srnm) {
        free(client->srnm);
    }
    if (client->ipsw) {
        free(client->ipsw);
    }
    if (client->version) {
        free(client->version);
    }
    if (client->build) {
        free(client->build);
    }
    if (client->restore_boot_args) {
        free(client->restore_boot_args);
    }
    if (client->cache_dir) {
        free(client->cache_dir);
    }
    free(client);
}

void idevicerestore_set_ecid(struct idevicerestore_client_t* client, unsigned long long ecid)
{
    if (!client)
        return;
    client->ecid = ecid;
}

void idevicerestore_set_udid(struct idevicerestore_client_t* client, const char* udid)
{
    if (!client)
        return;
    if (client->udid) {
        free(client->udid);
        client->udid = NULL;
    }
    if (udid) {
        client->udid = strdup(udid);
    }
}

void idevicerestore_set_flags(struct idevicerestore_client_t* client, int flags)
{
    if (!client)
        return;
    client->flags = flags;
}

void idevicerestore_set_ipsw(struct idevicerestore_client_t* client, const char* path)
{
    if (!client)
        return;
    if (client->ipsw) {
        free(client->ipsw);
        client->ipsw = NULL;
    }
    if (path) {
        client->ipsw = strdup(path);
    }
}

void idevicerestore_set_cache_path(struct idevicerestore_client_t* client, const char* path)
{
    if (!client)
        return;
    if (client->cache_dir) {
        free(client->cache_dir);
        client->cache_dir = NULL;
    }
    if (path) {
        client->cache_dir = strdup(path);
    }
}

void idevicerestore_set_progress_callback(struct idevicerestore_client_t* client, idevicerestore_progress_cb_t cbfunc, void* userdata)
{
    if (!client)
        return;
    client->progress_cb = cbfunc;
    client->progress_cb_data = userdata;
}

#ifndef IDEVICERESTORE_NOMAIN
int main(int argc, char* argv[]) {
    int opt = 0;
    int optindex = 0;
    char* ipsw = NULL;
    int result = 0;
    
    struct idevicerestore_client_t* client = idevicerestore_client_new();
    if (client == NULL) {
        error("ERROR: could not create idevicerestore client\n");
        return -1;
    }
    
    //while ((opt = getopt_long(argc, argv, "dhofcersxtplui:nC:k:b:m:", longopts, &optindex)) > 0) {
    while ((opt = getopt_long(argc, argv, "dhbofacersxtplui:nC:k:", longopts, &optindex)) > 0) {
        switch (opt) {
            case 'h':
                usage(argc, argv);
                return 0;
                
            case 'd':
                client->flags |= FLAG_DEBUG;
                break;
            
            /* beta */
            case 'b':
                client->flags |= FLAG_OTA_BLOB;
                break;
                
            case 'o':
                client->flags |= FLAG_OTA_BBFW;
                break;
            
            case 'a':
                client->flags |= FLAG_OLD_OTA_BBFW;
                break;
            
            case 'f':
                client->flags |= FLAG_UNOFFICIAL_BBFW;
                break;
            /* beta end*/
            
            case 'r':
                client->flags |= FLAG_RERESTORE;
                break;
                
            //case 'm':
            //    client->manifestPath = strdup(optarg);
            //    break;
                
            //case 'b':
            //    client->basebandPath = strdup(optarg);
            //    break;
                
            default:
                usage(argc, argv);
                return -1;
        }
    }
    
    if((client->flags & FLAG_OTA_BBFW) && (client->flags & FLAG_OLD_OTA_BBFW)){
        error("ERROR: You can't use --ota and --oldota options at the same time.\n");
        return -1;
    }
    
    if(((client->flags & FLAG_OTA_BBFW) || (client->flags & FLAG_OLD_OTA_BBFW)) && (client->flags & FLAG_UNOFFICIAL_BBFW)){
        error("ERROR: You can't use --xxxota and --forcelatestbb options at the same time.\n");
        return -1;
    }
    
    if (((argc-optind) == 1) || (client->flags & FLAG_PWN) || (client->flags & FLAG_LATEST)) {
        argc -= optind;
        argv += optind;
        
        ipsw = argv[0];
    } else {
        usage(argc, argv);
        return -1;
    }
    
    if ((client->flags & FLAG_LATEST) && (client->flags & FLAG_CUSTOM)) {
        error("ERROR: You can't use --custom and --latest options at the same time.\n");
        return -1;
    }
    
    if (ipsw) {
        client->ipsw = strdup(ipsw);
    }
    
    curl_global_init(CURL_GLOBAL_ALL);
    
    result = idevicerestore_start(client);
    
    idevicerestore_client_free(client);
    
    curl_global_cleanup();
    
    return result;
}
#endif

int check_mode(struct idevicerestore_client_t* client) {
    int mode = MODE_UNKNOWN;
    int dfumode = MODE_UNKNOWN;
    
    if (recovery_check_mode(client) == 0) {
        mode = MODE_RECOVERY;
    }
    
    else if (dfu_check_mode(client, &dfumode) == 0) {
        mode = dfumode;
    }
    
    else if (normal_check_mode(client) == 0) {
        mode = MODE_NORMAL;
    }
    
    else if (restore_check_mode(client) == 0) {
        mode = MODE_RESTORE;
    }
    
    if (mode == MODE_UNKNOWN) {
        client->mode = NULL;
    } else {
        client->mode = &idevicerestore_modes[mode];
    }
    return mode;
}

const char* check_hardware_model(struct idevicerestore_client_t* client) {
    const char* hw_model = NULL;
    int mode = MODE_UNKNOWN;
    
    if (client->mode) {
        mode = client->mode->index;
    }
    
    switch (mode) {
        case MODE_RESTORE:
            hw_model = restore_check_hardware_model(client);
            break;
            
        case MODE_NORMAL:
            hw_model = normal_check_hardware_model(client);
            break;
            
        case MODE_DFU:
        case MODE_RECOVERY:
            hw_model = dfu_check_hardware_model(client);
            break;
        default:
            break;
    }
    
    if (hw_model != NULL) {
        irecv_devices_get_device_by_hardware_model(hw_model, &client->device);
    }
    
    return hw_model;
}

int is_image4_supported(struct idevicerestore_client_t* client)
{
    int res = 0;
    int mode = MODE_UNKNOWN;
    
    if (client->mode) {
        mode = client->mode->index;
    }
    
    switch (mode) {
        case MODE_NORMAL:
            res = normal_is_image4_supported(client);
            break;
        case MODE_DFU:
            res = dfu_is_image4_supported(client);
            break;
        case MODE_RECOVERY:
            res = recovery_is_image4_supported(client);
            break;
        default:
            error("ERROR: Device is in an invalid state\n");
            return 0;
    }
    return res;
}

int get_ecid(struct idevicerestore_client_t* client, uint64_t* ecid) {
    int mode = MODE_UNKNOWN;
    
    if (client->mode) {
        mode = client->mode->index;
    }
    
    switch (mode) {
        case MODE_NORMAL:
            if (normal_get_ecid(client, ecid) < 0) {
                *ecid = 0;
                return -1;
            }
            break;
            
        case MODE_DFU:
            if (dfu_get_ecid(client, ecid) < 0) {
                *ecid = 0;
                return -1;
            }
            break;
            
        case MODE_RECOVERY:
            if (recovery_get_ecid(client, ecid) < 0) {
                *ecid = 0;
                return -1;
            }
            break;
            
        default:
            error("ERROR: Device is in an invalid state\n");
            *ecid = 0;
            return -1;
    }
    
    return 0;
}

int get_ap_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size) {
    int mode = MODE_UNKNOWN;
    
    *nonce = NULL;
    *nonce_size = 0;
    
    info("Getting ApNonce ");
    
    if (client->mode) {
        mode = client->mode->index;
    }
    
    switch (mode) {
        case MODE_NORMAL:
            info("in normal mode... ");
            if (normal_get_ap_nonce(client, nonce, nonce_size) < 0) {
                info("failed\n");
                return -1;
            }
            break;
        case MODE_DFU:
            info("in dfu mode... ");
            if (dfu_get_ap_nonce(client, nonce, nonce_size) < 0) {
                info("failed\n");
                return -1;
            }
            break;
        case MODE_RECOVERY:
            info("in recovery mode... ");
            if (recovery_get_ap_nonce(client, nonce, nonce_size) < 0) {
                info("failed\n");
                return -1;
            }
            break;
            
        default:
            info("failed\n");
            error("ERROR: Device is in an invalid state\n");
            return -1;
    }
    
    int i = 0;
    for (i = 0; i < *nonce_size; i++) {
        info("%02x", (*nonce)[i]);
    }
    info("\n");
    
    return 0;
}

int get_sep_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size) {
    int mode = MODE_UNKNOWN;
    
    *nonce = NULL;
    *nonce_size = 0;
    
    info("Getting SepNonce ");
    
    if (client->mode) {
        mode = client->mode->index;
    }
    
    switch (mode) {
        case MODE_NORMAL:
            info("in normal mode... ");
            if (normal_get_sep_nonce(client, nonce, nonce_size) < 0) {
                info("failed\n");
                return -1;
            }
            break;
        case MODE_DFU:
            info("in dfu mode... ");
            if (dfu_get_sep_nonce(client, nonce, nonce_size) < 0) {
                info("failed\n");
                return -1;
            }
            break;
        case MODE_RECOVERY:
            info("in recovery mode... ");
            if (recovery_get_sep_nonce(client, nonce, nonce_size) < 0) {
                info("failed\n");
                return -1;
            }
            break;
            
        default:
            info("failed\n");
            error("ERROR: Device is in an invalid state\n");
            return -1;
    }
    
    int i = 0;
    for (i = 0; i < *nonce_size; i++) {
        info("%02x ", (*nonce)[i]);
    }
    info("\n");
    
    return 0;
}

plist_t build_manifest_get_build_identity(plist_t build_manifest, uint32_t identity) {
    // fetch build identities array from BuildManifest
    plist_t build_identities_array = plist_dict_get_item(build_manifest, "BuildIdentities");
    if (!build_identities_array || plist_get_node_type(build_identities_array) != PLIST_ARRAY) {
        error("ERROR: Unable to find build identities node\n");
        return NULL;
    }
    
    // check and make sure this identity exists in buildmanifest
    if (identity >= plist_array_get_size(build_identities_array)) {
        return NULL;
    }
    
    plist_t build_identity = plist_array_get_item(build_identities_array, identity);
    if (!build_identity || plist_get_node_type(build_identity) != PLIST_DICT) {
        error("ERROR: Unable to find build identities node\n");
        return NULL;
    }
    
    return plist_copy(build_identity);
}

plist_t build_manifest_get_build_identity_for_model_with_restore_behavior(plist_t build_manifest, const char *hardware_model, const char *behavior)
{
    plist_t build_identities_array = plist_dict_get_item(build_manifest, "BuildIdentities");
    if (!build_identities_array || plist_get_node_type(build_identities_array) != PLIST_ARRAY) {
        error("ERROR: Unable to find build identities node\n");
        return NULL;
    }
    
    uint32_t i;
    for (i = 0; i < plist_array_get_size(build_identities_array); i++) {
        plist_t ident = plist_array_get_item(build_identities_array, i);
        if (!ident || plist_get_node_type(ident) != PLIST_DICT) {
            continue;
        }
        plist_t info_dict = plist_dict_get_item(ident, "Info");
        if (!info_dict || plist_get_node_type(ident) != PLIST_DICT) {
            continue;
        }
        plist_t devclass = plist_dict_get_item(info_dict, "DeviceClass");
        if (!devclass || plist_get_node_type(devclass) != PLIST_STRING) {
            continue;
        }
        char *str = NULL;
        plist_get_string_val(devclass, &str);
        if (strcasecmp(str, hardware_model) != 0) {
            free(str);
            continue;
        }
        free(str);
        str = NULL;
        if (behavior) {
            plist_t rbehavior = plist_dict_get_item(info_dict, "RestoreBehavior");
            if (!rbehavior || plist_get_node_type(rbehavior) != PLIST_STRING) {
                continue;
            }
            plist_get_string_val(rbehavior, &str);
            if (strcasecmp(str, behavior) != 0) {
                free(str);
                continue;
            } else {
                free(str);
                return plist_copy(ident);
            }
            free(str);
        } else {
            return plist_copy(ident);
        }
    }
    
    return NULL;
}

plist_t build_manifest_get_build_identity_for_model(plist_t build_manifest, const char *hardware_model)
{
    return build_manifest_get_build_identity_for_model_with_restore_behavior(build_manifest, hardware_model, NULL);
}

int get_tss_response(struct idevicerestore_client_t* client, plist_t build_identity, plist_t* tss) {
    plist_t request = NULL;
    plist_t response = NULL;
    *tss = NULL;
    
    if ((client->build_major <= 8) || (client->flags & (FLAG_CUSTOM | FLAG_RERESTORE))) {
        error("checking for local shsh\n");
        
        /* first check for local copy */
        char zfn[1024];
        if (client->version) {
            if (client->cache_dir) {
                sprintf(zfn, "%s/shsh/" FMT_qu "-%s-%s-%s.shsh", client->cache_dir, (long long int)client->ecid, client->device->product_type, client->version, client->build);
            } else {
                sprintf(zfn, "shsh/" FMT_qu "-%s-%s-%s.shsh", (long long int)client->ecid, client->device->product_type, client->version, client->build);
            }
            struct stat fst;
            if (stat(zfn, &fst) == 0) {
                gzFile zf = gzopen(zfn, "rb");
                if (zf) {
                    int blen = 0;
                    int readsize = 16384;
                    int bufsize = readsize;
                    char* bin = (char*)malloc(bufsize);
                    char* p = bin;
                    do {
                        int bytes_read = gzread(zf, p, readsize);
                        if (bytes_read < 0) {
                            fprintf(stderr, "Error reading gz compressed data\n");
                            exit(EXIT_FAILURE);
                        }
                        blen += bytes_read;
                        if (bytes_read < readsize) {
                            if (gzeof(zf)) {
                                bufsize += bytes_read;
                                break;
                            }
                        }
                        bufsize += readsize;
                        bin = realloc(bin, bufsize);
                        p = bin + blen;
                    } while (!gzeof(zf));
                    gzclose(zf);
                    if (blen > 0) {
                        if (memcmp(bin, "bplist00", 8) == 0) {
                            plist_from_bin(bin, blen, tss);
                        } else {
                            plist_from_xml(bin, blen, tss);
                        }
                    }
                    free(bin);
                }
            } else {
                error("no local file %s\n", zfn);
            }
        } else {
            error("No version found?!\n");
        }
    }
    
    if (*tss) {
        info("Using local SHSH\n");
        return 0;
    }
    else if ((client->flags & FLAG_RERESTORE) &&
             (client->flags & FLAG_OTA_BLOB)) {
        info("Trying to fetch new OTA SHSH blob\n");
    }
    else if (client->flags & FLAG_RERESTORE) {
        info("Attempting to check Cydia TSS server for SHSH blobs\n");
        client->tss_url = strdup("http://cydia.saurik.com/TSS/controller?action=2");
    }
    else {
        info("Trying to fetch new SHSH blob\n");
    }
    
    /* populate parameters */
    plist_t parameters = plist_new_dict();
    plist_dict_set_item(parameters, "ApECID", plist_new_uint(client->ecid));
    if (client->nonce) {
        plist_dict_set_item(parameters, "ApNonce", plist_new_data((const char*)client->nonce, client->nonce_size));
    }
    unsigned char* sep_nonce = NULL;
    int sep_nonce_size = 0;
    get_sep_nonce(client, &sep_nonce, &sep_nonce_size);
    
    if (sep_nonce) {
        plist_dict_set_item(parameters, "ApSepNonce", plist_new_data((const char*)sep_nonce, sep_nonce_size));
        free(sep_nonce);
    }
    
    plist_dict_set_item(parameters, "ApProductionMode", plist_new_bool(1));
    if (client->image4supported) {
        plist_dict_set_item(parameters, "ApSecurityMode", plist_new_bool(1));
        plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(1));
    } else {
        plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(0));
    }
    
    tss_parameters_add_from_manifest(parameters, build_identity);
    
    if (client->flags & FLAG_OTA_BLOB) {
        info("Trying to create request for OTA SHSH blob\n");
        plist_dict_remove_item(parameters, "UniqueBuildID");
        
        unsigned char* ubid;
        size_t ubid_size=0;
        get_ubid(client->device->product_type, &ubid, &ubid_size);
        if (ubid_size != 0){
            plist_dict_set_item(parameters, "UniqueBuildID", plist_new_data((const char*)ubid, ubid_size));
        } else {
            error("ERROR: Unable to find UniqueBuildID node for OTA SHSH blob\n");
            plist_free(parameters);
            return -1;
        }
    }
    
    /* create basic request */
    request = tss_request_new(NULL);
    if (request == NULL) {
        error("ERROR: Unable to create TSS request\n");
        plist_free(parameters);
        return -1;
    }
    
    /* add common tags from manifest */
    if (tss_request_add_common_tags(request, parameters, NULL) < 0) {
        error("ERROR: Unable to add common tags to TSS request\n");
        plist_free(request);
        plist_free(parameters);
        return -1;
    }
    
    /* add tags from manifest */
    if (tss_request_add_ap_tags(request, parameters, NULL, client) < 0) {
        error("ERROR: Unable to add common tags to TSS request\n");
        plist_free(request);
        plist_free(parameters);
        return -1;
    }
    
    if (client->image4supported) {
        /* add personalized parameters */
        if (tss_request_add_ap_img4_tags(request, parameters) < 0) {
            error("ERROR: Unable to add img4 tags to TSS request\n");
            plist_free(request);
            plist_free(parameters);
            return -1;
        }
    } else {
        /* add personalized parameters */
        if (tss_request_add_ap_img3_tags(request, parameters) < 0) {
            error("ERROR: Unable to add img3 tags to TSS request\n");
            plist_free(request);
            plist_free(parameters);
            return -1;
        }
    }
    
    if (client->mode->index == MODE_NORMAL) {
        /* normal mode; request baseband ticket aswell */
        plist_t pinfo = NULL;
        normal_get_preflight_info(client, &pinfo);
        if (pinfo) {
            plist_t node;
            node = plist_dict_get_item(pinfo, "Nonce");
            if (node) {
                plist_dict_set_item(parameters, "BbNonce", plist_copy(node));
            }
            node = plist_dict_get_item(pinfo, "ChipID");
            if (node) {
                plist_dict_set_item(parameters, "BbChipID", plist_copy(node));
            }
            node = plist_dict_get_item(pinfo, "CertID");
            if (node) {
                plist_dict_set_item(parameters, "BbGoldCertId", plist_copy(node));
            }
            node = plist_dict_get_item(pinfo, "ChipSerialNo");
            if (node) {
                plist_dict_set_item(parameters, "BbSNUM", plist_copy(node));
            }
            
            /* add baseband parameters */
            tss_request_add_baseband_tags(request, parameters, NULL);
        }
        client->preflight_info = pinfo;
    }
    
    /* send request and grab response */
    response = tss_request_send(request, client->tss_url);
    if (response == NULL) {
        info("ERROR: Unable to send TSS request\n");
        plist_free(request);
        plist_free(parameters);
        return -1;
    }
    
    info("Received SHSH blobs\n");
    if (client->flags & FLAG_RERESTORE) {
        client->tss_url = strdup("http://gs.apple.com/TSS/controller?action=2");
    }
    
    plist_free(request);
    plist_free(parameters);
    
    *tss = response;
    
    return 0;
}

void fixup_tss(plist_t tss)
{
    plist_t node;
    plist_t node2;
    node = plist_dict_get_item(tss, "RestoreLogo");
    if (node && (plist_get_node_type(node) == PLIST_DICT) && (plist_dict_get_size(node) == 0)) {
        node2 = plist_dict_get_item(tss, "AppleLogo");
        if (node2 && (plist_get_node_type(node2) == PLIST_DICT)) {
            plist_dict_remove_item(tss, "RestoreLogo");
            plist_dict_set_item(tss, "RestoreLogo", plist_copy(node2));
        }
    }
    node = plist_dict_get_item(tss, "RestoreDeviceTree");
    if (node && (plist_get_node_type(node) == PLIST_DICT) && (plist_dict_get_size(node) == 0)) {
        node2 = plist_dict_get_item(tss, "DeviceTree");
        if (node2 && (plist_get_node_type(node2) == PLIST_DICT)) {
            plist_dict_remove_item(tss, "RestoreDeviceTree");
            plist_dict_set_item(tss, "RestoreDeviceTree", plist_copy(node2));
        }
    }
    node = plist_dict_get_item(tss, "RestoreKernelCache");
    if (node && (plist_get_node_type(node) == PLIST_DICT) && (plist_dict_get_size(node) == 0)) {
        node2 = plist_dict_get_item(tss, "KernelCache");
        if (node2 && (plist_get_node_type(node2) == PLIST_DICT)) {
            plist_dict_remove_item(tss, "RestoreKernelCache");
            plist_dict_set_item(tss, "RestoreKernelCache", plist_copy(node2));
        }
    }
}

int build_manifest_get_identity_count(plist_t build_manifest) {
    // fetch build identities array from BuildManifest
    plist_t build_identities_array = plist_dict_get_item(build_manifest, "BuildIdentities");
    if (!build_identities_array || plist_get_node_type(build_identities_array) != PLIST_ARRAY) {
        error("ERROR: Unable to find build identities node\n");
        return -1;
    }
    
    // check and make sure this identity exists in buildmanifest
    return plist_array_get_size(build_identities_array);
}

int extract_component(const char* ipsw, const char* path, unsigned char** component_data, unsigned int* component_size)
{
    char* component_name = NULL;
    if (!ipsw || !path || !component_data || !component_size) {
        return -1;
    }
    
    component_name = strrchr(path, '/');
    if (component_name != NULL)
        component_name++;
    else
        component_name = (char*) path;
    
    info("Extracting %s...\n", component_name);
    if (ipsw_extract_to_memory(ipsw, path, component_data, component_size) < 0) {
        error("ERROR: Unable to extract %s from %s\n", component_name, ipsw);
        return -1;
    }
    
    return 0;
}

int personalize_component(const char *component_name, const unsigned char* component_data, unsigned int component_size, plist_t tss_response, unsigned char** personalized_component, unsigned int* personalized_component_size) {
    unsigned char* component_blob = NULL;
    unsigned int component_blob_size = 0;
    unsigned char* stitched_component = NULL;
    unsigned int stitched_component_size = 0;
    
    if (tss_response && tss_response_get_ap_img4_ticket(tss_response, &component_blob, &component_blob_size) == 0) {
        /* stitch ApImg4Ticket into IMG4 file */
        img4_stitch_component(component_name, component_data, component_size, component_blob, component_blob_size, &stitched_component, &stitched_component_size);
    } else {
        /* try to get blob for current component from tss response */
        if (tss_response && tss_response_get_blob_by_entry(tss_response, component_name, &component_blob) < 0) {
            debug("NOTE: No SHSH blob found for component %s\n", component_name);
        }
        
        if (component_blob != NULL) {
            if (img3_stitch_component(component_name, component_data, component_size, component_blob, 64, &stitched_component, &stitched_component_size) < 0) {
                error("ERROR: Unable to replace %s IMG3 signature\n", component_name);
                free(component_blob);
                return -1;
            }
        } else {
            info("Not personalizing component %s...\n", component_name);
            stitched_component = (unsigned char*)malloc(component_size);
            if (stitched_component) {
                stitched_component_size = component_size;
                memcpy(stitched_component, component_data, component_size);
            }
        }
    }
    free(component_blob);
    
    if (idevicerestore_keep_pers) {
        write_file(component_name, stitched_component, stitched_component_size);
    }
    
    *personalized_component = stitched_component;
    *personalized_component_size = stitched_component_size;
    return 0;
}

int build_manifest_check_compatibility(plist_t build_manifest, const char* product) {
    int res = -1;
    plist_t node = plist_dict_get_item(build_manifest, "SupportedProductTypes");
    if (!node || (plist_get_node_type(node) != PLIST_ARRAY)) {
        debug("%s: ERROR: SupportedProductTypes key missing\n", __func__);
        debug("%s: WARNING: If attempting to install iPhoneOS 2.x, be advised that Restore.plist does not contain the", __func__);
        debug("%s: WARNING: key 'SupportedProductTypes'. Recommendation is to manually add it to the Restore.plist.", __func__);
        return -1;
    }
    uint32_t pc = plist_array_get_size(node);
    uint32_t i;
    for (i = 0; i < pc; i++) {
        plist_t prod = plist_array_get_item(node, i);
        if (plist_get_node_type(prod) == PLIST_STRING) {
            char *val = NULL;
            plist_get_string_val(prod, &val);
            if (val && (strcmp(val, product) == 0)) {
                res = 0;
                free(val);
                break;
            }
        }
    }
    return res;
}

void build_manifest_get_version_information(plist_t build_manifest, struct idevicerestore_client_t* client) {
    plist_t node = NULL;
    client->version = NULL;
    client->build = NULL;
    
    node = plist_dict_get_item(build_manifest, "ProductVersion");
    if (!node || plist_get_node_type(node) != PLIST_STRING) {
        error("ERROR: Unable to find ProductVersion node\n");
        return;
    }
    plist_get_string_val(node, &client->version);
    
    node = plist_dict_get_item(build_manifest, "ProductBuildVersion");
    if (!node || plist_get_node_type(node) != PLIST_STRING) {
        error("ERROR: Unable to find ProductBuildVersion node\n");
        return;
    }
    plist_get_string_val(node, &client->build);
    
    client->build_major = strtoul(client->build, NULL, 10);
}

void build_identity_print_information(plist_t build_identity) {
    char* value = NULL;
    plist_t info_node = NULL;
    plist_t node = NULL;
    
    info_node = plist_dict_get_item(build_identity, "Info");
    if (!info_node || plist_get_node_type(info_node) != PLIST_DICT) {
        error("ERROR: Unable to find Info node\n");
        return;
    }
    
    node = plist_dict_get_item(info_node, "Variant");
    if (!node || plist_get_node_type(node) != PLIST_STRING) {
        error("ERROR: Unable to find Variant node\n");
        return;
    }
    plist_get_string_val(node, &value);
    
    info("Variant: %s\n", value);
    free(value);
    
    node = plist_dict_get_item(info_node, "RestoreBehavior");
    if (!node || plist_get_node_type(node) != PLIST_STRING) {
        error("ERROR: Unable to find RestoreBehavior node\n");
        return;
    }
    plist_get_string_val(node, &value);
    
    if (!strcmp(value, "Erase"))
        info("This restore will erase your device data.\n");
    
    if (!strcmp(value, "Update"))
        info("This restore will update your device without losing data.\n");
    
    free(value);
    
    info_node = NULL;
    node = NULL;
}

int build_identity_has_component(plist_t build_identity, const char* component) {
    plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
    if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
        return -1;
    }
    
    plist_t component_node = plist_dict_get_item(manifest_node, component);
    if (!component_node || plist_get_node_type(component_node) != PLIST_DICT) {
        return -1;
    }
    
    return 0;
}

int build_identity_get_component_path(plist_t build_identity, const char* component, char** path) {
    char* filename = NULL;
    
    plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
    if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
        error("ERROR: Unable to find manifest node\n");
        if (filename)
            free(filename);
        return -1;
    }
    
    plist_t component_node = plist_dict_get_item(manifest_node, component);
    if (!component_node || plist_get_node_type(component_node) != PLIST_DICT) {
        error("ERROR: Unable to find component node for %s\n", component);
        if (filename)
            free(filename);
        return -1;
    }
    
    plist_t component_info_node = plist_dict_get_item(component_node, "Info");
    if (!component_info_node || plist_get_node_type(component_info_node) != PLIST_DICT) {
        error("ERROR: Unable to find component info node for %s\n", component);
        if (filename)
            free(filename);
        return -1;
    }
    
    plist_t component_info_path_node = plist_dict_get_item(component_info_node, "Path");
    if (!component_info_path_node || plist_get_node_type(component_info_path_node) != PLIST_STRING) {
        error("ERROR: Unable to find component info path node for %s\n", component);
        if (filename)
            free(filename);
        return -1;
    }
    plist_get_string_val(component_info_path_node, &filename);
    
    *path = filename;
    return 0;
}

const char* get_component_name(const char* filename) {
    if (!strncmp(filename, "LLB", 3)) {
        return "LLB";
    } else if (!strncmp(filename, "iBoot", 5)) {
        return "iBoot";
    } else if (!strncmp(filename, "DeviceTree", 10)) {
        return "DeviceTree";
    } else if (!strncmp(filename, "applelogo", 9)) {
        return "AppleLogo";
    } else if (!strncmp(filename, "liquiddetect", 12)) {
        return "Liquid";
    } else if (!strncmp(filename, "recoverymode", 12)) {
        return "RecoveryMode";
    } else if (!strncmp(filename, "batterylow0", 11)) {
        return "BatteryLow0";
    } else if (!strncmp(filename, "batterylow1", 11)) {
        return "BatteryLow1";
    } else if (!strncmp(filename, "glyphcharging", 13)) {
        return "BatteryCharging";
    } else if (!strncmp(filename, "glyphplugin", 11)) {
        return "BatteryPlugin";
    } else if (!strncmp(filename, "batterycharging0", 16)) {
        return "BatteryCharging0";
    } else if (!strncmp(filename, "batterycharging1", 16)) {
        return "BatteryCharging1";
    } else if (!strncmp(filename, "batteryfull", 11)) {
        return "BatteryFull";
    } else if (!strncmp(filename, "needservice", 11)) {
        return "NeedService";
    } else if (!strncmp(filename, "SCAB", 4)) {
        return "SCAB";
    } else if (!strncmp(filename, "sep-firmware", 12)) {
        return "RestoreSEP";
    } else {
        error("WARNING: Unhandled component '%s'", filename);
        return filename;
    }
}
