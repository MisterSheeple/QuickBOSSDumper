#include "installer.h"
#include "safewrite.h"
#include "validator.h"
#include "unittype.h"
#include "nand.h"
#include "sdmmc.h"
#include "ui.h"
#include "qff.h"
#include "hid.h"
#include "sha.h"
#include "disadiff.h"
#include "sddata.h"

#define COLOR_STATUS(s) ((s == STATUS_GREEN) ? COLOR_BRIGHTGREEN : (s == STATUS_YELLOW) ? COLOR_BRIGHTYELLOW : (s == STATUS_RED) ? COLOR_RED : COLOR_DARKGREY)

#define MIN_SD_FREE (8 * 1024 * 1024) // 8MB

#define MAX_STAGE2_SIZE   0x89A00

#define STATUS_GREY    -1
#define STATUS_GREEN    0
#define STATUS_YELLOW   1
#define STATUS_RED      2

static int  statusSdCard       = STATUS_GREY;
static int  statusSector       = STATUS_GREY;
static int  statusDump         = STATUS_GREY;
static char msgSdCard[64]      = "not started";
static char msgSector[64]      = "not started";
static char msgDump[64]        = "not started";
static char msgDump2[70]       = "";
    
size_t FileGetData(const char* path, void* data, size_t size, size_t foffset) {
    UINT br;
    if (fx_qread(path, data, foffset, size, &br) != FR_OK) br = 0;
    return br;
}

u32 ShowInstallerStatus(void) {
    const u32 pos_xb = 10;
    const u32 pos_x0 = pos_xb + 4;
    const u32 pos_x1 = pos_x0 + (17*FONT_WIDTH_EXT);
    const u32 pos_yb = 10;
    const u32 pos_yu = 230;
    const u32 pos_y0 = pos_yb + 50;
    const u32 stp = 14;
    
    // DrawStringF(BOT_SCREEN, pos_xb, pos_yb, COLOR_STD_FONT, COLOR_STD_BG, "SafeB9SInstaller v" VERSION "\n" "-----------------------" "\n" "https://github.com/d0k3/SafeB9SInstaller");
    DrawStringF(BOT_SCREEN, pos_xb, pos_yb, COLOR_STD_FONT, COLOR_STD_BG, APP_TITLE "\n" "%.*s" "\n" APP_URL,
        strnlen(APP_TITLE, 32), "--------------------------------");
    
    DrawStringF(BOT_SCREEN, pos_x0, pos_y0 + (1*stp), COLOR_STD_FONT, COLOR_STD_BG, "MicroSD Card   -");
    //DrawStringF(BOT_SCREEN, pos_x0, pos_y0 + (2*stp), COLOR_STD_FONT, COLOR_STD_BG, "Secret Sector  -");
    DrawStringF(BOT_SCREEN, pos_x0, pos_y0 + (3*stp), COLOR_STD_FONT, COLOR_STD_BG, "BOSS Dump      -");
    DrawStringF(BOT_SCREEN, pos_x0, pos_y0 + (4*stp), COLOR_STD_FONT, COLOR_STD_BG, msgDump2);

    DrawStringF(BOT_SCREEN, pos_x1, pos_y0 + (1*stp), COLOR_STATUS(statusSdCard) , COLOR_STD_BG, "%-21.21s", msgSdCard );
    //DrawStringF(BOT_SCREEN, pos_x1, pos_y0 + (2*stp), COLOR_STATUS(statusSector) , COLOR_STD_BG, "%-21.21s", msgSector );
    DrawStringF(BOT_SCREEN, pos_x1, pos_y0 + (3*stp), COLOR_STATUS(statusDump)   , COLOR_STD_BG, "%-21.21s", msgDump   );
    
    DrawStringF(BOT_SCREEN, pos_xb, pos_yu - 10, COLOR_STD_FONT, COLOR_STD_BG, APP_USAGE);
    return 0;
}

u32 QuickBOSSDumper(void) {
    
    // initialization
    ShowString("Initializing, please wait...");
    
    // step #1 - init/check SD card
    snprintf(msgSdCard, 64, "checking...");
    statusSdCard = STATUS_YELLOW;
    ShowInstallerStatus();
    u64 sdFree = 0;
    u64 sdTotal = 0;
    if ((fs_init() != FR_OK) ||
        (f_getfreebyte("0:", &sdFree) != FR_OK) ||
        (f_gettotalbyte("0:", &sdTotal) != FR_OK)) {
        snprintf(msgSdCard, 64, "init failed");
        statusSdCard = STATUS_RED;
        return 1;
    }
    InitNandCrypto(); // for sector0x96 crypto and NAND drives
    snprintf(msgSdCard, 64, "%lluMB/%lluMB free", sdFree / (1024 * 1024), sdTotal / (1024 * 1024));
    statusSdCard = (sdFree < MIN_SD_FREE) ? STATUS_RED : STATUS_GREEN;
    ShowInstallerStatus();
    if (sdFree < MIN_SD_FREE) return 1;
    // SD card okay!
    
    // // step #2 - check secret_sector.bin file
    // u8 secret_sector[0x200] = { 0 };
    // if (IS_A9LH && !IS_SIGHAX && !IS_O3DS) {
    //     snprintf(msgSector, 64, "checking...");
    //     statusSector = STATUS_YELLOW;
    //     ShowInstallerStatus();
    //     if ((f_qread(NAME_SECTOR0x96, secret_sector, 0, 0x200, &bt) != FR_OK) || (bt != 0x200)) {
    //         snprintf(msgSector, 64, "file not found");
    //         statusSector = STATUS_RED;
    //         return 1;
    //     }
    //     if (ValidateSector(secret_sector) != 0) {
    //         snprintf(msgSector, 64, "invalid file");
    //         statusSector = STATUS_RED;
    //         return 1;
    //     }
    //     snprintf(msgSector, 64, "loaded & verified");
    // } else snprintf(msgSector, 64, "not required");
    // statusSector = STATUS_GREEN;
    // ShowInstallerStatus();
    // // secret_sector.bin okay or not required!
    
    
    // step #3 - dump BOSS save
    snprintf(msgDump, 64, "dumping...");
    statusDump = STATUS_YELLOW;

    // from gm9 to get the path we need
    //char bossSavePath[256];
    u8 sd_keyy[0x10] __attribute__((aligned(4)));
    char path_movable[32];
    u32 sha256sum[8];
    snprintf(path_movable, sizeof(path_movable), "1:/private/movable.sed");
    if (FileGetData(path_movable, sd_keyy, 0x10, 0x110) == 0x10) {
        sha_quick(sha256sum, sd_keyy, 0x10, SHA256_MODE);
        DIR ctrnandRoot;
        int result;
        if (result = fa_opendir(&ctrnandRoot, "1:/private") == FR_NO_PATH) snprintf(msgSdCard, 64, "nand mounting broken");
        else snprintf(msgSdCard, 64, "res: %d", result);
    }
    else memset(sha256sum, 0, 32);

    snprintf(msgDump2, sizeof(msgDump2), "1:/data/%08lx%08lx%08lx%08lx/sysdata/00010034/00000000",
    sha256sum[0], sha256sum[1], sha256sum[2], sha256sum[3]);

    //if (f_stat())

    // most code between here and next comment is modified from gm9 at https://github.com/d0k3/GodMode9/blob/master/arm9/source/virtual/vdisadiff.c#L150
    DisaDiffRWInfo partitionAInfo;
    DisaDiffRWInfo partitionBInfo;
    bool partitionAValid = true;
    bool partitionBValid = false;

    if ((GetDisaDiffRWInfo(msgDump2, &partitionAInfo, false) != 0) ||
        (!(partitionAInfo.dpfs_lvl2_cache = (u8*) malloc(partitionAInfo.size_dpfs_lvl2)) ||
        (BuildDisaDiffDpfsLvl2Cache(msgDump2, &partitionAInfo, partitionAInfo.dpfs_lvl2_cache, partitionAInfo.size_dpfs_lvl2) != 0))) {
        free(partitionAInfo.dpfs_lvl2_cache);
        partitionAValid = false;
   }

    if ((GetDisaDiffRWInfo(msgDump2, &partitionBInfo, true) == 0)) {
        partitionBValid = true;
        if (!(partitionBInfo.dpfs_lvl2_cache = (u8*) malloc(partitionBInfo.size_dpfs_lvl2)) ||
            (BuildDisaDiffDpfsLvl2Cache(msgDump2, &partitionBInfo, partitionBInfo.dpfs_lvl2_cache, partitionBInfo.size_dpfs_lvl2) != 0)) {
            if (partitionAInfo.dpfs_lvl2_cache) free(partitionAInfo.dpfs_lvl2_cache);
            partitionBValid = false;
        }
    }

    if (partitionAValid) {
        char *buffer = malloc(partitionAInfo.size_ivfc_lvl4);
        if (!buffer) {
            snprintf(msgDump, 64, "dump failed code 0011"); // couldnt allocate memory (partitionA)
            statusDump = STATUS_RED;
        } else {
            if (ReadDisaDiffIvfcLvl4(msgDump2, &partitionAInfo, 0, partitionAInfo.size_ivfc_lvl4, buffer) != 0) {
                FIL fp;

                if (f_open(&fp, "0:/partitionA.bin", FA_WRITE) == FR_OK) f_write(&fp, buffer, partitionAInfo.size_ivfc_lvl4, NULL);
                else {
                    snprintf(msgDump, 64, "dump failed code 0012"); // couldnt write file to sd (partitionA)
                    statusDump = STATUS_RED;
                }
                
                f_close(&fp);
            } else {
                snprintf(msgDump, 64, "dump failed code 0013"); // couldnt read partition (partitionA)
                statusDump = STATUS_RED;
            }
        }
        
        if (buffer) free(buffer);
    }

    if (partitionBValid) {
        char *buffer = malloc(partitionBInfo.size_ivfc_lvl4);
        if (!buffer) {
            snprintf(msgDump, 64, "dump failed code 0021"); // couldnt allocate memory (partitionB)
            statusDump = STATUS_RED;
        } else {
            if (ReadDisaDiffIvfcLvl4(msgDump2, &partitionBInfo, 0, partitionBInfo.size_ivfc_lvl4, buffer) != 0) {
                FIL fp;

                if (f_open(&fp, "0:/partitionB.bin", FA_WRITE) == FR_OK) f_write(&fp, buffer, partitionBInfo.size_ivfc_lvl4, NULL);
                else {
                    snprintf(msgDump, 64, "dump failed code 0022"); // couldnt write file to sd (partitionB)
                    statusDump = STATUS_RED;
                }

                f_close(&fp);
            } else {
                snprintf(msgDump, 64, "dump failed code 0023"); // couldnt read partition (partitionB)
                statusDump = STATUS_RED;
            }
        }

        if (buffer) free(buffer);
    }

    if (!partitionAValid && !partitionBValid) {
        snprintf(msgDump, 64, "dump failed code 0100"); // neither partitionA nor partitionB are valid
        statusDump = STATUS_RED;
        return 1;
    }

    if (statusDump != STATUS_RED) {
        snprintf(msgDump, 64, "dump complete");
        statusDump = STATUS_GREEN;
    }
    ShowInstallerStatus();
    
    return 0;
}
