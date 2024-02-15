#include "sddata.h"
#include "aes.h"
#include "sha.h"

#define DSIWARE_MAGIC "Nintendo DSiWare" // must be exactly 16 chars
#define NUM_ALIAS_DRV 2
#define NUM_FILCRYPTINFO 16

typedef struct {
    FIL* fptr;
    u8 ctr[16];
    u8 keyy[16];
} __attribute__((packed, aligned(4))) FilCryptInfo;

static FilCryptInfo filcrypt[NUM_FILCRYPTINFO] = { 0 };

static char alias_drv[NUM_ALIAS_DRV]; // 1 char ASCII drive number of the alias drive / 0x00 if unused
static char alias_path[NUM_ALIAS_DRV][128]; // full path to resolve the alias into

static u8 sd_keyy[NUM_ALIAS_DRV][16] __attribute__((aligned(4))); // key Y belonging to alias drive

int alias_num (const TCHAR* path) {
    int num = -1;
    for (u32 i = 0; i < NUM_ALIAS_DRV; i++) {
        if (!alias_drv[i]) continue;
        if ((path[0] == alias_drv[i]) && (path[1] == ':')) {
            num = i;
            break;
        }
    }
    return num;
}

void dealias_path (TCHAR* alias, const TCHAR* path) {
    int num = alias_num(path);
    u32 p_offs = (path[2] == '/' && ((path[3] == '/') || (path[3] == '\0'))) ? 3 : 2;
    if (num >= 0) // set alias (alias is assumed to be 256 byte!)
        snprintf(alias, 256, "%s%s", alias_path[num], path + p_offs);
    else snprintf(alias, 256, "%s", path);
}

FilCryptInfo* fx_find_cryptinfo(FIL* fptr) {
    FilCryptInfo* info = NULL;

    for (u32 i = 0; i < NUM_FILCRYPTINFO; i++) {
        if (!info && !filcrypt[i].fptr) // use first free
            info = &filcrypt[i];
        if (fptr == filcrypt[i].fptr) {
            info = &filcrypt[i];
            break;
        }
    }

    return info;
}

FRESULT fx_open (FIL* fp, const TCHAR* path, BYTE mode) {
    int num = alias_num(path);
    FilCryptInfo* info = fx_find_cryptinfo(fp);
    if (info) info->fptr = NULL;

    if (info && (num >= 0)) {
        // DSIWare Export, mark with the magic number
        if (strncmp(path + 2, "/" DSIWARE_MAGIC, 1 + 16) == 0) {
            memcpy(info->ctr, DSIWARE_MAGIC, 16);
        } else {
            // get AES counter, see: http://www.3dbrew.org/wiki/Extdata#Encryption
            // path is the part of the full path after //Nintendo 3DS/<ID0>/<ID1>
            u8 hashstr[256] __attribute__((aligned(4)));
            u8 sha256sum[32];
            u32 plen = 0;
            // poor man's ASCII -> UTF-16 / uppercase -> lowercase
            for (plen = 0; plen < 128; plen++) {
                u8 symbol = path[2 + plen];
                if ((symbol >= 'A') && (symbol <= 'Z')) symbol += ('a' - 'A');
                hashstr[2*plen] = symbol;
                hashstr[2*plen+1] = 0;
                if (symbol == 0) break;
            }
            sha_quick(sha256sum, hashstr, (plen + 1) * 2, SHA256_MODE);
            for (u32 i = 0; i < 16; i++)
                info->ctr[i] = sha256sum[i] ^ sha256sum[i+16];
        }
        // copy over key, FIL pointer
        memcpy(info->keyy, sd_keyy[num], 16);
        info->fptr = fp;
    }

    return fa_open(fp, path, mode);
}

FRESULT fx_read (FIL* fp, void* buff, UINT btr, UINT* br) {
    FilCryptInfo* info = fx_find_cryptinfo(fp);
    FSIZE_t off = f_tell(fp);
    FRESULT res = f_read(fp, buff, btr, br);
    if (info && info->fptr) {
        setup_aeskeyY(0x34, info->keyy);
        use_aeskey(0x34);
        if (memcmp(info->ctr, DSIWARE_MAGIC, 16) == 0) return FR_DENIED;
        else ctr_decrypt_byte(buff, buff, btr, off, AES_CNT_CTRNAND_MODE, info->ctr);
    }
    return res;
}

FRESULT fx_write (FIL* fp, const void* buff, UINT btw, UINT* bw) {
    FilCryptInfo* info = fx_find_cryptinfo(fp);
    FSIZE_t off = f_tell(fp);
    FRESULT res = FR_OK;

    if (info && info->fptr) {
        if (memcmp(info->ctr, DSIWARE_MAGIC, 16) == 0) return FR_DENIED;
        void* crypt_buff = (void*) malloc(min(btw, 0x100000));
        if (!crypt_buff) return FR_DENIED;

        setup_aeskeyY(0x34, info->keyy);
        use_aeskey(0x34);
        *bw = 0;
        for (UINT p = 0; (p < btw) && (res == FR_OK); p += 0x100000) {
            UINT pcount = min(0x100000, (btw - p));
            UINT bwl = 0;
            memcpy(crypt_buff, (u8*) buff + p, pcount);
            ctr_decrypt_byte(crypt_buff, crypt_buff, pcount, off + p, AES_CNT_CTRNAND_MODE, info->ctr);
            res = f_write(fp, (const void*) crypt_buff, pcount, &bwl);
            *bw += bwl;
        }

        free(crypt_buff);
    } else res = f_write(fp, buff, btw, bw);
    return res;
}

FRESULT fx_qread (const TCHAR* path, void* buff, FSIZE_t ofs, UINT btr, UINT* br) {
    FIL fp;
    FRESULT res;
    UINT brt = 0;

    res = fx_open(&fp, path, FA_READ | FA_OPEN_EXISTING);
    if (res != FR_OK) return res;

    res = f_lseek(&fp, ofs);
    if (res != FR_OK) {
        fx_close(&fp);
        return res;
    }

    res = fx_read(&fp, buff, btr, &brt);
    fx_close(&fp);

    if (br) *br = brt;
    else if ((res == FR_OK) && (brt != btr)) res = FR_DENIED;

    return res;
}

FRESULT fx_qwrite (const TCHAR* path, const void* buff, FSIZE_t ofs, UINT btw, UINT* bw) {
    FIL fp;
    FRESULT res;
    UINT bwt = 0;

    res = fx_open(&fp, path, FA_WRITE | FA_OPEN_ALWAYS);
    if (res != FR_OK) return res;

    res = f_lseek(&fp, ofs);
    if (res != FR_OK) {
        fx_close(&fp);
        return res;
    }

    res = fx_write(&fp, buff, btw, &bwt);
    fx_close(&fp);

    if (bw) *bw = bwt;
    else if ((res == FR_OK) && (bwt != btw)) res = FR_DENIED;

    return res;
}

FRESULT fx_close (FIL* fp) {
    FilCryptInfo* info = fx_find_cryptinfo(fp);
    if (info) memset(info, 0, sizeof(FilCryptInfo));
    return f_close(fp);
}

FRESULT fa_open (FIL* fp, const TCHAR* path, BYTE mode) {
    TCHAR alias[256];
    dealias_path(alias, path);
    return f_open(fp, alias, mode);
}

FRESULT fa_opendir (DIR* dp, const TCHAR* path) {
    TCHAR alias[256];
    dealias_path(alias, path);
    return f_opendir(dp, alias);
}

FRESULT fa_mkdir (const TCHAR* path) {
    TCHAR alias[256];
    dealias_path(alias, path);
    return f_mkdir(alias);
}

FRESULT fa_stat (const TCHAR* path, FILINFO* fno) {
    TCHAR alias[256];
    dealias_path(alias, path);
    return f_stat(alias, fno);
}

FRESULT fa_unlink (const TCHAR* path) {
    TCHAR alias[256];
    dealias_path(alias, path);
    return f_unlink(alias);
}