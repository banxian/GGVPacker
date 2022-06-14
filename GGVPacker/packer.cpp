#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <direct.h>
#include <conio.h>
#include <sys/stat.h>
#include <io.h>
#include <fcntl.h>
#include <time.h>
#include <mbstring.h>


#pragma pack(push, 1)
struct vdir_s
{
    char prefix[8];
    char content[16];
    char eor;
    char sum;
};

struct lenkey_s
{
    uint8_t keylen;
    uint8_t key[0];
};

struct encheader_s
{
    uint16_t keydelta;
    vdir_s dir;
    vdir_s file;
    vdir_s attr;
};
#pragma pack(pop)

extern "C" const unsigned char keytab[256][256];
#ifdef DECTAB
extern "C" const unsigned char dectab[256][256];
#endif

int errprintf(__in_z __format_string const char * _Format, ...);
void quickdump(unsigned int addr, const unsigned char *data, unsigned int amount);
int random(int from, int to);
BYTE ByteDecode(BYTE key, BYTE source);
bool CheckDirFileAttr(vdir_s* cp, int type);
void FillDirChecksum(vdir_s* dir);
uint8_t ByteEncode(uint8_t key, uint8_t index);
bool endswith(const char* str, const char* substr);

#define exitclose(code) \
    _close(inputf);\
    return code;

#define exitclose2(code) \
    _close(inputf);\
    _close(outputf);\
    return code;


int main(int argc, char* argv[])
{
    const char* inputfname = 0;
    const char* outputfname = 0;
    char* basename = 0;
    bool decode = false;
    bool verbose = false;
    if (argc < 3) {
        printf("packer input.bin output.bin {appname} {-decode} {-v}\n");
        return -1;
    }
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "-decode") == 0) {
            decode = true;
        } else if (_stricmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (inputfname == 0) {
            inputfname = argv[i];
        } else if (outputfname == 0) {
            outputfname = argv[i];
        } else {
            basename = argv[i];
        }
    }
    if (inputfname == 0 || outputfname == 0) {
        printf("missing file path\n");
        return -1;
    }
    struct _stat st;
    if (_stat(inputfname, &st) == -1) {
        errprintf("stat input file failed!\n");
        return -1;
    }
    _off_t filesize = st.st_size;
    int inputf = _open(inputfname, O_RDONLY | O_BINARY);
    // 1+8+80+8
    // 3+8
    if ((decode && filesize < 97) || filesize < 11) {
        errprintf("input file is too small!\n");
        exitclose(-1);
    }
    if (decode) {
        uint8_t keylen;
        read(inputf, &keylen, sizeof(keylen));
        if (keylen > 24 || keylen < 8) {
            errprintf("wrong key length %d\n", keylen);
        }
        uint8_t buflen = keylen + sizeof(encheader_s); // key,position,dir,file,attr
        uint8_t *buf = (uint8_t *)malloc(buflen);
        encheader_s* header = (encheader_s*)&buf[keylen];
        read(inputf, buf, buflen);
        int keypos = 1 + buflen + header->keydelta;
        // keypos取值范围从magic后到代码结束
        if ((keylen + keypos) > filesize || header->keydelta < 3) {
            errprintf("xorkey out of range!\n");
            free(buf);
            exitclose(-1);
        }
        int magicpos = 1 + keylen + sizeof(encheader_s);
        int contentsize = filesize - magicpos; // 包含magic的代码大小
        uint8_t* temp = (uint8_t*)malloc(contentsize);
        read(inputf, temp, contentsize);

        uint8_t* xorer = &temp[header->keydelta];
        for (int i = 0; i < keylen; i++) {
            buf[i] ^= xorer[i];
        }
        //if (verbose) {
        //    printf("key:\n");
        //    quickdump(0, buf, keylen);
        //}
        // 当前二级密匙序号
        int curkey = 0;
        // 解密dir,file,attr
        for (uint8_t* ptr = (uint8_t*)&header->dir; ptr != (uint8_t*)(header + 1); ptr++) {
            *ptr = ByteDecode(buf[(curkey++) % keylen], *ptr);
        }
        // check dir,file,attr
        if (!(CheckDirFileAttr(&header->dir, 1) &&
            CheckDirFileAttr(&header->file, 2) && CheckDirFileAttr(&header->attr, 3))) {
            errprintf("wrong encheader!\n");
            quickdump(0, (unsigned char*)header, sizeof(*header));
            free(temp);
            free(buf);
            exitclose(-1);
        }
        // current..keypos
        for (int i = 0; i < keypos - magicpos; i++) {
            temp[i] = ByteDecode(buf[(curkey++) % keylen], temp[i]);
        }
        // keypos+keylen..contentsize
        for (int i = keypos + keylen - magicpos; i < contentsize; i++) {
            temp[i] = ByteDecode(buf[(curkey++) % keylen], temp[i]);
        }
        lseek(inputf, 1 + keylen + sizeof(encheader_s), 0);

        // check 0xAA
        if (temp[0] != 0xAA || temp[1] != 0xA5 || temp[2] != 0x5A) {
            errprintf("magic error!\n");
            free(temp);
            free(buf);
            exitclose(-1);
        }
        int outputf = _open(outputfname, O_CREAT | O_TRUNC | O_RDWR | O_BINARY, S_IREAD | S_IWRITE);
        if (endswith(inputfname, ".tmp") || endswith(inputfname, ".raw")) {
            // 如果是tmp格式, 保存dir,file,attr给payload用
            write(outputf, &header->dir.content, 16); // Application
            write(outputf, &header->file.content, 16); // blink.bin
            write(outputf, &header->attr.content, 16); // 000300
        }
        write(outputf, temp, contentsize);
        _close(outputf);
        free(temp);
        free(buf);
    } else {
        uint8_t* temp = (uint8_t*)malloc(filesize);
        read(inputf, temp, filesize);
        // 0x30+3+8
        bool tmpmode = (filesize >= 0x3B && temp[0x30] == 0xAA && temp[0x31] == 0xA5 && temp[0x32] == 0x5A);
        bool codmode = (temp[0] == 0xAA && temp[1] == 0xA5 && temp[2] == 0x5A);
        if (tmpmode == false && codmode == false) {
            errprintf("bad input file!\n");
            free(temp);
            exitclose(-1);
        }
        unsigned char keylen = random(8, 24);
        unsigned char keydelta = random(3, filesize - keylen); // 相对于代码文件的偏移(从AAA55A magic末尾开始)
        lenkey_s* key = (lenkey_s*)malloc(keylen + 1);
        key->keylen = keylen;
        for (int i = 0; i < keylen; i++) {
            key->key[i] = random(0, 255);
        }
        encheader_s header;
        header.keydelta = keydelta;
        memcpy(&header.dir, "ggvroot/Application     ", 8 + 16);
        memcpy(header.file.prefix, "ggvfile/", 8);
        memcpy(header.attr.prefix, "ggvattr/", 8);
        if (codmode) {
            // 生成文曲星上文件名, 长度10.3
            bool freebase = basename == 0;
            if (freebase) {
                basename = (char*)malloc(strlen(inputfname));
                _splitpath(inputfname, 0, 0, basename, 0);
            }
            size_t baselen = strlen(basename);
            if (strlen(basename) <= 10) {
                strcpy(header.file.content, basename);
            } else {
                _mbsnbcpy((unsigned char*)header.file.content, (unsigned char*)basename, 10);
                baselen = strlen(header.file.content);
            }
            if (freebase) {
                free(basename);
            }
            strcat(header.file.content, ".bin");
            memset(&header.file.content[baselen + 4], ' ', 16 - baselen - 4);
            memset(header.attr.content, 0xFF, 16);
            *(uint16_t*)&header.attr.content[0] = 0xDFEF; // RWX
            *(uint16_t*)&header.attr.content[8] = filesize;
            header.attr.content[10] = filesize >> 16;
        } else {
            memcpy(header.dir.content, &temp[0], 16);
            memcpy(header.file.content, &temp[0x10], 16);
            memcpy(header.attr.content, &temp[0x20], 16);
        }
        FillDirChecksum(&header.dir);
        FillDirChecksum(&header.file);
        FillDirChecksum(&header.attr);
        if (verbose) {
            printf("encheader:\n");
            quickdump(0, (unsigned char*)&header, sizeof(header));
        }

        int curkey = 0;
        // 加密dir,file,attr
        for (uint8_t* ptr = (uint8_t*)&header.dir; ptr != (uint8_t*)(&header + 1); ptr++) {
            *ptr = ByteEncode(key->key[(curkey++) % keylen], *ptr);
        }
        int start = codmode?0:0x30;
        uint8_t* body = temp + start;
        // current..keypos
        for (int i = 0; i < keydelta; i++) {
            body[i] = ByteEncode(key->key[(curkey++) % keylen], body[i]);
        }
        // keypos+keylen..contentsize
        for (int i = keydelta + keylen; i < filesize; i++) {
            body[i] = ByteEncode(key->key[(curkey++) % keylen], body[i]);
        }
        for (int i = 0; i < keylen; i++) {
            key->key[i] ^= body[i + keydelta];
        }
        int outputf = _open(outputfname, O_CREAT | O_TRUNC | O_RDWR | O_BINARY, S_IREAD | S_IWRITE);
        write(outputf, key, 1 + keylen);
        write(outputf, &header, sizeof(header));
        write(outputf, body, filesize - start);
        close(outputf);
        free(temp);
        free(key);
    }

    _close(inputf);
    return 0;
}

BYTE ByteDecode(BYTE key, BYTE source)
{
#ifdef DECTAB
    return dectab[key][index];
#else
    for (int index = 0; index < 256; index++) {
        if (keytab[key][index] == source) {
            return index;
        }
    }
    return 0;
#endif
}

uint8_t ByteEncode(uint8_t key, uint8_t index)
{
    return keytab[key][index];
}

bool CheckDirFileAttr(vdir_s* cp, int type)
{
    switch (type) {
    case 1:
        // check dir
        if (memcmp(cp, "ggvroot/", 8))
            return false;
        break;
    case 2:
        // check file
        if (memcmp(cp, "ggvfile/", 8))
            return false;
        break;
    case 3:
        // check attr
        if (memcmp(cp, "ggvattr/", 8))
            return false;
        break;
    }
    uint8_t eor = cp->eor, sum = cp->sum;
    for (int i = 0; i < sizeof(cp->content); i++) {
        eor ^= cp->content[i];
        sum -= cp->content[i];
    }
    return eor == 0 && sum == 0;
}

void FillDirChecksum(vdir_s* dir)
{
    dir->eor = 0;
    dir->sum = 0;
    for (int i = 0; i < sizeof(dir->content); i++) {
        dir->eor ^= dir->content[i];
        dir->sum += dir->content[i];
    }
}

int errprintf(__in_z __format_string const char * _Format, ...)
{
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    GetConsoleScreenBufferInfo(hCon, &info);
    SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_INTENSITY);
    va_list va;
    va_start(va, _Format);
    int len = vfprintf(stderr, _Format, va);
    va_end(va);
    SetConsoleTextAttribute(hCon, info.wAttributes);

    return len;
}

static bool randomized = false;
int random(int from, int to) {
    int result;
    if (!randomized) {
        srand(GetTickCount());
        randomized = true;
    }
    result = rand()%(to - from + 1) + from;
    return result;
}

unsigned char Nibble2Hex(unsigned char num) {
    if (num < 10) {
        return num + '0';
    } else {
        return num + '7';
    }
}

//00004000: 00 00 00 00 00 00 00 00  02 00 BF D7 04 00 00 00  | ................
//012345678 0         0         0  345    0         0        90 2             78     
void quickdump(unsigned int addr, const unsigned char *data, unsigned int amount)
{
    char line[78];
    const unsigned char* ptr = data;
    int fullline = amount / 16;
    int rowcount = fullline;
    int last = amount % 16;
    if (last) {
        rowcount++;
    }
    line[8] = ':';
    line[9] = ' ';
    line[34] = ' ';
    line[59] = '|';
    line[60] = ' ';
    line[77] = 0;
    for (int y = 0; y < rowcount; y++) {
        unsigned vaddr = ptr - data + addr;
        for (int i = 8; i; i--) {
            line[i - 1] = Nibble2Hex(vaddr & 0xF);
            vaddr >>= 4;
        }
        unsigned pos = 10;
        int w = (!last || y != rowcount - 1)?16:last;
        for (int x = 0; x < w; x++, ptr++) {
            unsigned char c = *ptr;
            if (c == 0) {
                *(unsigned short*)&line[pos] = '00';
                pos += 2;
            } else if (c == 0xFF) {
                *(unsigned short*)&line[pos] = 'FF';
                pos += 2;
            } else {
                line[pos++] = Nibble2Hex(c >> 4);
                line[pos++] = Nibble2Hex(c & 0xF);
            }
            line[pos++] = ' ';
            if (x == 7) {
                pos++;
            }
            line[61 + x] = (c >= ' ' && c <= '~')?c:'.';
        }
        if (w != 16) {
            line[61 + last] = 0;
        }
        puts(line);
    }
}

bool endswith(const char* str, const char* substr)
{
    size_t sublen = strlen(substr);
    if (strlen(str) >= sublen) {
        return stricmp(&str[strlen(str) - sublen], substr) == 0;
    }
    return false;
}
