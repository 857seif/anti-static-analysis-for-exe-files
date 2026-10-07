#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <random>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <cstdint>

#pragma comment(lib, "comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define ID_BTN_BROWSE   1001
#define ID_BTN_PACK     1002
#define ID_EDIT_PATH    1003
#define ID_EDIT_KEY     1005
#define ID_CHK_AUTOKEY  1006
#define ID_RAD_FAST     1007
#define ID_RAD_BALANCED 1008
#define ID_STATUS       1010
#define ID_PROGRESS     1011
#define ID_COMBO_ALGO   1012
#define ID_STATIC_SIZE  1013

HWND g_hwnd, g_hPath, g_hKey, g_hStatus, g_hProg, g_hCombo, g_hSizeInfo;
bool g_autoKey = true;
int g_mode = 0;
int g_algo = 0;

std::vector<BYTE> EncXOR(const std::vector<BYTE>& d, const std::string& k) {
    std::vector<BYTE> o(d.size());
    for (size_t i = 0; i < d.size(); i++) o[i] = d[i] ^ (BYTE)k[i % k.size()];
    return o;
}

std::vector<BYTE> EncXORRoll(const std::vector<BYTE>& d, const std::string& k) {
    std::vector<BYTE> o(d.size());
    BYTE s = 0x5A;
    for (size_t i = 0; i < d.size(); i++) {
        s = (BYTE)(s + k[i % k.size()] + (BYTE)(i * 31));
        o[i] = d[i] ^ s;
    }
    return o;
}

std::vector<BYTE> EncRC4(const std::vector<BYTE>& d, const std::string& k) {
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = (BYTE)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + (BYTE)k[i % k.size()]) & 0xFF;
        std::swap(S[i], S[j]);
    }
    std::vector<BYTE> o(d.size());
    int i = 0; j = 0;
    for (size_t n = 0; n < d.size(); n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        std::swap(S[i], S[j]);
        BYTE ks = S[(S[i] + S[j]) & 0xFF];
        o[n] = d[n] ^ ks;
    }
    return o;
}

static void TeaEncryptBlock(uint32_t* v, const uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    uint32_t delta = 0x9E3779B9;
    for (int i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0; v[1] = v1;
}
std::vector<BYTE> EncTEA(const std::vector<BYTE>& d, const std::string& key) {
    uint32_t k[4] = {0};
    for (int i = 0; i < 4; i++)
        for (int b = 0; b < 4; b++)
            k[i] = (k[i] << 8) | (BYTE)key[(i*4+b) % key.size()];
    std::vector<BYTE> padded = d;
    while (padded.size() % 8) padded.push_back(0);
    for (size_t i = 0; i < padded.size(); i += 8)
        TeaEncryptBlock((uint32_t*)(padded.data() + i), k);
    std::vector<BYTE> o;
    uint32_t sz = (uint32_t)d.size();
    o.push_back(sz & 0xFF); o.push_back((sz>>8)&0xFF);
    o.push_back((sz>>16)&0xFF); o.push_back((sz>>24)&0xFF);
    o.insert(o.end(), padded.begin(), padded.end());
    return o;
}

static void XteaEncryptBlock(uint32_t* v, const uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    uint32_t delta = 0x9E3779B9;
    for (int i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
    }
    v[0] = v0; v[1] = v1;
}
std::vector<BYTE> EncXTEA(const std::vector<BYTE>& d, const std::string& key) {
    uint32_t k[4] = {0};
    for (int i = 0; i < 4; i++)
        for (int b = 0; b < 4; b++)
            k[i] = (k[i] << 8) | (BYTE)key[(i*4+b) % key.size()];
    std::vector<BYTE> padded = d;
    while (padded.size() % 8) padded.push_back(0);
    for (size_t i = 0; i < padded.size(); i += 8)
        XteaEncryptBlock((uint32_t*)(padded.data() + i), k);
    std::vector<BYTE> o;
    uint32_t sz = (uint32_t)d.size();
    o.push_back(sz & 0xFF); o.push_back((sz>>8)&0xFF);
    o.push_back((sz>>16)&0xFF); o.push_back((sz>>24)&0xFF);
    o.insert(o.end(), padded.begin(), padded.end());
    return o;
}

static void XxteaEncrypt(uint32_t* v, int n, const uint32_t* k) {
    uint32_t z = v[n-1], y, sum = 0, e, DELTA = 0x9E3779B9;
    int p, q = 6 + 52 / n;
    while (q-- > 0) {
        sum += DELTA;
        e = (sum >> 2) & 3;
        for (p = 0; p < n - 1; p++) {
            y = v[p+1];
            z = v[p] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
        }
        y = v[0];
        z = v[n-1] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
    }
}
std::vector<BYTE> EncXXTEA(const std::vector<BYTE>& d, const std::string& key) {
    uint32_t k[4] = {0};
    for (int i = 0; i < 4; i++)
        for (int b = 0; b < 4; b++)
            k[i] = (k[i] << 8) | (BYTE)key[(i*4+b) % key.size()];
    std::vector<BYTE> padded = d;
    while (padded.size() % 4) padded.push_back(0);
    int n = (int)padded.size() / 4;
    XxteaEncrypt((uint32_t*)padded.data(), n, k);
    std::vector<BYTE> o;
    uint32_t sz = (uint32_t)d.size();
    o.push_back(sz & 0xFF); o.push_back((sz>>8)&0xFF);
    o.push_back((sz>>16)&0xFF); o.push_back((sz>>24)&0xFF);
    o.insert(o.end(), padded.begin(), padded.end());
    return o;
}

static uint32_t Rotl(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }
std::vector<BYTE> EncSalsa20(const std::vector<BYTE>& d, const std::string& key) {
    BYTE keyb[32] = {0};
    for (size_t i = 0; i < 32; i++) keyb[i] = (BYTE)key[i % key.size()];
    uint32_t k[8];
    for (int i = 0; i < 8; i++)
        k[i] = keyb[i*4] | (keyb[i*4+1]<<8) | (keyb[i*4+2]<<16) | (keyb[i*4+3]<<24);
    std::vector<BYTE> o(d.size());
    for (size_t i = 0; i < d.size(); i++) {
        uint32_t block[16] = {
            0x61707865, k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
            0x3320646e, 0x79622d32, 0x6b206574,
            (uint32_t)(i / 64), 0, 0, 0
        };
        uint32_t x[16];
        memcpy(x, block, sizeof(x));
        for (int r = 0; r < 10; r++) {
            x[4] ^= Rotl(x[0]+x[12], 7);  x[8] ^= Rotl(x[4]+x[0], 9);
            x[12] ^= Rotl(x[8]+x[4], 13); x[0] ^= Rotl(x[12]+x[8], 18);
            x[9] ^= Rotl(x[5]+x[1], 7);   x[13] ^= Rotl(x[9]+x[5], 9);
            x[1] ^= Rotl(x[13]+x[9], 13); x[5] ^= Rotl(x[1]+x[13], 18);
            x[14] ^= Rotl(x[10]+x[6], 7); x[2] ^= Rotl(x[14]+x[10], 9);
            x[6] ^= Rotl(x[2]+x[14], 13); x[10] ^= Rotl(x[6]+x[2], 18);
            x[3] ^= Rotl(x[15]+x[11], 7); x[7] ^= Rotl(x[3]+x[15], 9);
            x[11] ^= Rotl(x[7]+x[3], 13); x[15] ^= Rotl(x[11]+x[7], 18);
            x[1] ^= Rotl(x[0]+x[3], 7);   x[2] ^= Rotl(x[1]+x[0], 9);
            x[3] ^= Rotl(x[2]+x[1], 13);  x[0] ^= Rotl(x[3]+x[2], 18);
            x[6] ^= Rotl(x[5]+x[4], 7);   x[7] ^= Rotl(x[6]+x[5], 9);
            x[4] ^= Rotl(x[7]+x[6], 13);  x[5] ^= Rotl(x[4]+x[7], 18);
            x[11] ^= Rotl(x[10]+x[9], 7); x[8] ^= Rotl(x[11]+x[10], 9);
            x[9] ^= Rotl(x[8]+x[11], 13); x[10] ^= Rotl(x[9]+x[8], 18);
            x[12] ^= Rotl(x[15]+x[14], 7); x[13] ^= Rotl(x[12]+x[15], 9);
            x[14] ^= Rotl(x[13]+x[12], 13); x[15] ^= Rotl(x[14]+x[13], 18);
        }
        BYTE ks[64];
        for (int j = 0; j < 16; j++) {
            uint32_t v = x[j] + block[j];
            ks[j*4] = v & 0xFF; ks[j*4+1] = (v>>8)&0xFF;
            ks[j*4+2] = (v>>16)&0xFF; ks[j*4+3] = (v>>24)&0xFF;
        }
        o[i] = d[i] ^ ks[i % 64];
    }
    return o;
}

std::vector<BYTE> EncChaCha(const std::vector<BYTE>& d, const std::string& key) {
    BYTE keyb[32] = {0};
    for (size_t i = 0; i < 32; i++) keyb[i] = (BYTE)key[i % key.size()];
    uint32_t k[8];
    for (int i = 0; i < 8; i++)
        k[i] = keyb[i*4] | (keyb[i*4+1]<<8) | (keyb[i*4+2]<<16) | (keyb[i*4+3]<<24);
    std::vector<BYTE> o(d.size());
    for (size_t i = 0; i < d.size(); i++) {
        uint32_t s[16] = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
            (uint32_t)(i/64), 0, 0, 0
        };
        uint32_t x[16];
        memcpy(x, s, sizeof(x));
        for (int r = 0; r < 10; r++) {
            #define QR(a,b,c,d) \
                x[a]+=x[b]; x[d]^=x[a]; x[d]=Rotl(x[d],16); \
                x[c]+=x[d]; x[b]^=x[c]; x[b]=Rotl(x[b],12); \
                x[a]+=x[b]; x[d]^=x[a]; x[d]=Rotl(x[d],8);  \
                x[c]+=x[d]; x[b]^=x[c]; x[b]=Rotl(x[b],7);
            QR(0,4,8,12) QR(1,5,9,13) QR(2,6,10,14) QR(3,7,11,15)
            QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13) QR(3,4,9,14)
            #undef QR
        }
        BYTE ks[64];
        for (int j = 0; j < 16; j++) {
            uint32_t v = x[j] + s[j];
            ks[j*4]=v&0xFF; ks[j*4+1]=(v>>8)&0xFF;
            ks[j*4+2]=(v>>16)&0xFF; ks[j*4+3]=(v>>24)&0xFF;
        }
        o[i] = d[i] ^ ks[i % 64];
    }
    return o;
}

std::vector<BYTE> EncBlowfish(const std::vector<BYTE>& d, const std::string& key) {
    std::vector<BYTE> o(d.size());
    uint32_t state = 0x243F6A88;
    for (size_t i = 0; i < key.size(); i++)
        state = state * 0x01000193 ^ (BYTE)key[i];
    for (size_t i = 0; i < d.size(); i++) {
        state ^= (uint32_t)(i * 0x9E3779B9);
        state = Rotl(state, 7) * 0x85EBCA6B;
        o[i] = d[i] ^ (BYTE)(state >> 13);
    }
    return o;
}

std::vector<BYTE> EncTwofish(const std::vector<BYTE>& d, const std::string& key) {
    std::vector<BYTE> o(d.size());
    uint32_t k0 = 0x01234567, k1 = 0x89ABCDEF;
    for (size_t i = 0; i < key.size(); i++) {
        k0 = Rotl(k0 ^ (BYTE)key[i], 5);
        k1 = Rotl(k1 + (BYTE)key[i] * 0x9E3779B9, 7);
    }
    for (size_t i = 0; i < d.size(); i++) {
        uint32_t t = k0 ^ (uint32_t)(i * 0xDEADBEEF);
        k0 = Rotl(k0 + k1, 9);
        k1 = Rotl(k1 ^ t, 13);
        o[i] = d[i] ^ (BYTE)((k0 ^ k1) >> 11);
    }
    return o;
}

std::vector<BYTE> EncSerpent(const std::vector<BYTE>& d, const std::string& key) {
    std::vector<BYTE> o(d.size());
    uint32_t sbox[16] = {3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12};
    uint32_t state = 0;
    for (size_t i = 0; i < key.size(); i++) state = state * 31 + (BYTE)key[i];
    for (size_t i = 0; i < d.size(); i++) {
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF;
        uint32_t sub = sbox[(state >> 7) & 0xF];
        o[i] = d[i] ^ (BYTE)(sub ^ (state >> 11));
    }
    return o;
}

std::vector<BYTE> Enc3Layer(const std::vector<BYTE>& d, const std::string& key) {
    std::vector<BYTE> t1 = EncXORRoll(d, key);
    std::vector<BYTE> t2 = EncRC4(t1, key + "_L2");
    std::vector<BYTE> t3(t2.size());
    BYTE s = 0xA5;
    for (size_t i = 0; i < t2.size(); i++) {
        s = (BYTE)(s * 31 + key[i % key.size()]);
        t3[i] = t2[i] ^ s;
    }
    return t3;
}

struct AlgoInfo {
    const char* name;
    const char* desc;
    int overhead;
    std::vector<BYTE> (*fn)(const std::vector<BYTE>&, const std::string&);
};

AlgoInfo g_algos[] = {
    {"1. XOR",              "Simple XOR",                   0,  EncXOR},
    {"2. XOR Rolling",      "Evolving XOR key",             0,  EncXORRoll},
    {"3. RC4",              "Stream cipher",                 0,  EncRC4},
    {"4. TEA",              "64-bit block cipher",           4,  EncTEA},
    {"5. XTEA",             "Improved TEA",                  4,  EncXTEA},
    {"6. XXTEA",            "Variable block XXTEA",          4,  EncXXTEA},
    {"7. Salsa20",          "Modern stream cipher",          0,  EncSalsa20},
    {"8. ChaCha20",         "ARX stream cipher",             0,  EncChaCha},
    {"9. Blowfish-like",    "Feistel network",               0,  EncBlowfish},
    {"10. Twofish-like",    "Complex Feistel",               0,  EncTwofish},
    {"11. Serpent-like",    "SPN network",                   0,  EncSerpent},
    {"12. 3-Layer",         "XOR+RC4+Rolling",               0,  Enc3Layer},
};

const int NUM_ALGOS = sizeof(g_algos) / sizeof(g_algos[0]);

std::string RandomKey(int len = 16) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    std::mt19937 rng((unsigned)time(nullptr) ^ GetTickCount());
    std::uniform_int_distribution<int> dist(0, (int)sizeof(chars) - 2);
    std::string k;
    for (int i = 0; i < len; i++) k += chars[dist(rng)];
    return k;
}

std::vector<BYTE> RleCompress(const std::vector<BYTE>& data) {
    std::vector<BYTE> out;
    out.reserve(data.size());
    size_t i = 0;
    while (i < data.size()) {
        BYTE b = data[i];
        size_t run = 1;
        while (i + run < data.size() && data[i + run] == b && run < 255) run++;
        if (run >= 4) {
            out.push_back(0xFF); out.push_back(b); out.push_back((BYTE)run);
            i += run;
        } else {
            if (b == 0xFF) { out.push_back(0xFF); out.push_back(0xFF); out.push_back(1); }
            else out.push_back(b);
            i++;
        }
    }
    return out;
}

std::string BytesToCppArray(const std::vector<BYTE>& data, const char* name) {
    std::ostringstream oss;
    oss << "static unsigned char " << name << "[] = {\n";
    for (size_t i = 0; i < data.size(); i++) {
        if (i % 16 == 0) oss << "    ";
        char buf[8];
        sprintf(buf, "0x%02X", data[i]);
        oss << buf;
        if (i + 1 < data.size()) oss << ",";
        if (i % 16 == 15) oss << "\n";
        else oss << " ";
    }
    if (data.size() % 16 != 0) oss << "\n";
    oss << "};\n";
    oss << "static unsigned int " << name << "_len = " << data.size() << ";\n";
    return oss.str();
}

std::string DecryptorCode(int algo) {
    switch (algo) {
    case 0: return
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    std::vector<unsigned char> o(d.size());\n"
        "    for (size_t i = 0; i < d.size(); i++) o[i] = d[i] ^ (unsigned char)k[i % kl];\n"
        "    return o;\n"
        "}\n";
    case 1: return
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    std::vector<unsigned char> o(d.size());\n"
        "    unsigned char s = 0x5A;\n"
        "    for (size_t i = 0; i < d.size(); i++) {\n"
        "        s = (unsigned char)(s + k[i % kl] + (unsigned char)(i * 31));\n"
        "        o[i] = d[i] ^ s;\n"
        "    }\n"
        "    return o;\n"
        "}\n";
    case 2: return
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    unsigned char S[256];\n"
        "    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;\n"
        "    int j = 0;\n"
        "    for (int i = 0; i < 256; i++) { j = (j + S[i] + (unsigned char)k[i % kl]) & 0xFF; std::swap(S[i], S[j]); }\n"
        "    std::vector<unsigned char> o(d.size());\n"
        "    int i = 0; j = 0;\n"
        "    for (size_t n = 0; n < d.size(); n++) {\n"
        "        i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF; std::swap(S[i], S[j]);\n"
        "        o[n] = d[n] ^ S[(S[i] + S[j]) & 0xFF];\n"
        "    }\n"
        "    return o;\n"
        "}\n";
    case 3: return
        "static void TeaDecrypt(unsigned int* v, const unsigned int* k) {\n"
        "    unsigned int v0 = v[0], v1 = v[1], sum = 0xC6EF3720, delta = 0x9E3779B9;\n"
        "    for (int i = 0; i < 32; i++) {\n"
        "        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);\n"
        "        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);\n"
        "        sum -= delta;\n"
        "    }\n"
        "    v[0] = v0; v[1] = v1;\n"
        "}\n"
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    if (d.size() < 4) return {};\n"
        "    unsigned int sz = d[0] | (d[1]<<8) | (d[2]<<16) | (d[3]<<24);\n"
        "    unsigned int key[4] = {0};\n"
        "    for (int i = 0; i < 4; i++) for (int b = 0; b < 4; b++) key[i] = (key[i] << 8) | (unsigned char)k[(i*4+b) % kl];\n"
        "    std::vector<unsigned char> p(d.begin()+4, d.end());\n"
        "    for (size_t i = 0; i < p.size(); i += 8) TeaDecrypt((unsigned int*)(p.data() + i), key);\n"
        "    p.resize(sz);\n"
        "    return p;\n"
        "}\n";
    case 4: return
        "static void XteaDecrypt(unsigned int* v, const unsigned int* k) {\n"
        "    unsigned int v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * 32;\n"
        "    for (int i = 0; i < 32; i++) {\n"
        "        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);\n"
        "        sum -= delta;\n"
        "        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);\n"
        "    }\n"
        "    v[0] = v0; v[1] = v1;\n"
        "}\n"
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    if (d.size() < 4) return {};\n"
        "    unsigned int sz = d[0] | (d[1]<<8) | (d[2]<<16) | (d[3]<<24);\n"
        "    unsigned int key[4] = {0};\n"
        "    for (int i = 0; i < 4; i++) for (int b = 0; b < 4; b++) key[i] = (key[i] << 8) | (unsigned char)k[(i*4+b) % kl];\n"
        "    std::vector<unsigned char> p(d.begin()+4, d.end());\n"
        "    for (size_t i = 0; i < p.size(); i += 8) XteaDecrypt((unsigned int*)(p.data() + i), key);\n"
        "    p.resize(sz);\n"
        "    return p;\n"
        "}\n";
    case 5: return
        "static void XxteaDecrypt(unsigned int* v, int n, const unsigned int* k) {\n"
        "    unsigned int z, y = v[0], sum = 0x9E3779B9 * (6 + 52 / n), DELTA = 0x9E3779B9;\n"
        "    int p, q = 6 + 52 / n;\n"
        "    while (q-- > 0) {\n"
        "        unsigned int e = (sum >> 2) & 3;\n"
        "        for (p = n - 1; p > 0; p--) {\n"
        "            z = v[p-1];\n"
        "            y = v[p] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));\n"
        "        }\n"
        "        z = v[n-1];\n"
        "        y = v[0] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));\n"
        "        sum -= DELTA;\n"
        "    }\n"
        "}\n"
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    if (d.size() < 4) return {};\n"
        "    unsigned int sz = d[0] | (d[1]<<8) | (d[2]<<16) | (d[3]<<24);\n"
        "    unsigned int key[4] = {0};\n"
        "    for (int i = 0; i < 4; i++) for (int b = 0; b < 4; b++) key[i] = (key[i] << 8) | (unsigned char)k[(i*4+b) % kl];\n"
        "    std::vector<unsigned char> p(d.begin()+4, d.end());\n"
        "    int n = (int)p.size() / 4;\n"
        "    XxteaDecrypt((unsigned int*)p.data(), n, key);\n"
        "    p.resize(sz);\n"
        "    return p;\n"
        "}\n";
    case 6: return
        "static unsigned int Rotl(unsigned int x, int c) { return (x << c) | (x >> (32 - c)); }\n"
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    unsigned char keyb[32] = {0};\n"
        "    for (unsigned int i = 0; i < 32; i++) keyb[i] = (unsigned char)k[i % kl];\n"
        "    unsigned int K[8];\n"
        "    for (int i = 0; i < 8; i++) K[i] = keyb[i*4] | (keyb[i*4+1]<<8) | (keyb[i*4+2]<<16) | (keyb[i*4+3]<<24);\n"
        "    std::vector<unsigned char> o(d.size());\n"
        "    for (size_t i = 0; i < d.size(); i++) {\n"
        "        unsigned int blk[16] = {0x61707865,K[0],K[1],K[2],K[3],K[4],K[5],K[6],K[7],0x3320646e,0x79622d32,0x6b206574,(unsigned int)(i/64),0,0,0};\n"
        "        unsigned int x[16]; memcpy(x, blk, sizeof(x));\n"
        "        for (int r = 0; r < 10; r++) {\n"
        "            x[4]^=Rotl(x[0]+x[12],7); x[8]^=Rotl(x[4]+x[0],9); x[12]^=Rotl(x[8]+x[4],13); x[0]^=Rotl(x[12]+x[8],18);\n"
        "            x[9]^=Rotl(x[5]+x[1],7); x[13]^=Rotl(x[9]+x[5],9); x[1]^=Rotl(x[13]+x[9],13); x[5]^=Rotl(x[1]+x[13],18);\n"
        "            x[14]^=Rotl(x[10]+x[6],7); x[2]^=Rotl(x[14]+x[10],9); x[6]^=Rotl(x[2]+x[14],13); x[10]^=Rotl(x[6]+x[2],18);\n"
        "            x[3]^=Rotl(x[15]+x[11],7); x[7]^=Rotl(x[3]+x[15],9); x[11]^=Rotl(x[7]+x[3],13); x[15]^=Rotl(x[11]+x[7],18);\n"
        "            x[1]^=Rotl(x[0]+x[3],7); x[2]^=Rotl(x[1]+x[0],9); x[3]^=Rotl(x[2]+x[1],13); x[0]^=Rotl(x[3]+x[2],18);\n"
        "            x[6]^=Rotl(x[5]+x[4],7); x[7]^=Rotl(x[6]+x[5],9); x[4]^=Rotl(x[7]+x[6],13); x[5]^=Rotl(x[4]+x[7],18);\n"
        "            x[11]^=Rotl(x[10]+x[9],7); x[8]^=Rotl(x[11]+x[10],9); x[9]^=Rotl(x[8]+x[11],13); x[10]^=Rotl(x[9]+x[8],18);\n"
        "            x[12]^=Rotl(x[15]+x[14],7); x[13]^=Rotl(x[12]+x[15],9); x[14]^=Rotl(x[13]+x[12],13); x[15]^=Rotl(x[14]+x[13],18);\n"
        "        }\n"
        "        unsigned char ks[64];\n"
        "        for (int j = 0; j < 16; j++) { unsigned int v = x[j] + blk[j]; ks[j*4]=v&0xFF; ks[j*4+1]=(v>>8)&0xFF; ks[j*4+2]=(v>>16)&0xFF; ks[j*4+3]=(v>>24)&0xFF; }\n"
        "        o[i] = d[i] ^ ks[i % 64];\n"
        "    }\n"
        "    return o;\n"
        "}\n";
    case 7: return
        "static unsigned int Rotl(unsigned int x, int c) { return (x << c) | (x >> (32 - c)); }\n"
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    unsigned char keyb[32] = {0};\n"
        "    for (unsigned int i = 0; i < 32; i++) keyb[i] = (unsigned char)k[i % kl];\n"
        "    unsigned int K[8];\n"
        "    for (int i = 0; i < 8; i++) K[i] = keyb[i*4] | (keyb[i*4+1]<<8) | (keyb[i*4+2]<<16) | (keyb[i*4+3]<<24);\n"
        "    std::vector<unsigned char> o(d.size());\n"
        "    for (size_t i = 0; i < d.size(); i++) {\n"
        "        unsigned int s[16] = {0x61707865,0x3320646e,0x79622d32,0x6b206574,K[0],K[1],K[2],K[3],K[4],K[5],K[6],K[7],(unsigned int)(i/64),0,0,0};\n"
        "        unsigned int x[16]; memcpy(x, s, sizeof(x));\n"
        "        for (int r = 0; r < 10; r++) {\n"
        "            #define QR(a,b,c,d) x[a]+=x[b]; x[d]^=x[a]; x[d]=Rotl(x[d],16); x[c]+=x[d]; x[b]^=x[c]; x[b]=Rotl(x[b],12); x[a]+=x[b]; x[d]^=x[a]; x[d]=Rotl(x[d],8); x[c]+=x[d]; x[b]^=x[c]; x[b]=Rotl(x[b],7);\n"
        "            QR(0,4,8,12) QR(1,5,9,13) QR(2,6,10,14) QR(3,7,11,15)\n"
        "            QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13) QR(3,4,9,14)\n"
        "            #undef QR\n"
        "        }\n"
        "        unsigned char ks[64];\n"
        "        for (int j = 0; j < 16; j++) { unsigned int v = x[j] + s[j]; ks[j*4]=v&0xFF; ks[j*4+1]=(v>>8)&0xFF; ks[j*4+2]=(v>>16)&0xFF; ks[j*4+3]=(v>>24)&0xFF; }\n"
        "        o[i] = d[i] ^ ks[i % 64];\n"
        "    }\n"
        "    return o;\n"
        "}\n";
    case 8: return
        "static unsigned int Rotl(unsigned int x, int c) { return (x << c) | (x >> (32 - c)); }\n"
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    std::vector<unsigned char> o(d.size());\n"
        "    unsigned int state = 0x243F6A88;\n"
        "    for (unsigned int i = 0; i < kl; i++) state = state * 0x01000193 ^ (unsigned char)k[i];\n"
        "    for (size_t i = 0; i < d.size(); i++) {\n"
        "        state ^= (unsigned int)(i * 0x9E3779B9);\n"
        "        state = Rotl(state, 7) * 0x85EBCA6B;\n"
        "        o[i] = d[i] ^ (unsigned char)(state >> 13);\n"
        "    }\n"
        "    return o;\n"
        "}\n";
    case 9: return
        "static unsigned int Rotl(unsigned int x, int c) { return (x << c) | (x >> (32 - c)); }\n"
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    std::vector<unsigned char> o(d.size());\n"
        "    unsigned int k0 = 0x01234567, k1 = 0x89ABCDEF;\n"
        "    for (unsigned int i = 0; i < kl; i++) { k0 = Rotl(k0 ^ (unsigned char)k[i], 5); k1 = Rotl(k1 + (unsigned char)k[i] * 0x9E3779B9, 7); }\n"
        "    for (size_t i = 0; i < d.size(); i++) {\n"
        "        unsigned int t = k0 ^ (unsigned int)(i * 0xDEADBEEF);\n"
        "        k0 = Rotl(k0 + k1, 9); k1 = Rotl(k1 ^ t, 13);\n"
        "        o[i] = d[i] ^ (unsigned char)((k0 ^ k1) >> 11);\n"
        "    }\n"
        "    return o;\n"
        "}\n";
    case 10: return
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    std::vector<unsigned char> o(d.size());\n"
        "    unsigned int sbox[16] = {3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12};\n"
        "    unsigned int state = 0;\n"
        "    for (unsigned int i = 0; i < kl; i++) state = state * 31 + (unsigned char)k[i];\n"
        "    for (size_t i = 0; i < d.size(); i++) {\n"
        "        state = (state * 1103515245 + 12345) & 0x7FFFFFFF;\n"
        "        unsigned int sub = sbox[(state >> 7) & 0xF];\n"
        "        o[i] = d[i] ^ (unsigned char)(sub ^ (state >> 11));\n"
        "    }\n"
        "    return o;\n"
        "}\n";
    case 11: return
        "std::vector<unsigned char> Decrypt3Layer(const std::vector<unsigned char>& d, const char* k, unsigned int kl) {\n"
        "    std::vector<unsigned char> t3(d.size());\n"
        "    unsigned char s = 0xA5;\n"
        "    for (size_t i = 0; i < d.size(); i++) { s = (unsigned char)(s * 31 + k[i % kl]); t3[i] = d[i] ^ s; }\n"
        "    unsigned char S[256];\n"
        "    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;\n"
        "    std::string k2 = std::string(k) + \"_L2\";\n"
        "    int j = 0;\n"
        "    for (int i = 0; i < 256; i++) { j = (j + S[i] + (unsigned char)k2[i % k2.size()]) & 0xFF; std::swap(S[i], S[j]); }\n"
        "    std::vector<unsigned char> t2(d.size());\n"
        "    int i = 0; j = 0;\n"
        "    for (size_t n = 0; n < d.size(); n++) { i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF; std::swap(S[i], S[j]); t2[n] = t3[n] ^ S[(S[i] + S[j]) & 0xFF]; }\n"
        "    std::vector<unsigned char> o(t2.size());\n"
        "    unsigned char s2 = 0x5A;\n"
        "    for (size_t n = 0; n < t2.size(); n++) { s2 = (unsigned char)(s2 + k[n % kl] + (unsigned char)(n * 31)); o[n] = t2[n] ^ s2; }\n"
        "    return o;\n"
        "}\n"
        "std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& d, const char* k, unsigned int kl) { return Decrypt3Layer(d, k, kl); }\n";
    }
    return "";
}

bool GenerateCppStub(const std::wstring& outCppPath,
                     const std::vector<BYTE>& encrypted,
                     const std::string& key,
                     int mode, int algo,
                     unsigned int origSize)
{
    std::string keyEsc;
    for (unsigned char c : key) {
        char buf[8];
        sprintf(buf, "\\x%02X", c);
        keyEsc += buf;
    }

    std::ostringstream src;

    src <<
        "#include <windows.h>\n"
        "#include <vector>\n"
        "#include <string>\n"
        "#include <cstring>\n"
        "#include <cstdio>\n"
        "#include <algorithm>\n"
        "#include <tlhelp32.h>\n"
        "\n"
        << BytesToCppArray(encrypted, "g_payload") <<
        "\n"
        "static const char g_key[] = \"" << keyEsc << "\";\n"
        "static const unsigned int g_key_len = " << key.size() << ";\n"
        "static const unsigned int g_mode = " << mode << ";\n"
        "static const unsigned int g_algo = " << algo << ";\n"
        "static const unsigned int g_orig_size = " << origSize << ";\n"
        "\n"
        "std::vector<unsigned char> RleDecompress(const std::vector<unsigned char>& data) {\n"
        "    std::vector<unsigned char> out;\n"
        "    size_t i = 0;\n"
        "    while (i < data.size()) {\n"
        "        if (data[i] == 0xFF && i + 2 < data.size()) {\n"
        "            unsigned char val = data[i+1];\n"
        "            unsigned char cnt = data[i+2];\n"
        "            for (int j = 0; j < cnt; j++) out.push_back(val);\n"
        "            i += 3;\n"
        "        } else { out.push_back(data[i]); i++; }\n"
        "    }\n"
        "    return out;\n"
        "}\n"
        "\n"
        << DecryptorCode(algo) <<
        "\n"
        "static void HookExitProcess(PVOID imageBase, PIMAGE_NT_HEADERS nt) {\n"
        "    PIMAGE_DATA_DIRECTORY impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];\n"
        "    if (!impDir->Size) return;\n"
        "    FARPROC realExit = GetProcAddress(GetModuleHandleA(\"kernel32.dll\"), \"ExitProcess\");\n"
        "    FARPROC fakeExit = GetProcAddress(GetModuleHandleA(\"kernel32.dll\"), \"ExitThread\");\n"
        "    if (!realExit || !fakeExit) return;\n"
        "    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)imageBase + impDir->VirtualAddress);\n"
        "    while (imp->Name) {\n"
        "        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + imp->FirstThunk);\n"
        "        if (!imp->OriginalFirstThunk) { imp++; continue; }\n"
        "        PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + imp->OriginalFirstThunk);\n"
        "        while (orig->u1.AddressOfData) {\n"
        "            if (!(orig->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {\n"
        "                PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((BYTE*)imageBase + orig->u1.AddressOfData);\n"
        "                if (strcmp((const char*)ibn->Name, \"ExitProcess\") == 0) iat->u1.Function = (ULONG_PTR)fakeExit;\n"
        "            }\n"
        "            orig++; iat++;\n"
        "        }\n"
        "        imp++;\n"
        "    }\n"
        "}\n"
        "\n"
        "static void KillSpawnedProcesses() {\n"
        "    wchar_t selfName[MAX_PATH] = {};\n"
        "    GetModuleFileNameW(NULL, selfName, MAX_PATH);\n"
        "    wchar_t* p = wcsrchr(selfName, L'\\\\');\n"
        "    if (!p) return;\n"
        "    DWORD selfPid = GetCurrentProcessId();\n"
        "    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n"
        "    if (hSnap == INVALID_HANDLE_VALUE) return;\n"
        "    PROCESSENTRY32W pe = { sizeof(pe) };\n"
        "    if (Process32FirstW(hSnap, &pe)) {\n"
        "        do {\n"
        "            if (_wcsicmp(pe.szExeFile, p + 1) == 0 && pe.th32ProcessID != selfPid) {\n"
        "                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);\n"
        "                if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); }\n"
        "            }\n"
        "        } while (Process32NextW(hSnap, &pe));\n"
        "    }\n"
        "    CloseHandle(hSnap);\n"
        "}\n"
        "\n"
        "typedef BOOL (WINAPI *DLLMAIN_FN)(HINSTANCE, DWORD, LPVOID);\n"
        "\n"
        "LPVOID MapAndRun(const std::vector<unsigned char>& pe) {\n"
        "    if (pe.size() < sizeof(IMAGE_DOS_HEADER)) return NULL;\n"
        "    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe.data();\n"
        "    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;\n"
        "    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe.data() + dos->e_lfanew);\n"
        "    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;\n"
        "    DWORD imageSize = nt->OptionalHeader.SizeOfImage;\n"
        "    LPVOID base = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n"
        "    if (!base) return NULL;\n"
        "    memcpy(base, pe.data(), nt->OptionalHeader.SizeOfHeaders);\n"
        "    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);\n"
        "    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {\n"
        "        if (sec->SizeOfRawData == 0) continue;\n"
        "        if ((size_t)sec->PointerToRawData + sec->SizeOfRawData > pe.size()) continue;\n"
        "        memcpy((BYTE*)base + sec->VirtualAddress, pe.data() + sec->PointerToRawData, sec->SizeOfRawData);\n"
        "    }\n"
        "    ULONG_PTR delta = (ULONG_PTR)base - nt->OptionalHeader.ImageBase;\n"
        "    if (delta != 0) {\n"
        "        PIMAGE_DATA_DIRECTORY relDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];\n"
        "        if (relDir->Size) {\n"
        "            PIMAGE_BASE_RELOCATION rel = (PIMAGE_BASE_RELOCATION)((BYTE*)base + relDir->VirtualAddress);\n"
        "            while (rel->SizeOfBlock) {\n"
        "                DWORD cnt = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);\n"
        "                WORD* list = (WORD*)(rel + 1);\n"
        "                for (DWORD j = 0; j < cnt; j++) {\n"
        "                    int type = list[j] >> 12; int off = list[j] & 0x0FFF;\n"
        "                    BYTE* target = (BYTE*)base + rel->VirtualAddress + off;\n"
        "                    if (type == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)target += (DWORD)delta;\n"
        "                    else if (type == IMAGE_REL_BASED_DIR64) *(ULONGLONG*)target += (ULONGLONG)delta;\n"
        "                }\n"
        "                rel = (PIMAGE_BASE_RELOCATION)((BYTE*)rel + rel->SizeOfBlock);\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    PIMAGE_DATA_DIRECTORY impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];\n"
        "    if (impDir->Size) {\n"
        "        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + impDir->VirtualAddress);\n"
        "        while (imp->Name) {\n"
        "            const char* dllName = (const char*)((BYTE*)base + imp->Name);\n"
        "            HMODULE hDll = LoadLibraryA(dllName);\n"
        "            if (!hDll) { VirtualFree(base, 0, MEM_RELEASE); return NULL; }\n"
        "            PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)((BYTE*)base + imp->OriginalFirstThunk);\n"
        "            PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((BYTE*)base + imp->FirstThunk);\n"
        "            if (!imp->OriginalFirstThunk) orig = iat;\n"
        "            while (orig->u1.AddressOfData) {\n"
        "                FARPROC fn = NULL;\n"
        "                if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) fn = GetProcAddress(hDll, (LPCSTR)(orig->u1.Ordinal & 0xFFFF));\n"
        "                else { PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + orig->u1.AddressOfData); fn = GetProcAddress(hDll, (LPCSTR)ibn->Name); }\n"
        "                iat->u1.Function = (ULONG_PTR)fn; orig++; iat++;\n"
        "            }\n"
        "            imp++;\n"
        "        }\n"
        "    }\n"
        "    HookExitProcess(base, nt);\n"
        "    PIMAGE_DATA_DIRECTORY tlsDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];\n"
        "    if (tlsDir->Size) {\n"
        "        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)((BYTE*)base + tlsDir->VirtualAddress);\n"
        "        PIMAGE_TLS_CALLBACK* cb = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;\n"
        "        if (cb) while (*cb) { (*cb)((LPVOID)base, DLL_PROCESS_ATTACH, NULL); cb++; }\n"
        "    }\n"
        "    DWORD epRva = nt->OptionalHeader.AddressOfEntryPoint;\n"
        "    if (epRva == 0) return base;\n"
        "    BYTE* entry = (BYTE*)base + epRva;\n"
        "    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) {\n"
        "        DLLMAIN_FN dllMain = (DLLMAIN_FN)entry;\n"
        "        dllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);\n"
        "        return base;\n"
        "    }\n"
        "    DWORD tid = 0;\n"
        "    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entry, NULL, 0, &tid);\n"
        "    WORD subsystem = nt->OptionalHeader.Subsystem;\n"
        "    if (subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {\n"
        "        MSG msg;\n"
        "        while (GetMessageW(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }\n"
        "        if (hThread) CloseHandle(hThread);\n"
        "    } else {\n"
        "        if (hThread) { WaitForSingleObject(hThread, INFINITE); CloseHandle(hThread); }\n"
        "    }\n"
        "    return base;\n"
        "}\n"
        "\n"
        "int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {\n"
        "    HANDLE hJob = CreateJobObjectA(NULL, NULL);\n"
        "    if (hJob) {\n"
        "        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};\n"
        "        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;\n"
        "        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));\n"
        "        AssignProcessToJobObject(hJob, GetCurrentProcess());\n"
        "    }\n"
        "\n"
        "    std::vector<unsigned char> data(g_payload, g_payload + g_payload_len);\n"
        "    data = Decrypt(data, g_key, g_key_len);\n"
        "    if (g_mode >= 1) data = RleDecompress(data);\n"
        "    if (data.size() > g_orig_size) data.resize(g_orig_size);\n"
        "    if (data.size() > sizeof(IMAGE_DOS_HEADER)) {\n"
        "        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)data.data();\n"
        "        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {\n"
        "            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(data.data() + dos->e_lfanew);\n"
        "            if (nt->Signature == IMAGE_NT_SIGNATURE && nt->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {\n"
        "                AllocConsole();\n"
        "                freopen(\"CONOUT$\", \"w\", stdout);\n"
        "                freopen(\"CONOUT$\", \"w\", stderr);\n"
        "                freopen(\"CONIN$\", \"r\", stdin);\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    MapAndRun(data);\n"
        "\n"
        "    KillSpawnedProcesses();\n"
        "    if (hJob) {\n"
        "        TerminateJobObject(hJob, 0);\n"
        "        CloseHandle(hJob);\n"
        "    }\n"
        "    ExitProcess(0);\n"
        "    return 0;\n"
        "}\n";

    std::ofstream ofs(outCppPath.c_str(), std::ios::binary);
    if (!ofs) return false;
    std::string s = src.str();
    ofs.write(s.data(), s.size());
    ofs.close();
    return true;
}

bool PackToCpp(const std::wstring& inputPath, const std::string& key,
               int mode, int algo, std::wstring& outCpp, size_t& outSize)
{
    std::ifstream ifs(inputPath.c_str(), std::ios::binary | std::ios::ate);
    if (!ifs) return false;
    size_t sz = (size_t)ifs.tellg();
    ifs.seekg(0);
    std::vector<BYTE> raw(sz);
    ifs.read((char*)raw.data(), sz);
    ifs.close();

    std::vector<BYTE> payload = raw;
    if (mode >= 1) {
        std::vector<BYTE> c = RleCompress(raw);
        if (c.size() < raw.size()) payload = c;
    }

    std::vector<BYTE> encrypted = g_algos[algo].fn(payload, key);
    outSize = encrypted.size();

    wchar_t dir[MAX_PATH];
    wcsncpy(dir, inputPath.c_str(), MAX_PATH - 1);
    dir[MAX_PATH - 1] = 0;
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash) *(slash + 1) = 0;
    else wcscpy(dir, L".\\");

    std::wstring base = inputPath;
    size_t pos = base.find_last_of(L"\\/");
    if (pos != std::wstring::npos) base = base.substr(pos + 1);
    pos = base.find_last_of(L'.');
    if (pos != std::wstring::npos) base = base.substr(0, pos);

    outCpp = std::wstring(dir) + base + L"_packed.cpp";

    return GenerateCppStub(outCpp, encrypted, key, mode, algo, (unsigned int)raw.size());
}

void SetStatus(const wchar_t* msg) {
    if (g_hStatus) SetWindowTextW(g_hStatus, msg);
}

void UpdateSizeInfo() {
    wchar_t path[MAX_PATH] = {};
    GetWindowTextW(g_hPath, path, MAX_PATH);
    if (!path[0] || GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        SetWindowTextW(g_hSizeInfo, L"Select EXE file first");
        return;
    }
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) { SetWindowTextW(g_hSizeInfo, L"Cannot read file"); return; }
    size_t sz = (size_t)ifs.tellg();
    ifs.close();

    size_t overhead = g_algos[g_algo].overhead;
    size_t codeOverhead = 1500;
    size_t estimated = sz + overhead + codeOverhead;

    wchar_t wname[128] = {};
    MultiByteToWideChar(CP_UTF8, 0, g_algos[g_algo].name, -1, wname, 128);

    wchar_t wnum1[32], wnum2[32];
    swprintf(wnum1, 32, L"%zu", sz / 1024);
    swprintf(wnum2, 32, L"%zu", estimated / 1024);

    wchar_t buf[512] = {};
    wcscpy(buf, L"Original: ");
    wcscat(buf, wnum1);
    wcscat(buf, L" KB | Estimated CPP: ~");
    wcscat(buf, wnum2);
    wcscat(buf, L" KB | Algo: ");
    wcscat(buf, wname);
    SetWindowTextW(g_hSizeInfo, buf);
}

void DoPack() {
    wchar_t path[MAX_PATH] = {};
    GetWindowTextW(g_hPath, path, MAX_PATH);
    if (!path[0] || GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(g_hwnd, L"Select a valid EXE", L"Error", MB_ICONERROR);
        return;
    }

    std::string key;
    if (g_autoKey) {
        key = RandomKey(16);
    } else {
        wchar_t kbuf[256] = {};
        GetWindowTextW(g_hKey, kbuf, 256);
        char narrow[256];
        WideCharToMultiByte(CP_UTF8, 0, kbuf, -1, narrow, 256, NULL, NULL);
        key = narrow;
        if (key.empty()) {
            MessageBoxW(g_hwnd, L"Key empty", L"Error", MB_ICONERROR);
            return;
        }
    }

    SetStatus(L"Encrypting and generating C++ code...");
    EnableWindow(GetDlgItem(g_hwnd, ID_BTN_PACK), FALSE);
    SendMessageW(g_hProg, PBM_SETPOS, 40, 0);

    std::wstring outCpp;
    size_t outSize = 0;
    bool ok = PackToCpp(path, key, g_mode, g_algo, outCpp, outSize);

    SendMessageW(g_hProg, PBM_SETPOS, 100, 0);
    EnableWindow(GetDlgItem(g_hwnd, ID_BTN_PACK), TRUE);

    if (ok) {
        wchar_t kwide[64];
        MultiByteToWideChar(CP_UTF8, 0, key.c_str(), -1, kwide, 64);

        wchar_t wname[128] = {};
        MultiByteToWideChar(CP_UTF8, 0, g_algos[g_algo].name, -1, wname, 128);

        std::wstringstream msg;
        msg << L"C++ Stub generated!\n\n";
        msg << L"Algorithm: " << wname << L"\n";
        msg << L"Encrypted size: " << (outSize / 1024) << L" KB\n";
        msg << L"Key: " << kwide << L"\n\n";
        msg << L"File: " << outCpp << L"\n\n";
        msg << L"Build:\n";
        msg << L"g++ -O2 -s -DUNICODE -D_UNICODE \"" << outCpp
            << L"\" -o packed.exe -luser32 -mwindows "
               L"-Wl,--strip-all -Wl,--gc-sections "
               L"-ffunction-sections -fdata-sections "
               L"-fno-exceptions -fno-rtti "
               L"-fno-asynchronous-unwind-tables -fno-unwind-tables "
               L"-fno-ident -static-libgcc -static-libstdc++";

        MessageBoxW(g_hwnd, msg.str().c_str(), L"Success", MB_ICONINFORMATION);
        SetStatus(L"Done");
        UpdateSizeInfo();
    } else {
        MessageBoxW(g_hwnd, L"Failed", L"Error", MB_ICONERROR);
        SetStatus(L"Error");
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HFONT f = CreateFontW(15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        int y = 12;
        CreateWindowW(L"STATIC", L"anti static analysis", WS_CHILD | WS_VISIBLE, 20, y, 550, 24, hwnd, NULL, NULL, NULL);
        y += 32;
        CreateWindowW(L"STATIC", L"EXE File:", WS_CHILD | WS_VISIBLE, 20, y + 2, 90, 20, hwnd, NULL, NULL, NULL);
        g_hPath = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 110, y, 380, 24, hwnd, (HMENU)ID_EDIT_PATH, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Browse", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 500, y, 70, 24, hwnd, (HMENU)ID_BTN_BROWSE, NULL, NULL);
        y += 34;
        CreateWindowW(L"STATIC", L"Algorithm:", WS_CHILD | WS_VISIBLE, 20, y + 2, 90, 20, hwnd, NULL, NULL, NULL);
        g_hCombo = CreateWindowW(L"COMBOBOX", NULL,
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
            110, y, 460, 300, hwnd, (HMENU)ID_COMBO_ALGO, NULL, NULL);
        for (int i = 0; i < NUM_ALGOS; i++) {
            wchar_t wname[128] = {};
            wchar_t wdesc[128] = {};
            MultiByteToWideChar(CP_UTF8, 0, g_algos[i].name, -1, wname, 128);
            MultiByteToWideChar(CP_UTF8, 0, g_algos[i].desc, -1, wdesc, 128);
            wchar_t item[256] = {};
            wcscpy(item, wname);
            wcscat(item, L"  -  ");
            wcscat(item, wdesc);
            SendMessageW(g_hCombo, CB_ADDSTRING, 0, (LPARAM)item);
        }
        SendMessageW(g_hCombo, CB_SETCURSEL, 0, 0);
        y += 34;
        CreateWindowW(L"STATIC", L"Key:", WS_CHILD | WS_VISIBLE, 20, y + 2, 90, 20, hwnd, NULL, NULL, NULL);
        g_hKey = CreateWindowW(L"EDIT", L"(auto)", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD, 110, y, 300, 24, hwnd, (HMENU)ID_EDIT_KEY, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Auto Key", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 420, y, 100, 24, hwnd, (HMENU)ID_CHK_AUTOKEY, NULL, NULL);
        CheckDlgButton(hwnd, ID_CHK_AUTOKEY, BST_CHECKED);
        EnableWindow(g_hKey, FALSE);
        y += 36;
        CreateWindowW(L"STATIC", L"Mode:", WS_CHILD | WS_VISIBLE, 20, y + 2, 90, 20, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Fast", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON, 110, y, 70, 22, hwnd, (HMENU)ID_RAD_FAST, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Balanced", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON, 190, y, 90, 22, hwnd, (HMENU)ID_RAD_BALANCED, NULL, NULL);
        CheckDlgButton(hwnd, ID_RAD_FAST, BST_CHECKED);
        y += 36;
        g_hProg = CreateWindowW(PROGRESS_CLASSW, NULL, WS_CHILD | WS_VISIBLE, 20, y, 550, 20, hwnd, (HMENU)ID_PROGRESS, NULL, NULL);
        SendMessageW(g_hProg, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        y += 30;
        g_hSizeInfo = CreateWindowW(L"STATIC", L"Select EXE file first", WS_CHILD | WS_VISIBLE | SS_LEFT, 20, y, 550, 44, hwnd, (HMENU)ID_STATIC_SIZE, NULL, NULL);
        y += 48;
        CreateWindowW(L"BUTTON", L"GENERATE C++ STUB", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 180, y, 200, 36, hwnd, (HMENU)ID_BTN_PACK, NULL, NULL);
        y += 48;
        g_hStatus = CreateWindowW(L"STATIC", L"Select EXE then Generate", WS_CHILD | WS_VISIBLE, 20, y, 550, 22, hwnd, (HMENU)ID_STATUS, NULL, NULL);
        EnumChildWindows(hwnd, [](HWND h, LPARAM font) -> BOOL {
            SendMessageW(h, WM_SETFONT, (WPARAM)font, TRUE);
            return TRUE;
        }, (LPARAM)f);
        break;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == ID_BTN_BROWSE) {
            OPENFILENAMEW ofn = { sizeof(ofn) };
            wchar_t file[MAX_PATH] = {};
            ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = L"EXE Files\0*.exe\0All\0*.*\0";
            ofn.lpstrFile = file;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                SetWindowTextW(g_hPath, file);
                UpdateSizeInfo();
            }
        } else if (id == ID_CHK_AUTOKEY) {
            g_autoKey = IsDlgButtonChecked(hwnd, ID_CHK_AUTOKEY) == BST_CHECKED;
            EnableWindow(g_hKey, !g_autoKey);
            SetWindowTextW(g_hKey, g_autoKey ? L"(auto)" : L"");
        } else if (id == ID_COMBO_ALGO) {
            if (HIWORD(wp) == CBN_SELCHANGE) {
                g_algo = (int)SendMessageW(g_hCombo, CB_GETCURSEL, 0, 0);
                UpdateSizeInfo();
            }
        } else if (id == ID_BTN_PACK) DoPack();
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hi, HINSTANCE, LPSTR, int ns) {
    INITCOMMONCONTROLSEX ic = { sizeof(ic), ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&ic);
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"AntiStaticAnalysis";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassExW(&wc);
    g_hwnd = CreateWindowExW(0, L"AntiStaticAnalysis", L"anti static analysis",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 620, 480, NULL, NULL, hi, NULL);
    ShowWindow(g_hwnd, ns);
    UpdateWindow(g_hwnd);
    MSG m;
    while (GetMessageW(&m, NULL, 0, 0)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return (int)m.wParam;
}