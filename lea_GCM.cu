#include <stdio.h>
//#include <crtdbg.h>
#include <corecrt_malloc.h>


#pragma once
typedef unsigned char byte;
typedef unsigned int uint32;

#define GETU32(p)(((uint32)p[0]<<24)^((uint32)p[1]<<16)^((uint32)p[2]<<8)^((uint32)p[3]))
#define PUTU32(b, x) { \
(b)[0] = (byte)((x) >> 24); \
(b)[1] = (byte)((x) >> 16); \
(b)[2] = (byte)((x) >> 8); \
(b)[3] = (byte)(x); }

uint32 keyNum[8] = { 0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957 };



// 바이트 배열 복사하기 (메모리 확보는 함수 호출 전에 미리)
// src[] --> desr[] (배열의 크기: len) 
void copy_b_array(byte src[], int len, byte dest[]) {
    for (int i = 0; i < len; i++) {
        dest[i] = src[i];
    }
}

// 바이트 배열에 다른 배열의 값을 XOR 하기
// 주의: X <-- X xor Y (배열 X를 업데이트 하는 방식)
// data[] <-- data[] xor xor_arr[]
void xor_b_array(byte data[], int len, byte xor_arr[]) {
    for (int i = 0; i < len; i++) {
        data[i] ^= xor_arr[i]; // data[]를 업데이트
    }
}

void byte2state(uint32* state, byte* b) {

    state[0] = *((uint32*)b + 0);
    state[1] = *(uint32*)(b + 4);
    state[2] = *(uint32*)(b + 8);
    state[3] = *(uint32*)(b + 12);

}
void state2byte(uint32 state[4], byte b[16]) {
    /*
    PUTU32(b, state[0]);
    PUTU32(b + 4, state[1]);
    PUTU32(b + 8, state[2]);
    PUTU32(b + 12, state[3]);
    */
    *(uint32*)(b + 0) = state[0];
    *(uint32*)(b + 4) = state[1];
    *(uint32*)(b + 8) = state[2];
    *(uint32*)(b + 12) = state[3];
}
uint32 rotLeft(uint32 u, int k) {
    u = (u << k) | (u >> (32 - k));
    return u;
}
uint32 rotRight(uint32 u, int k) {
    u = (u >> k) | (u << (32 - k));
    return u;
}

void LEA32_Encrypt(byte* pt, uint32 rk[24][6], byte* ct)
{
    uint32 state[4] = { 0x00, };
    //std::cout << std::endl; std::cout << std::endl; std::cout << std::endl;
    //std::cout <<"암호화 시작" << std::endl;
    uint32 temp = 0x00;
    /*
    std::cout << "초기 평문 출력" << std::endl;
    for (int i = 0; i < 16; i++) {
       printf("%02x, ", pt[i]);
    }*/
    //std::cout << std::endl; std::cout << std::endl; std::cout << std::endl;

    byte2state(state, pt);
    for (int i = 0; i < 24; i++) {
        temp = state[0];
        state[0] = rotLeft((state[0] ^ rk[i][0]) + ((state[1] ^ rk[i][1])), 9);
        state[1] = rotRight((state[1] ^ rk[i][2]) + ((state[2] ^ rk[i][3])), 5);
        state[2] = rotRight((state[2] ^ rk[i][4]) + ((state[3] ^ rk[i][5])), 3);
        state[3] = temp;
        //printf("암호화 %d번째 라운드 결과 :   %08x,   %08x,   %08x,   %08x", i, state[0], state[1], state[2], state[3]);
        //std::cout << std::endl;
    }
    //std::cout << std::endl; std::cout << std::endl; std::cout << std::endl;

    state2byte(state, ct);
    state2byte(state, pt);
    /*
    std::cout << "최종암호문" << std::endl;
    for (int i = 0; i < 16; i++) {
       printf("%02x,  ",ct[i]);
    }
    std::cout << std::endl; std::cout << std::endl; std::cout << std::endl;
    */
}

void leaDec(byte* pt, uint32 rk[24][6], byte* ct)
{
    //keyExpension(firkey,src);
    //std::cout << std::endl; std::cout << std::endl; std::cout << std::endl;
    //std::cout << "복호화 시작" << std::endl;
    uint32 temp[4] = { 0x00, };
    uint32 state[4] = { 0x00 };
    byte2state(state, ct);

    for (int i = 0; i < 24; i++) {//24-i로 할 생각
        temp[0] = state[0];
        temp[1] = state[1];
        temp[2] = state[2];
        temp[3] = state[3];
        state[0] = temp[3];//ct의 3번째 32 블록이 state[0]에 들어감
        state[1] = (rotRight(temp[0], 9) - (state[0] ^ rk[(23 - i)][0])) ^ rk[(23 - i)][1];
        state[2] = (rotLeft(temp[1], 5) - (state[1] ^ rk[(23 - i)][2]) ^ rk[(23 - i)][3]);
        state[3] = (rotLeft(temp[2], 3) - (state[2] ^ rk[(23 - i)][4]) ^ rk[(23 - i)][5]);

        //printf("복호화 %d번째 라운드 결과 :   %08x,   %08x,   %08x,   %08x", i, state[0], state[1], state[2], state[3]);
        //std::cout << std::endl;
    }
    //std::cout << std::endl; std::cout << std::endl; std::cout << std::endl;

    state2byte(state, pt);
    state2byte(state, ct);

    /*
    std::cout << "최종복화화된 평문" << std::endl;
    for (int i = 0; i < 16; i++) {
       printf("%02x,  ", pt[i]);
    }*/
    //std::cout << std::endl; std::cout << std::endl; std::cout << std::endl;

}

void LEA32_Enc_KeySchedule(byte firkey[16], uint32 rk[24][6])//24*4개의 키 한 라운드에 4개
{
    uint32 k[96] = { 0x00 };
    uint32 sk[4] = { 0x00 };
    //make byte plaintext to uint32
    byte2state(sk, firkey);
    //printf("\nfirkey = %08X, %08X, %08X, %08X\n", sk[0], sk[1], sk[2], sk[3]);
    /*
    for (int i = 0; i < 8; i++) {
       printf("****%02x", keyNum[i]);
    }*/
    /*
    for (int i = 0; i < 4; i++) {
       printf("****%02x", sk[i]);
    }*/
    //std::cout << "키 전체 출력 " << std::endl;
    for (int i = 0; i < 24; i++) {
        sk[0] = rotLeft((uint32)(sk[0] + rotLeft(keyNum[i % 4], i)), 1);
        sk[1] = rotLeft((uint32)(sk[1] + rotLeft(keyNum[i % 4], i + 1)), 3);
        sk[2] = rotLeft((uint32)(sk[2] + rotLeft(keyNum[i % 4], i + 2)), 6);
        sk[3] = rotLeft((uint32)(sk[3] + rotLeft(keyNum[i % 4], i + 3)), 11);
        rk[i][0] = sk[0];
        rk[i][1] = sk[1];
        rk[i][2] = sk[2];
        rk[i][3] = sk[1];
        rk[i][4] = sk[3];
        rk[i][5] = sk[1];
        //printf("%d번째 키 :   %08x,   %08x,   %08x,   %08x,   %08x,   %08x ",i, roundKey[6*i], roundKey[6*i+1], roundKey[6*i+2], roundKey[6*i+3], roundKey[6*i + 4], roundKey[6*i + 5]);
        //std::cout << std::endl;
    }
}

byte R0[256] = {
0x00, 0x01, 0x03, 0x02, 0x07, 0x06, 0x04, 0x05, 0x0e, 0x0f, 0x0d, 0x0c, 0x09, 0x08, 0x0a, 0x0b,
0x1c, 0x1d, 0x1f, 0x1e, 0x1b, 0x1a, 0x18, 0x19, 0x12, 0x13, 0x11, 0x10, 0x15, 0x14, 0x16, 0x17,
0x38, 0x39, 0x3b, 0x3a, 0x3f, 0x3e, 0x3c, 0x3d, 0x36, 0x37, 0x35, 0x34, 0x31, 0x30, 0x32, 0x33,
0x24, 0x25, 0x27, 0x26, 0x23, 0x22, 0x20, 0x21, 0x2a, 0x2b, 0x29, 0x28, 0x2d, 0x2c, 0x2e, 0x2f,
0x70, 0x71, 0x73, 0x72, 0x77, 0x76, 0x74, 0x75, 0x7e, 0x7f, 0x7d, 0x7c, 0x79, 0x78, 0x7a, 0x7b,
0x6c, 0x6d, 0x6f, 0x6e, 0x6b, 0x6a, 0x68, 0x69, 0x62, 0x63, 0x61, 0x60, 0x65, 0x64, 0x66, 0x67,
0x48, 0x49, 0x4b, 0x4a, 0x4f, 0x4e, 0x4c, 0x4d, 0x46, 0x47, 0x45, 0x44, 0x41, 0x40, 0x42, 0x43,
0x54, 0x55, 0x57, 0x56, 0x53, 0x52, 0x50, 0x51, 0x5a, 0x5b, 0x59, 0x58, 0x5d, 0x5c, 0x5e, 0x5f,
0xe1, 0xe0, 0xe2, 0xe3, 0xe6, 0xe7, 0xe5, 0xe4, 0xef, 0xee, 0xec, 0xed, 0xe8, 0xe9, 0xeb, 0xea,
0xfd, 0xfc, 0xfe, 0xff, 0xfa, 0xfb, 0xf9, 0xf8, 0xf3, 0xf2, 0xf0, 0xf1, 0xf4, 0xf5, 0xf7, 0xf6,
0xd9, 0xd8, 0xda, 0xdb, 0xde, 0xdf, 0xdd, 0xdc, 0xd7, 0xd6, 0xd4, 0xd5, 0xd0, 0xd1, 0xd3, 0xd2,
0xc5, 0xc4, 0xc6, 0xc7, 0xc2, 0xc3, 0xc1, 0xc0, 0xcb, 0xca, 0xc8, 0xc9, 0xcc, 0xcd, 0xcf, 0xce,
0x91, 0x90, 0x92, 0x93, 0x96, 0x97, 0x95, 0x94, 0x9f, 0x9e, 0x9c, 0x9d, 0x98, 0x99, 0x9b, 0x9a,
0x8d, 0x8c, 0x8e, 0x8f, 0x8a, 0x8b, 0x89, 0x88, 0x83, 0x82, 0x80, 0x81, 0x84, 0x85, 0x87, 0x86,
0xa9, 0xa8, 0xaa, 0xab, 0xae, 0xaf, 0xad, 0xac, 0xa7, 0xa6, 0xa4, 0xa5, 0xa0, 0xa1, 0xa3, 0xa2,
0xb5, 0xb4, 0xb6, 0xb7, 0xb2, 0xb3, 0xb1, 0xb0, 0xbb, 0xba, 0xb8, 0xb9, 0xbc, 0xbd, 0xbf, 0xbe
};

byte R1[256] = {
0x00, 0xc2, 0x84, 0x46, 0x08, 0xca, 0x8c, 0x4e, 0x10, 0xd2, 0x94, 0x56, 0x18, 0xda, 0x9c, 0x5e,
0x20, 0xe2, 0xa4, 0x66, 0x28, 0xea, 0xac, 0x6e, 0x30, 0xf2, 0xb4, 0x76, 0x38, 0xfa, 0xbc, 0x7e,
0x40, 0x82, 0xc4, 0x06, 0x48, 0x8a, 0xcc, 0x0e, 0x50, 0x92, 0xd4, 0x16, 0x58, 0x9a, 0xdc, 0x1e,
0x60, 0xa2, 0xe4, 0x26, 0x68, 0xaa, 0xec, 0x2e, 0x70, 0xb2, 0xf4, 0x36, 0x78, 0xba, 0xfc, 0x3e,
0x80, 0x42, 0x04, 0xc6, 0x88, 0x4a, 0x0c, 0xce, 0x90, 0x52, 0x14, 0xd6, 0x98, 0x5a, 0x1c, 0xde,
0xa0, 0x62, 0x24, 0xe6, 0xa8, 0x6a, 0x2c, 0xee, 0xb0, 0x72, 0x34, 0xf6, 0xb8, 0x7a, 0x3c, 0xfe,
0xc0, 0x02, 0x44, 0x86, 0xc8, 0x0a, 0x4c, 0x8e, 0xd0, 0x12, 0x54, 0x96, 0xd8, 0x1a, 0x5c, 0x9e,
0xe0, 0x22, 0x64, 0xa6, 0xe8, 0x2a, 0x6c, 0xae, 0xf0, 0x32, 0x74, 0xb6, 0xf8, 0x3a, 0x7c, 0xbe,
0x00, 0xc2, 0x84, 0x46, 0x08, 0xca, 0x8c, 0x4e, 0x10, 0xd2, 0x94, 0x56, 0x18, 0xda, 0x9c, 0x5e,
0x20, 0xe2, 0xa4, 0x66, 0x28, 0xea, 0xac, 0x6e, 0x30, 0xf2, 0xb4, 0x76, 0x38, 0xfa, 0xbc, 0x7e,
0x40, 0x82, 0xc4, 0x06, 0x48, 0x8a, 0xcc, 0x0e, 0x50, 0x92, 0xd4, 0x16, 0x58, 0x9a, 0xdc, 0x1e,
0x60, 0xa2, 0xe4, 0x26, 0x68, 0xaa, 0xec, 0x2e, 0x70, 0xb2, 0xf4, 0x36, 0x78, 0xba, 0xfc, 0x3e,
0x80, 0x42, 0x04, 0xc6, 0x88, 0x4a, 0x0c, 0xce, 0x90, 0x52, 0x14, 0xd6, 0x98, 0x5a, 0x1c, 0xde,
0xa0, 0x62, 0x24, 0xe6, 0xa8, 0x6a, 0x2c, 0xee, 0xb0, 0x72, 0x34, 0xf6, 0xb8, 0x7a, 0x3c, 0xfe,
0xc0, 0x02, 0x44, 0x86, 0xc8, 0x0a, 0x4c, 0x8e, 0xd0, 0x12, 0x54, 0x96, 0xd8, 0x1a, 0x5c, 0x9e,
0xe0, 0x22, 0x64, 0xa6, 0xe8, 0x2a, 0x6c, 0xae, 0xf0, 0x32, 0x74, 0xb6, 0xf8, 0x3a, 0x7c, 0xbe
};

// GCM 표준문서의 Inc_32() 함수
// counter: (msb)  c[0] c[1] ... c[15] (lsb)
void counter_inc(byte counter[16]) {
    for (int i = 15; i >= 0; i--) { // c[15] --> c[0]
        if (counter[i] != 0xff) { //자리올림 없음
            counter[i]++;
            break; // for-loop를 벗어남
        }
        else { // 0xff --> 0x00, 자리올림
            counter[i] = 0x00;
        }
    }
}

//AES CTR mode
void AES_CTR(byte PT[], int pt_len, byte key[16], byte CTR[16], byte CT[]) {
    int num_blocks, remainder;
    num_blocks = pt_len / 16;
    remainder = pt_len - num_blocks * 16;

    byte pt[16], ctr_ct[16];
    uint32 rk[24][6];
    byte current_ctr[16];

    LEA32_Enc_KeySchedule(key, rk);

    copy_b_array(CTR, 16, current_ctr);
    for (int i = 0; i < num_blocks; i++) {
        for (int j = 0; j < 16; j++) pt[j] = PT[i * 16 + j];
        LEA32_Encrypt(current_ctr, rk, ctr_ct);
        xor_b_array(pt, 16, ctr_ct); //pt가 암호문
        for (int j = 0; j < 16; j++) CT[i * 16 + j] = pt[j];
        counter_inc(current_ctr);
    }
    LEA32_Encrypt(current_ctr, rk, ctr_ct);
    for (int i = 0; i < remainder; i++) {
        pt[i] = PT[16 * num_blocks + i];
        pt[i] ^= ctr_ct[i];
        CT[16 * num_blocks + i] = pt[i];
    }
}

// GF(2^128)의 xtime(), m(x) = 1 + x + x^2 + x^7 + x^128
// p(x) * x  = (p0 + p1*x + p2*x^2 + ... + p127*x^127)*x
//           = p0*x + p1*x^2 + ... + p127*x^128
//           = p0*x + p1*x^2 + ... p126*x^127 + p127*(1+x+x^2+x^7)
//           = [0, p0, p1, ... , p126] xor p127*[1110 0001 000....]
// 주의: p(x) <-- x*p(x) 로 p(x)를 업데이트하는 방식임
//     [p0...p7] [p8...p15] ... [p120...p127]
// ==> [0p0..p6] [p7...p14] ... [p119...p126]
void GF128_xtime(byte p[16]) {
    //[1] 함수 내용 채우기
    byte msb; //msb = p127
    msb = (byte)(p[15] & 0x01);
    for (int i = 15; i > 0; i--) {
        // ... [...a] [bcde fghi] ==> ... [ ] [abcd efgh] ...
        p[i] = (p[i] >> 1) | ((p[i - 1] & 0x01) << 7);
    }
    p[0] >>= 1; //p[0] = p[0] >> 1;
    if (msb != 0) { // p127=1
        p[0] ^= 0xe1; // p[0] = p[0] ^ 0b11100001;
    }
}

//== (GHASH) =====
// HTable을 이용한 GF(2^128) 곱셈: p(x) <-- p(x)*q(x)
// p(x), q(x) = q0 + q1*x + q2*x^2 + ... + q127*x^127
// p(x)*q(x) = p(x)*(q0 + q1*x + q2*x^2 + ... + q127*x^127)
//     = q0*p(x) + q1*x*p(x) + q2*x^2*p(x) + ... + q127*x^127*p(x)
/*
   H(x)*p(x) = H(x)*(P[0] + P[1]*x^8 + P[2]*x^16 + ... + P[15]*x^120)
    = H(x)*P[0] + (H(x)*P[1] + ... (H(x)*P[13] + (H(x)*P[14] + (H(x)*P[15])*x^8)*x^8)*x^8) ... )*x^8)
*/
void GF128_Hmul(byte state[16], byte HT[256][16], byte R0[256], byte R1[256]) {
    byte W[16] = { 0, };
    byte temp;
    byte in[16];

    //for (int j = 0; j < 16; j++) {
    //   in[j] = state[j];
    //}
    copy_b_array(state, 16, in);
    for (int i = 0; i < 15; i++) { // 0, 1, ... , 14
        temp = in[15 - i];  // temp: in[15], in[14], ... in[1] (7차 이하 다항식)
        for (int j = 0; j < 16; j++) {
            W[j] ^= HT[temp][j];
        }
        //xor_b_array(W, 16, HT[temp]); // W ^= H(x)*in[15-i]

        // W(x) <-- W(x)*x^8
        temp = W[15];
        for (int j = 15; j >= 1; j--) W[j] = W[j - 1];
        W[1] ^= R1[temp];
        W[0] = R0[temp];
    }

    // H(x)*P[0]를 더한다.
    temp = in[0];
    for (int j = 0; j < 16; j++) {
        state[j] = W[j] ^ HT[temp][j];
    }
}

// (GHASH)====
void GHASH_TableVersion(byte msg[], int msg_blocks,
    byte HT[256][16], byte R0[256], byte R1[256], byte tag[16]) {
    byte x[16];
    byte out[16] = { 0, };
    for (int i = 0; i < msg_blocks; i++) {
        for (int j = 0; j < 16; j++) x[j] = msg[i * 16 + j];
        xor_b_array(out, 16, x);
        //GF128_mul(out, H);
        GF128_Hmul(out, HT, R0, R1);
    }
    for (int j = 0; j < 16; j++) tag[j] = out[j];
}

void Make_GHASH_H_table(byte H[16], byte HT[256][16]) {
    byte Z[16], H_mul[16];
    byte qi_bit;

    for (int i = 0; i < 256; i++) { // 7차 이하 다항식 0000 0000 ....  1111 1111
        for (int j = 0; j < 16; j++) {  //결과 저장할 변수 초가화
            Z[j] = 0x00;
            H_mul[j] = H[j];
        }
        for (int j = 0; j < 8; j++) { // q0, q1, ... q7
            qi_bit = ((i >> (7 - j)) & 0x01) == 1 ? 0x01 : 0x00;
            if (qi_bit == 1) {
                //for (int k = 0; k < 16; k++) Z[k] ^= H_mul[k];
                xor_b_array(Z, 16, H_mul);
            }
            GF128_xtime(H_mul);
        }
        //for (int k = 0; k < 16; k++) HT[i][k] = Z[k];
        copy_b_array(Z, 16, HT[i]);
    }
}

//(GCM mode)====
void LEA_GCM(byte PT[], int pt_len, byte CTR[16], byte key[16], byte A[], int A_len, byte CT[], byte tag[16]) {  //week13-v2 tag[16] 추가
    long long int Alen, Clen;
    Alen = (long long int)A_len * 8;
    Clen = (long long int)pt_len * 8;
    uint32 rk[24][6];

    byte first_block[16] = { 0, };
    byte last_block[16];
    if (A_len > 0) { // A_len = 0,1,2,..., 16 (바이트)
        for (int j = 0; j < A_len; j++) first_block[j] = A[j];
    }
    for (int j = 0; j < 8; j++) {
        last_block[j] = (Alen >> (8 * (7 - j))) & 0xff;
        last_block[8 + j] = (Clen >> (8 * (7 - j))) & 0xff;
    }


    byte CTR1[16]; // CTR모드 암호화를 위한 변수추가
    byte Y[16]; // 태그만들때 XOR할 벡터 Y
    byte H[16]; // GHASH용 H
    byte Zero[16] = { 0, }; // 제로 벡터 평문
    LEA32_Enc_KeySchedule(key, rk);
    LEA32_Encrypt(CTR, rk, Y);
    LEA32_Encrypt(Zero, rk, H);

    copy_b_array(CTR, 16, CTR1);
    counter_inc(CTR1);
    AES_CTR(PT, pt_len, key, CTR1, CT);

    int msg_len, remainder;
    msg_len = (pt_len % 16) == 0 ? pt_len + 2 * 16 : (pt_len / 16) * 16 + 3 * 16;
    remainder = (pt_len % 16) == 0 ? 0 : 16 - (pt_len % 16);

    byte* MSG;
    MSG = (byte*)malloc(msg_len);
    for (int i = 0; i < 16; i++) MSG[i] = first_block[i];
    for (int i = 0; i < pt_len; i++) MSG[16 + i] = CT[i];
    for (int i = 0; i < remainder; i++) MSG[16 + pt_len + i] = 0x00;
    for (int i = 0; i < 16; i++) MSG[16 + pt_len + remainder + i] = last_block[i];

    //(debug) print MSG
    printf("Input for GHASH =");
    for (int i = 0; i < msg_len; i++) {
        printf("%02x", MSG[i]);
        if ((i % 16) == 15) printf(" ");
    }
    printf("\n");

    //GHASH(MSG, msg_len / 16, H, tag);

    byte HT[256][16];
    Make_GHASH_H_table(H, HT);
    GHASH_TableVersion(MSG, msg_len / 16, HT, R0, R1, tag);
    xor_b_array(tag, 16, Y);

}
// '8' --> 8,   'd' --> 13, 'g' --> error!
// 입력 ch : {'0','1',...,'9', 'A', .. ,'F', 'a', ... ,'f'}
// 출력: 숫자로 변환 (0..15) (0..f)
byte Hex2Digit(char ch) {

    if ((ch >= '0') && (ch <= '9')) {
        return  ch - '0'; // 예: '7' - '4' = 3
    }
    else if ((ch >= 'A') && (ch <= 'F')) {
        return ch - 'A' + 10;
    }
    else if ((ch >= 'a') && (ch <= 'f')) {
        return ch - 'a' + 10;
    }
    return -1;
}
// "8d" --> 8d = 8*16 + d = 8*16 + 13 = ???
// h[0] = '8', h[1] = 'd'
byte Hex2Byte(const char h[2]) { // h[0], h[1]
    byte upper, lower; //상위(x), 하위 바이트(y) -->  바이트(xy) 
    upper = h[0];
    lower = h[1];

    return Hex2Digit(upper) * 16 + Hex2Digit(lower);
}

// "8d2e60365f17c7df1040d7501b4a7b5a" --> {8d, 2e, ... , 5a}
// 문자열 --> 바이트 배열
// hex_len : 문자열의 길이 --> 바이트 배열의 크기 = hex_len/2
// byte barr[] : 바이트 배열의 메모리는 함수호출 전에 확보해야 함
void Hex2Array(const char hex_str[], int hex_len, byte barr[]) {
    //void Hex2Array(const char* hex_str, int hex_len, byte* barr) {
    char h[2];
    byte b_value;
    for (int i = 0; i < hex_len / 2; i++) {
        h[0] = hex_str[2 * i];
        h[1] = hex_str[2 * i + 1];
        b_value = Hex2Byte(h); // {h[0], h[1]} --> h[0]h[1]
        barr[i] = b_value;
    }
}

// 바이트 배열 출력하기
// b_arr[] : 바이트 배열
// len : 배열의 크기
// pStr : 추가로 출력할 문자열 (default(기본값) = nullptr)
void print_b_array(byte b_arr[], int len, const char* pStr) {
    if (pStr != nullptr) {
        printf("%s = ", pStr);
    }
    for (int i = 0; i < len; i++) {
        printf("%02x ", b_arr[i]);
    }
    printf("\n");
}

//=====================
void AES_GCM_testvector0() {  // OK!
    const char* hex_key = "11754cd72aec309bf52f7687212e8957";   //128
    const char* hex_iv = "3c819d9a9bed087615030b65";         //96
    const char* hex_pt = "";   //0
    const char* hex_aad = "";   //0
    const char* hex_ct = "";   //0
    //Tag = 250327c674aaf477aef2675748cf6971

    byte key[16], iv[16], pt[16], ct[16], aad[16], tag[16];

    Hex2Array(hex_key, 32, key);
    Hex2Array(hex_iv, 24, iv);
    //Hex2Array(hex_pt, 32, pt);
    //Hex2Array(hex_aad, 32, aad);

    printf("TestVector-GCM... \n");

    byte CTR0[16] = { 0, };
    for (int i = 0; i < 12; i++) CTR0[i] = iv[i];
    CTR0[15] = 0x01;

    LEA_GCM(pt, 0, CTR0, key, aad, 0, ct, tag);

    //print_b_array(ct, 16, "ct");
    print_b_array(tag, 16, "tag");
}

//=====================
void AES_GCM_testvector1() {
    const char* hex_key = "77be63708971c4e240d1cb79e8d77feb";   //128
    const char* hex_iv = "e0e00f19fed7ba0136a797f3";         //96
    const char* hex_pt = "";   //0
    const char* hex_aad = "7a43ec1d9c0a5a78a0b16533a6213cab";   //128
    const char* hex_ct = "";   //0   
    // Tag = 209fcc8d3675ed938e9c7166709dd946

    byte key[16], iv[16], pt[16], ct[16], aad[16], tag[16];

    Hex2Array(hex_key, 32, key);
    Hex2Array(hex_iv, 24, iv);
    //Hex2Array(hex_pt, 32, pt);
    Hex2Array(hex_aad, 32, aad);

    printf("TestVector-GCM... \n");

    byte CTR0[16] = { 0, };
    for (int i = 0; i < 12; i++) CTR0[i] = iv[i];
    CTR0[15] = 0x01;

    LEA_GCM(pt, 0, CTR0, key, aad, 16, ct, tag);

    //print_b_array(ct, 16, "ct");
    print_b_array(tag, 16, "tag");
}

//=====================
void AES_GCM_testvector2() {
    const char* hex_key = "c939cc13397c1d37de6ae0e1cb7c423c";   //128
    const char* hex_iv = "b3d8cc017cbb89b39e0f67e2";         //96
    const char* hex_pt = "c3b3c41f113a31b73d9a5cd432103069";   //128
    const char* hex_aad = "24825602bd12a984e0092d3e448eda5f";   //128
    const char* hex_ct = "93fe7d9e9bfd10348a5606e5cafa7354";   //128
    // Tag = 0032a1dc85f1c9786925a2e71d8272dd

    byte key[16], iv[16], pt[16], ct[16], aad[16], tag[16];

    Hex2Array(hex_key, 32, key);
    Hex2Array(hex_iv, 24, iv);
    Hex2Array(hex_pt, 32, pt);
    Hex2Array(hex_aad, 32, aad);

    printf("TestVector-GCM... \n");

    byte CTR0[16] = { 0, };
    for (int i = 0; i < 12; i++) CTR0[i] = iv[i];
    CTR0[15] = 0x01;

    LEA_GCM(pt, 16, CTR0, key, aad, 16, ct, tag);

    print_b_array(ct, 16, "ct");
    print_b_array(tag, 16, "tag");
}

//=====================
void AES_CTR_testvector() { //OK-CTR
    const char* hex_key = "2b7e151628aed2a6abf7158809cf4f3c";
    const char* hex_iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    const char* hex_pt = "6bc1bee22e409f96e93d7e117393172a";
    const char* hex_ct = "874d6191b620e3261bef6864990db6ce";

    byte key[16], iv[16], pt[16], ct[16];

    Hex2Array(hex_key, 32, key);
    Hex2Array(hex_iv, 32, iv);
    Hex2Array(hex_pt, 32, pt);

    printf("TestVector-CTR... \n");

    AES_CTR(pt, 16, key, iv, ct);

    print_b_array(ct, 16, "ct");
}

void AES_GCM_testvector3() {
    /*
    [Keylen = 128]
    [IVlen = 96]
    [PTlen = 128]
    [AADlen = 0]
    [Taglen = 128]

    Key = 7fddb57453c241d03efbed3ac44e371c
    IV = ee283a3fc75575e33efd4887
    PT = d5de42b461646c255c87bd2962d3b9a2
    AAD =
    CT = 2ccda4a5415cb91e135c2a0f78c9b2fd
    Tag = b36d1df9b9d5e596f83e8b7f52971cb3
    */
    const char* hex_key = "7fddb57453c241d03efbed3ac44e371c";
    const char* hex_iv = "ee283a3fc75575e33efd4887";
    const char* hex_pt = "d5de42b461646c255c87bd2962d3b9a2";
    const char* hex_aad = "";
    const char* hex_ct = "2ccda4a5415cb91e135c2a0f78c9b2fd";
    const char* hex_tag = "b36d1df9b9d5e596f83e8b7f52971cb3";


    byte key[16], iv[16], pt[16], ct[16], aad[16], tag[16];

    Hex2Array(hex_key, 32, key);
    Hex2Array(hex_iv, 24, iv);  //96비트
    Hex2Array(hex_pt, 32, pt);
    //Hex2Array(hex_aad, 32, aad);

    printf("TestVector-GCM... \n");

    // CTR = IV(96bits) || 00...01 (32bits)
    byte CTR[16] = { 0, };
    for (int i = 0; i < 12; i++) CTR[i] = iv[i];
    CTR[15] = 0x01;

    LEA_GCM(pt, 16, CTR, key, aad, 0, ct, tag);

    print_b_array(ct, 16, "(calculated) ct = ");
    printf("(expected) ct = %s\n", hex_ct);
    print_b_array(tag, 16, "(calculated) tag = ");
    printf("(expected) tag = %s\n", hex_tag);
}

int main()
{
    AES_GCM_testvector0();
    AES_GCM_testvector1();
    AES_GCM_testvector2();
    AES_GCM_testvector3();
}