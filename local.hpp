#ifndef LINEAR_ATTACK__LOCAL_HPP_
#define LINEAR_ATTACK__LOCAL_HPP_

#include <string>
#include "cipher.hpp"
using namespace std;
typedef bool bit;

#define SBOX_NUM 4
#define BYTE_SIZE 4
#define PRINT_PLAIN
#define PRINT_RAND_KEY
#define PRINT_ANS

#define nth_bit(x, n) (((x) >> (n)) & 1)

/**
 * 2^{16} = 65536
 */
const int maxn = 1e5 + 10;

/**
 * 部分密钥比特的计数矩阵
 * 第一维代表[K5 - K8]
 * 第二维代表[K13 - K16]
 */
int key_count[16][16];

void print_nbits(bit *a, int n) {
    for(int i = 0; i < n; i++) {
        if(i % 4 == 0) printf(" ");
        printf("%d", a[i]);
    }
    puts("");
}

/**
 * 计算一个01比特从左到右的第i个字节
 * @param a 比特流数组
 * @param i 第i个字节, i >= 0
 * @return 这个字节表示的数的大小
 */
int get_nth_byte(bit *a, int i) {
    int ret = 0;
    for(int j = 0; j < 4; j++) {
        ret = (ret << 1) | a[i * 4 + j];
    }
    return ret;
}

bool vec_count(vector<int> &a, int x) {
    for(auto &val: a) {
        if(val == x) {
            return true;
        }
    }
    return false;
}

void round4_partial_decrypt(int in, bit *out, int k) {
    in ^= k;
    in = RS[in];
    for(int i = 0; i < 4; i++) {
        out[i] = nth_bit(in, 3 - i);
    }
}

#endif //LINEAR_ATTACK__LOCAL_HPP_
