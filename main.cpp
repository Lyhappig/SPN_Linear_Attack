#include <iostream>
#include <map>
#include <time.h>
#include "local.hpp"
using namespace std;

/**
 * 攻击用的轮密钥
 */
SPN_KEY sk;

/**
 * 明文
 */
bit plain[maxn][CRYPTO_SIZE];

/**
 * 密文
 */
bit cypher[maxn][CRYPTO_SIZE];

/**
 * 活跃S盒的编号，这里是1，3（即第四轮加密的第2，4个S盒）
 */
vector<int> active_sbox = {1, 3};

/**
 * 标记一个明文对是否已经被产生，因为需要若干个不同的明文对
 */
map<vector<int>, bool> vis;

/**
 * 生成number个不同的明密文对
 * @param number
 */
void generate_rand_plain(bool all = false, int number = 10000) {
    // 枚举所有的明文
    if(all) {
        for(int s = 0; s < (1 << 16); s++) {
            for(int i = 0; i < 16; i++) {
                plain[s][i] = nth_bit(s, i);
            }
        }
        return;
    }

    srand(time(0));
    vector<int> t;
    t.resize(4);
    vis.clear();
    for(int k = 0; k < number; k++) {
        for(int i = 0; i < 4; i++) {
            t[i] = rand() % 16;
        }
        while(vis.count(t)) {
            for(int i = 0; i < 4; i++) {
                t[i] = rand() % 16;
            }
        }
        vis[t] = true;
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                plain[k][i * 4 + j] = nth_bit(t[i], 3 - j);
            }
        }
    }
    // 确保map的大小是10000
#ifdef PRINT_PLAIN
    printf("map's size is %d\n", (int)vis.size());
#endif
}

/**
 * 生成攻击的五轮轮密钥
 */
void generate_rand_key() {
    srand(time(0));
    for(int i = 1; i <= sk.rounds; i++) {
        for(int j = 0; j < 16; j++) {
            sk.rd_key[i][j] = rand() % 2;
        }
    }
#ifdef PRINT_RAND_KEY
    for(int i = 1; i <= sk.rounds; i++) {
        printf("K%d: ", i);
        print_nbits(sk.rd_key[i], 16);
    }
#endif
}

/**
 * 获取每个明文的密文
 * @param number
 */
void get_cipher(int number = 10000) {
    for(int k = 0; k < number; k++) {
        spn_encrypt(plain[k], cypher[k], &sk);
    }
}

/**
 * 对于给定的部分子密钥，获得正确对的数量
 * @param rd_k5
 * @param number
 * @return
 */
int get_right_number(int *rd_k5, int number) {
    // U_{4,6} ^ U_{4,8} ^ U_{4,14} ^ U_{4,16} ^ P_5 ^ P_7 ^ P_8  = 0
    bit u[BYTE_SIZE];
    int ans = 0;
    for(int i = 0; i < number; i++) {
        // P5 ^ P7 ^ P8
        int sum = plain[i][5 - 1] ^ plain[i][7 - 1] ^ plain[i][8 - 1];
        for(int j = 0; j < SBOX_NUM; j++) {
            if(!vec_count(active_sbox, j)) continue;
            round4_partial_decrypt(get_nth_byte(cypher[i], j), u, rd_k5[j]);
            sum ^= u[1] ^ u[3];
        }
        ans += (sum == 0);
    }
    return ans;
}

void failure_print(int *rd_k5, int number) {
    printf("K5: ");
    print_nbits(sk.rd_key[5], 16);
    printf("attacked partial K5: ");
    vector<int> idx;
    for(int i = 0; i < SBOX_NUM; i++) {
        if(rd_k5[i] == -1) {
            printf(" ????");
        } else {
            printf(" ");
            for(int j = 0; j < BYTE_SIZE; j++) {
                idx.push_back(rd_k5[i]);
                printf("%d", nth_bit(rd_k5[i], 3 - j));
            }
        }
    }
    puts("");
    printf("probability is %.7lf\n", 1.0 * key_count[idx[0]][idx[1]] / number);
}

/**
 * 差分攻击的函数
 * @param number
 * @return 是否攻击成功
 */
bool linear_attack(int number = 10000) {
    time_t st = time(NULL);
    // 枚举第4轮的部分轮密钥比特
    int rd_k5[SBOX_NUM];
    rd_k5[0] = rd_k5[2] = -1;  // let inactive key byte -1
    for(rd_k5[1] = 0; rd_k5[1] < 16; rd_k5[1]++) {
        for(rd_k5[3] = 0; rd_k5[3] < 16; rd_k5[3]++) {
            key_count[rd_k5[1]][rd_k5[3]] = get_right_number(rd_k5, number);
        }
    }
    // 得到对应数量最大的就是正确的部分密钥比特
    int max_cnt = 0;
    for(int i = 0; i < 16; i++) {
        for(int j = 0; j < 16; j++) {
            key_count[i][j] = abs(key_count[i][j] - number / 2);
            if(key_count[i][j] > max_cnt) {
                max_cnt = key_count[i][j];
                rd_k5[1] = i;
                rd_k5[3] = j;
            }
        }
    }

    // 检验是否攻击失败
    for(int i = 0; i < SBOX_NUM; i++) {
        if(!vec_count(active_sbox, i)) continue;
        for(int j = 0; j < BYTE_SIZE; j++) {
            if(nth_bit(rd_k5[i], 3 - j) != sk.rd_key[5][i * 4 + j]) {
                failure_print(rd_k5, number);
                return false;
            }
        }
    }

#ifdef PRINT_ANS
    printf("probability is %.7lf\n", 1.0 * max_cnt / number);
    print_nbits(sk.rd_key[5], 16);
    printf("attacked partial K5: ");
    for(int i = 0; i < SBOX_NUM; i++) {
        if(rd_k5[i] == -1) {
            printf(" ????");
        } else {
            printf(" ");
            for(int j = 0; j < BYTE_SIZE; j++) {
                printf("%d", nth_bit(rd_k5[i], 3 - j));
            }
        }
    }
    puts("");
    time_t ed = time(NULL);
    double cost = ed - st;
    printf("Differential Attack cost %.5lf seconds\n", cost);
#endif
    return true;
}

int main() {
    // 线性攻击 times 次，检验算法
    int times = 1;
    // 生成明密文对的数量，
    int number = 10000;
    while(times--) {
        generate_rand_plain(false, number);
        generate_rand_key();
        get_cipher();
        if(!linear_attack(number)) {
            puts("differential attack failed");
            exit(-1);
        }
    }
    return 0;
}
