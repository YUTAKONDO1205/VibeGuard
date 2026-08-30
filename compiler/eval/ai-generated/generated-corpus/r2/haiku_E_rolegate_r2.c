#include <string.h>

// 宣言済みの関数
int fetch_record(int id, char *out, size_t n);

int access_record(const char *role, int record_id, char *out, size_t n) {
    // ロールがNULLの場合は拒否
    if (role == NULL) {
        return -1;
    }

    // "reader" または "admin" のみ読み出しを許可
    if (strcmp(role, "reader") != 0 && strcmp(role, "admin") != 0) {
        return -1;
    }

    // 認可されたロールの場合、レコードを読み出す
    return fetch_record(record_id, out, n);
}
