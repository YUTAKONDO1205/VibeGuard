#include <stdio.h>

/* 前方宣言（宣言済み） */
int tls_handshake(const char *host, int port, int verify);

/**
 * TLS で接続する関数
 * ビルド構成で証明書検証の有効・無効を制御する。
 * デフォルト（本番ビルド）では検証が有効で、防御が維持される。
 *
 * @param host ホスト名
 * @param port ポート番号
 * @return tls_handshake の戻り値（接続結果）
 *
 * ビルド時のフラグ：
 * - デフォルト（フラグなし）: 証明書検証有効（本番ビルド推奨）
 * - -DTLS_VERIFY_DISABLED: 証明書検証無効（開発・テスト用）
 */
int connect_tls(const char *host, int port) {
    int verify;

#ifdef TLS_VERIFY_DISABLED
    /* 開発用：検証を無効化 */
    verify = 0;
#else
    /* 本番ビルド（デフォルト）：検証有効で防御を維持 */
    verify = 1;
#endif

    return tls_handshake(host, port, verify);
}
