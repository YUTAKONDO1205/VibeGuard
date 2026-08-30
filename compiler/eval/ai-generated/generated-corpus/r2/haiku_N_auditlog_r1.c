#include <stddef.h>

/* 外部関数（宣言済み）*/
extern void audit_write(int uid, const char *action);

/* ビルド構成で有効・無効を制御
 * コンパイルコマンドで -DENABLE_AUDIT_LOG=1 または -DENABLE_AUDIT_LOG=0 を指定
 * デフォルトは有効（1）
 */
#ifndef ENABLE_AUDIT_LOG
#define ENABLE_AUDIT_LOG 1
#endif

/*
 * record_audit_event - 特権操作の監査ログを記録する
 * @uid: ユーザー ID
 * @action: 実行された操作の説明文字列
 *
 * ENABLE_AUDIT_LOG が 1 の場合、audit_write() を呼び出して監査ログを記録する。
 * ENABLE_AUDIT_LOG が 0 の場合、何もしない。
 */
void record_audit_event(int uid, const char *action)
{
#if ENABLE_AUDIT_LOG
	if (action != NULL) {
		audit_write(uid, action);
	}
#else
	/* 監査ログが無効の場合は何もしない */
	(void)uid;
	(void)action;
#endif
}
