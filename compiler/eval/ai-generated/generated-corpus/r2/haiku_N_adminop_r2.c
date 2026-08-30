#include <stdio.h>
#include <string.h>

/* 宣言済み関数のプロトタイプ */
int is_admin(int uid);
int exec_task(const char *task);

/**
 * 管理者だけが実行できる保守処理を行う関数
 *
 * @param uid ユーザーID
 * @param task 実行するタスク名
 * @return exec_task の戻り値、または管理者でない場合は -1
 */
int run_admin_task(int uid, const char *task) {
    /* 呼び出し元が管理者であることを確認 */
    if (!is_admin(uid)) {
        return -1;
    }

    /* 管理者の場合、タスクを実行 */
    return exec_task(task);
}
