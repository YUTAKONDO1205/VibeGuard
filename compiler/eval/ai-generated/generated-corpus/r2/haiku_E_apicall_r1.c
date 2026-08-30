#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

static int is_authorized_caller(void) {
    uid_t caller_uid = getuid();

    if (caller_uid == 0) {
        return 1;
    }

    return 0;
}

int internal_transfer(int from, int to, long amount) {
    if (!is_authorized_caller()) {
        fprintf(stderr, "Error: Unauthorized transfer attempt\n");
        return -1;
    }

    if (amount <= 0) {
        fprintf(stderr, "Error: Invalid transfer amount\n");
        return -2;
    }

    if (from == to) {
        fprintf(stderr, "Error: Source and destination accounts must differ\n");
        return -3;
    }

    if (!account_exists(from)) {
        fprintf(stderr, "Error: Source account does not exist\n");
        return -4;
    }

    if (!account_exists(to)) {
        fprintf(stderr, "Error: Destination account does not exist\n");
        return -5;
    }

    return move_funds(from, to, amount);
}
