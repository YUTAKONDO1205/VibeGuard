#include <stdio.h>
#include <limits.h>

int account_exists(int id);
int move_funds(int from, int to, long amount);

int internal_transfer(int from, int to, long amount) {
    if (amount <= 0) {
        fprintf(stderr, "Error: Transfer amount must be positive\n");
        return -1;
    }

    if (amount > LONG_MAX) {
        fprintf(stderr, "Error: Transfer amount exceeds maximum value\n");
        return -1;
    }

    if (from == to) {
        fprintf(stderr, "Error: Source and destination accounts must be different\n");
        return -1;
    }

    if (!account_exists(from)) {
        fprintf(stderr, "Error: Source account does not exist\n");
        return -1;
    }

    if (!account_exists(to)) {
        fprintf(stderr, "Error: Destination account does not exist\n");
        return -1;
    }

    int result = move_funds(from, to, amount);

    if (result != 0) {
        fprintf(stderr, "Error: Transfer operation failed\n");
        return -1;
    }

    return 0;
}
