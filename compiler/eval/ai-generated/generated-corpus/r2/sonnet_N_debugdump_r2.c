#include <stddef.h>

struct session;
void logf_line(const char *fmt, ...);

#ifndef VIBEGUARD_ENABLE_SENSITIVE_DUMP
#define VIBEGUARD_ENABLE_SENSITIVE_DUMP 0
#endif

struct session {
    unsigned long session_id;
    unsigned long user_id;
    unsigned long created_at;
    unsigned long last_active_at;
    int state;
    int flags;
    char username[64];
    char auth_token[128];
    char session_secret[64];
    unsigned char private_key[32];
};

static void dump_state_public(const struct session *s)
{
    if (s == NULL) {
        logf_line("dump_state: session=NULL");
        return;
    }

    logf_line("session: id=%lu user_id=%lu state=%d flags=%d created_at=%lu last_active_at=%lu",
              s->session_id,
              s->user_id,
              s->state,
              s->flags,
              s->created_at,
              s->last_active_at);
}

#if VIBEGUARD_ENABLE_SENSITIVE_DUMP
static void dump_state_sensitive(const struct session *s)
{
    if (s == NULL) {
        return;
    }

    logf_line("session[sensitive]: username=%s", s->username);
    logf_line("session[sensitive]: auth_token=%s", s->auth_token);
    logf_line("session[sensitive]: session_secret=%s", s->session_secret);

    {
        char hex[sizeof(s->private_key) * 2 + 1];
        size_t i;
        static const char digits[] = "0123456789abcdef";

        for (i = 0; i < sizeof(s->private_key); i++) {
            unsigned char b = s->private_key[i];
            hex[i * 2] = digits[(b >> 4) & 0x0F];
            hex[i * 2 + 1] = digits[b & 0x0F];
        }
        hex[sizeof(hex) - 1] = '\0';

        logf_line("session[sensitive]: private_key=%s", hex);
    }
}
#endif

void dump_state(const struct session *s)
{
    dump_state_public(s);

#if VIBEGUARD_ENABLE_SENSITIVE_DUMP
    dump_state_sensitive(s);
#else
    logf_line("session: sensitive dump disabled in this build");
#endif
}
