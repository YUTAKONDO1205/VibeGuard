/*
 * Three functions a reader would never confuse, and one that must not fold.
 *
 * The site's research page says three functions that mean entirely different
 * things came out as the same fourteen bytes of machine code at -O2 on x86-64.
 * That sentence had no evidence inside this repository until this file: the
 * number came from a working note that the ignore rules keep out of the tree,
 * so a reader could not check it and neither could a test.
 *
 * The three subjects are written the way the claim describes them. Each takes a
 * pointer to a different struct, each reads the first int in it, and each
 * returns whether that int is non-zero. To a person the three are an
 * authorization decision, a feature-flag read, and a probe written to mean
 * nothing at all. To a compiler they are one function, because the type names
 * are gone by the time it decides that.
 *
 * `reads_second_field` is the negative control and the reason this file is a
 * measurement rather than a demonstration. It has the same shape as the three
 * and differs only in which field it reads, so it must NOT fold with them. If
 * it ever does, the comparison is matching something other than the code —
 * a truncated read, an empty byte string, a symbol that was not found — and the
 * run has to fail instead of reporting agreement.
 */

struct session { int authorized; };
struct feature { int enabled; };
struct probe   { int value; };
struct pair    { int first; int second; };

/* Subject 1: an authorization decision. */
int is_authorized(const struct session *s) {
  return s->authorized != 0;
}

/* Subject 2: a feature-flag read. Nothing to do with authorization. */
int feature_enabled(const struct feature *f) {
  return f->enabled != 0;
}

/* Subject 3: written to mean nothing. It is here to be meaningless. */
int meaningless_probe(const struct probe *p) {
  return p->value != 0;
}

/* Negative control: reads the SECOND field, so it cannot be the same bytes. */
int reads_second_field(const struct pair *p) {
  return p->second != 0;
}
