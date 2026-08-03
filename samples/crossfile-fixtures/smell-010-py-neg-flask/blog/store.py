"""In-memory stand-in for the persistence layer. No authorization happens here."""


class Post:
    def __init__(self, post_id, title, author_id):
        self.post_id = post_id
        self.title = title
        self.author_id = author_id

    def retire(self):
        self.title = ""


class AuditEntry:
    def __init__(self, summary, tenant_id):
        self.summary = summary
        self.tenant_id = tenant_id


_POSTS = [Post(1, "Release notes", 7), Post(2, "Roadmap", 9)]
_AUDIT = [AuditEntry("post retired", 1), AuditEntry("post published", 2)]


def list_posts():
    return list(_POSTS)


def find_post(post_id):
    for post in _POSTS:
        if post.post_id == post_id:
            return post
    return None


def list_audit_entries():
    return list(_AUDIT)
