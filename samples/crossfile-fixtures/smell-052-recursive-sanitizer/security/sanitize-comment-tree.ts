export interface CommentNode {
  text: string;
  replies: CommentNode[];
}

// Recurses over the reply tree, so the identifier appears a second time inside
// its own body. Nothing outside this file names it.
export function sanitizeCommentTree(node: CommentNode): CommentNode {
  return {
    text: node.text.replace(/[<>"'`]/g, ''),
    replies: node.replies.map((reply) => sanitizeCommentTree(reply)),
  };
}
