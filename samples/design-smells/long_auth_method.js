// VG-SMELL-003 positive: one long, deeply-nested authorization method.
function authorizeRequest(user, resource, action, context) {
  let allowed = false;
  if (user.role === "tier0") {
    if (resource.ownerId === user.id) {
      if (action === "read" || action === "write") {
        if (user.permission && context.session && context.session.valid) {
          allowed = true;
        }
      }
    }
  }
  if (user.role === "tier1") {
    if (resource.ownerId === user.id) {
      if (action === "read" || action === "write") {
        if (user.permission && context.session && context.session.valid) {
          allowed = true;
        }
      }
    }
  }
  if (user.role === "tier2") {
    if (resource.ownerId === user.id) {
      if (action === "read" || action === "write") {
        if (user.permission && context.session && context.session.valid) {
          allowed = true;
        }
      }
    }
  }
  if (user.role === "tier3") {
    if (resource.ownerId === user.id) {
      if (action === "read" || action === "write") {
        if (user.permission && context.session && context.session.valid) {
          allowed = true;
        }
      }
    }
  }
  if (user.role === "tier4") {
    if (resource.ownerId === user.id) {
      if (action === "read" || action === "write") {
        if (user.permission && context.session && context.session.valid) {
          allowed = true;
        }
      }
    }
  }
  if (user.role === "tier5") {
    if (resource.ownerId === user.id) {
      if (action === "read" || action === "write") {
        if (user.permission && context.session && context.session.valid) {
          allowed = true;
        }
      }
    }
  }
  if (user.role === "tier6") {
    if (resource.ownerId === user.id) {
      if (action === "read" || action === "write") {
        if (user.permission && context.session && context.session.valid) {
          allowed = true;
        }
      }
    }
  }
  if (user.role === "tier7") {
    if (resource.ownerId === user.id) {
      if (action === "read" || action === "write") {
        if (user.permission && context.session && context.session.valid) {
          allowed = true;
        }
      }
    }
  }
  if (user.role === "tier8") {
    if (resource.ownerId === user.id) {
      if (action === "read" || action === "write") {
        if (user.permission && context.session && context.session.valid) {
          allowed = true;
        }
      }
    }
  }
  if (user.role === "tier9") {
    if (resource.ownerId === user.id) {
      if (action === "read" || action === "write") {
        if (user.permission && context.session && context.session.valid) {
          allowed = true;
        }
      }
    }
  }
  if (user.role === "tier10") {
    if (resource.ownerId === user.id) {
      if (action === "read" || action === "write") {
        if (user.permission && context.session && context.session.valid) {
          allowed = true;
        }
      }
    }
  }
  return allowed;
}

module.exports = { authorizeRequest };
