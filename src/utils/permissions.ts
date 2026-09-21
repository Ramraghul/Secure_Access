// src/utils/permissions.ts — Pure RBAC permission matching (no DB access)

export const PERMISSION_ACTIONS = ["create", "read", "update", "delete", "manage", "export"] as const;

// Resources the API checks: user, role, user-role, audit, client. "*" in a grant matches all of them.

export interface PermissionGrant {
  action:   string;
  resource: string;
}

/**
 * Does any held grant allow `action` on `resource`?
 *  - "manage" implies every action on its resource
 *  - resource "*" matches every resource
 * So the seeded admin grant "manage:*" allows everything.
 */
export function grants(held: PermissionGrant[], action: string, resource: string): boolean {
  return held.some(p =>
    (p.action === action || p.action === "manage") &&
    (p.resource === resource || p.resource === "*")
  );
}

export const toPermissionString = (p: PermissionGrant): string => `${p.action}:${p.resource}`;
