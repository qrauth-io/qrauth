import { ROLE_HIERARCHY, type MembershipRole } from './constants.js';

/**
 * Who may change or remove whom in an organization. The API enforces these
 * (services/membership-admin.ts); the dashboard uses them to offer only the
 * actions the API will accept. ROLE_HIERARCHY is ordered highest first.
 */

/** An OWNER may act on anyone, other OWNERs included; anyone else only on lower roles. */
export function canManageMember(actorRole: MembershipRole, targetRole: MembershipRole): boolean {
  if (actorRole === 'OWNER') return true;
  return ROLE_HIERARCHY.indexOf(actorRole) < ROLE_HIERARCHY.indexOf(targetRole);
}

/** An OWNER may grant any role; anyone else at most their own. Only an OWNER makes an OWNER. */
export function canGrantRole(actorRole: MembershipRole, newRole: MembershipRole): boolean {
  if (actorRole === 'OWNER') return true;
  return ROLE_HIERARCHY.indexOf(actorRole) <= ROLE_HIERARCHY.indexOf(newRole);
}

/** The roles this actor may give a member, highest first. */
export function grantableRoles(actorRole: MembershipRole): MembershipRole[] {
  return ROLE_HIERARCHY.filter((role) => canGrantRole(actorRole, role));
}
