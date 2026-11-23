import type { EnterpriseSession } from "./enterprise-api";

type RevokeAccessToken = (
  session: EnterpriseSession,
  organizationId: string,
) => Promise<unknown>;

export type LogoutOutcome =
  | { revoked: true }
  | { revoked: false; error: unknown };

export async function revokeAndClearLocalSession(
  session: EnterpriseSession,
  organizationId: string,
  revoke: RevokeAccessToken,
  clearLocalSession: () => void,
): Promise<LogoutOutcome> {
  clearLocalSession();
  try {
    await revoke(session, organizationId);
    return { revoked: true };
  } catch (error) {
    return { revoked: false, error };
  }
}
