import { createAnonUser } from "./create-user";
import { createXidRecord, xidExists } from "../xids";
import { deleteSuzinvite } from "./auth";
import { failJson } from "../utils/fail";
import { getConversationInfo } from "../conversation";
import {
  getFncpManagedXidDecision,
  isFncpProviderPolicyUnavailable,
  resolveFncpManagedConversation,
} from "../fncp-provider-policy";
import { getSUZinviteInfo } from "../invites/suzinvites";
import { getUserInfoForUid2 } from "../user";
import { issueAnonymousJWT } from "./anonymous-jwt";
import { isXidAllowed } from "../xids";
import { joinConversation } from "../participant";
import { userHasAnsweredZeQuestions } from "../server-helpers";
import type { ParticipantInfo } from "../d";

interface DeregisterRequest {
  p?: { showPage?: any };
}

interface DeregisterResponse {
  status: (code: number) => {
    json: (data: any) => void;
  };
}

interface JoinRequest {
  p: {
    answers: any;
    uid?: number;
    suzinvite: string;
    zid: number;
    referrer: string;
    parent_url: string;
    xid?: string;
  };
}

interface JoinResponse {
  status: (code: number) => {
    json: (data: {
      pid: number;
      uid?: number;
      token?: string;
      isAnonymous?: boolean;
    }) => void;
  };
}

interface JoinParams {
  answers: any;
  existingAuth: boolean;
  suzinvite: string;
  uid?: number;
  zid: number;
  referrer: string;
  parent_url: string;
  conv?: any;
  user?: any;
  xid?: string;
  [key: string]: any;
}

/**
 * JWT-based logout handler
 * With JWTs, logout is primarily a client-side operation.
 * The server doesn't need to track sessions or clear cookies.
 */
function handle_POST_auth_deregister_jwt(
  req: DeregisterRequest,
  res: DeregisterResponse
): void {
  // With JWT auth, the server doesn't need to do anything
  // The client is responsible for:
  // 1. Removing the JWT from localStorage/memory
  // 2. Optionally calling OIDC logout endpoint

  res.status(200).json({
    status: "success",
    message: "Logout successful. Please remove your JWT token.",
  });
}

async function handle_POST_joinWithInvite(
  req: JoinRequest,
  res: JoinResponse
): Promise<void> {
  try {
    const result = await _joinWithZidOrSuzinvite({
      answers: req.p.answers,
      existingAuth: !!req.p.uid,
      suzinvite: req.p.suzinvite,
      uid: req.p.uid,
      zid: req.p.zid,
      referrer: req.p.referrer,
      parent_url: req.p.parent_url,
      xid: req.p.xid,
    });

    const response: any = {
      pid: result.pid,
      uid: result.uid,
    };

    // If anonymous user, issue Anonymous JWT
    if (!req.p.uid && result.uid) {
      const anonymousToken = issueAnonymousJWT(
        result.conversation_id || String(result.zid),
        result.uid,
        result.pid
      );
      response.token = anonymousToken;
      response.isAnonymous = true;
    }

    res.status(200).json(response);
  } catch (err: any) {
    if (err?.message?.match(/polis_err_need_full_user/)) {
      failJson(res, 403, err.message, err);
    } else if (err?.message?.match(/polis_err_xid_required/)) {
      failJson(res, 403, err.message, err);
    } else if (err?.message?.match(/polis_err_xid_not_allowed/)) {
      failJson(res, 403, err.message, err);
    } else if (
      isFncpProviderPolicyUnavailable(err) ||
      err?.message?.match(/polis_err_fncp_provider_gate_unavailable/)
    ) {
      failJson(res, 503, "polis_err_fncp_provider_policy_unavailable", err);
    } else if (err?.message) {
      failJson(res, 500, err.message, err);
    } else {
      failJson(res, 500, "polis_err_joinWithZidOrSuzinvite", err);
    }
  }
}

async function _joinWithZidOrSuzinvite(params: JoinParams): Promise<any> {
  let o = { ...params };

  // Get suzinvite info or use zid
  if (o.suzinvite) {
    const suzinviteInfo = await getSUZinviteInfo(o.suzinvite);
    o = Object.assign(o, suzinviteInfo);
  } else if (!o.zid) {
    throw new Error("polis_err_missing_invite");
  }

  // Get conversation info
  const conv = await getConversationInfo(o.zid);
  o.conv = conv;
  const providerPolicy = await resolveFncpManagedConversation(o.zid);
  if (providerPolicy.managed && !o.conv.use_xid_whitelist) {
    throw new Error("polis_err_fncp_provider_gate_unavailable");
  }

  // Validate the complete XID policy before creating a user, joining a
  // participant, answering metadata questions, or consuming an invitation.
  // For the provider-managed conversation the provider operation ledger is
  // authoritative; a legacy owner-scoped allowlist row is not sufficient.
  if (o.conv.use_xid_whitelist) {
    if (!o.xid) {
      throw new Error("polis_err_xid_required");
    }
    let isAllowed: boolean;
    if (providerPolicy.managed) {
      const providerDecision = await getFncpManagedXidDecision(o.zid, o.xid);
      if (providerDecision === undefined) {
        // Enforcement changed or the managed target became uncertain between
        // the policy and XID read. Never fall back to the legacy owner-scoped
        // allowlist after the first decision identified a managed target.
        throw new Error("polis_err_fncp_provider_gate_unavailable");
      }
      isAllowed = providerDecision;
    } else {
      isAllowed = await isXidAllowed(o.xid, o.zid, o.conv.owner);
    }
    if (!isAllowed) {
      throw new Error("polis_err_xid_not_allowed");
    }
  } else if (o.conv.xid_required && !o.xid) {
    throw new Error("polis_err_xid_required");
  }

  // Get user info if uid exists
  if (o.uid) {
    const user = await getUserInfoForUid2(o.uid);
    o.user = user;
  } else {
    // Create anonymous user
    const uid = await createAnonUser();
    o.uid = uid;
  }

  // Check if user has answered required questions
  await userHasAnsweredZeQuestions(o.zid, o.answers);

  // Join conversation
  const info: ParticipantInfo = {};
  if (o.referrer) {
    info.referrer = o.referrer;
  }
  if (o.parent_url) {
    info.parent_url = o.parent_url;
  }

  const ptpt = await joinConversation(o.zid, o.uid, info, o.answers);
  o = Object.assign(o, ptpt);

  // Handle XID if present
  if (o.xid) {
    const exists = await xidExists(o.xid, o.conv.org_id, o.uid);
    if (!exists) {
      await createXidRecord(o.xid, o.conv.owner, o.uid, o.zid);
    }
  }

  // Delete suzinvite if it was used
  if (o.suzinvite) {
    await deleteSuzinvite(o.suzinvite);
  }

  return o;
}

export { handle_POST_auth_deregister_jwt, handle_POST_joinWithInvite };
