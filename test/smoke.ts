import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { parseUsage } from "../src/usage";
import * as usageModule from "../src/usage";
import { isAuthProblem } from "../src/ui/accountsView";
import { CredentialsManager } from "../src/credentials";
import { requiresProfileReauthorization, TokenRefresher } from "../src/oauth";
import { AccountStore } from "../src/accountStore";
import { buildBrowserAuthorizationUrl, parseBrowserTokenResponse } from "../src/browserOAuth";
import { ProfileActivityRegistry } from "../src/profileActivity";
import { SwitchService } from "../src/switchService";

let failures = 0;
function check(name: string, cond: boolean): void {
  console.log((cond ? "  PASS" : "  FAIL") + " - " + name);
  if (!cond) failures++;
}

console.log("parseUsage:");
// Real captured /api/oauth/usage response shape
const real = {
  five_hour: { utilization: 12.0, resets_at: "2026-06-25T11:00:00+00:00" },
  seven_day: { utilization: 8.0, resets_at: "2026-06-29T12:00:00+00:00" },
  limits: [
    { kind: "session", group: "session", percent: 12, severity: "normal", resets_at: "2026-06-25T11:00:00+00:00", is_active: true },
    { kind: "weekly_all", group: "weekly", percent: 8, severity: "normal", resets_at: "2026-06-29T12:00:00+00:00", is_active: false },
  ],
};
const snap = parseUsage(real as never);
check("2 windows from limits[]", snap.windows.length === 2);
check("sessionPercent = 12", snap.sessionPercent === 12);
check("weeklyPercent = 8", snap.weeklyPercent === 8);
check("session label", snap.windows[0].label === "Session (5h)");

const fb = parseUsage({ five_hour: { utilization: 50, resets_at: null }, seven_day: { utilization: 90, resets_at: null } } as never);
check("fallback sessionPercent = 50", fb.sessionPercent === 50);
check("fallback weeklyPercent = 90", fb.weeklyPercent === 90);

const em = parseUsage({} as never);
check("empty -> 0 windows, null percents", em.windows.length === 0 && em.sessionPercent === null);

// A per-model cap arrives as kind "weekly_scoped" alongside the account-wide weekly total.
// Without the scope name both rows render as "Weekly" and look like duplicates.
const scoped = parseUsage({
  limits: [
    { kind: "session", group: "session", percent: 82, resets_at: null },
    { kind: "weekly_all", group: "weekly", percent: 48, resets_at: null },
    {
      kind: "weekly_scoped",
      group: "weekly",
      percent: 76,
      resets_at: null,
      scope: { model: { id: null, display_name: "Fable" }, surface: null },
    },
  ],
} as never);
check("scoped weekly limit is named after its model", scoped.windows[2].label === "Weekly (Fable)");
check("scoped weekly limit keeps its own percent", scoped.windows[2].percent === 76);
check("weeklyPercent still tracks the account-wide total", scoped.weeklyPercent === 48);

const unnamedScope = parseUsage({
  limits: [{ kind: "weekly_scoped", group: "weekly", percent: 5, resets_at: null, scope: null }],
} as never);
check("unnamed scope falls back to a distinct label", unnamedScope.windows[0].label === "Weekly (scoped)");

const futureKind = parseUsage({
  limits: [{ kind: "monthly_all", group: "monthly", percent: 7, resets_at: null }],
} as never);
check("unknown future kinds still render", futureKind.windows[0].label === "monthly_all");

console.log("Stale usage markers:");
// The panel replaces an error with "Needs reauthorization" (and hides the meters behind an
// Auth button) whenever isAuthProblem matches. A "usage is stale" note must never match.
const staleMessages = [
  usageModule.STALE_TOKEN_HELD_BY_CLAUDE,
  usageModule.STALE_ACTIVE_TOKEN_EXPIRED,
  usageModule.STALE_ACTIVE_TOKEN_REJECTED,
];
check(
  "stale markers do not read as broken profiles",
  staleMessages.every((m) => !isAuthProblem(m) && !requiresProfileReauthorization(m))
);
check(
  "genuine auth failures still read as broken profiles",
  isAuthProblem("Failed to refresh token: HTTP 400 invalid_grant") &&
    isAuthProblem("HTTP 401: unauthorized")
);

console.log("CredentialsManager (temp file):");
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cas-test-"));
const credPath = path.join(tmpDir, ".credentials.json");
process.env.TEST_CRED_PATH = credPath;
const mgr = new CredentialsManager();

const credsA = { accessToken: "AAA", refreshToken: "ra", expiresAt: 111, scopes: ["x"], subscriptionType: "pro" };
const credsB = { accessToken: "BBB", refreshToken: "rb", expiresAt: 222, scopes: ["y"], subscriptionType: "max" };

check("path resolves to override", mgr.getCredentialsPath() === credPath);
mgr.writeCreds(credsA as never);
check("write + read account A", mgr.readCurrent()?.accessToken === "AAA");

mgr.backupCurrent();
check("hasBackup after backup", mgr.hasBackup() === true);

mgr.writeCreds(credsB as never);
check("switch to account B", mgr.readCurrent()?.accessToken === "BBB");

mgr.restoreBackup();
check("undo restores account A", mgr.readCurrent()?.accessToken === "AAA");

fs.writeFileSync(credPath, JSON.stringify({ claudeAiOauth: credsA, otherField: 123 }));
mgr.writeCreds(credsB as never);
const rawAfter = JSON.parse(fs.readFileSync(credPath, "utf8"));
check("preserves extra fields on write", rawAfter.otherField === 123 && rawAfter.claudeAiOauth.accessToken === "BBB");

check(
  "does not overwrite a credential file that Claude already rotated",
  mgr.writeCredsIfCurrent(credsA as never, credsB as never) === false &&
    mgr.readCurrent()?.refreshToken === "rb"
);
check(
  "compare-and-swap persists a rotation from the current generation",
  mgr.writeCredsIfCurrent(credsB as never, credsA as never) === true &&
    mgr.readCurrent()?.refreshToken === "ra"
);

fs.writeFileSync(credPath, JSON.stringify({ claudeAiOauth: { accessToken: "", refreshToken: "", expiresAt: 0, scopes: [] } }));
check("empty tokens are not a current login", mgr.readCurrent() === null);

mgr.writeCreds(credsA as never);
let refusedIncompleteWrite = false;
try {
  mgr.writeCreds({ accessToken: "", refreshToken: "", expiresAt: 0, scopes: [] } as never);
} catch {
  refusedIncompleteWrite = true;
}
check("refuses to write incomplete credentials", refusedIncompleteWrite);
check("incomplete write does not overwrite existing credentials", mgr.readCurrent()?.accessToken === "AAA");

fs.rmSync(tmpDir, { recursive: true, force: true });

function createStore(): AccountStore {
  const globalState = new Map<string, unknown>();
  const workspaceState = new Map<string, unknown>();
  const secrets = new Map<string, string>();
  const memento = (values: Map<string, unknown>) => ({
    get: <T>(key: string, defaultValue?: T): T => (values.has(key) ? values.get(key) : defaultValue) as T,
    update: async (key: string, value: unknown) => {
      if (value === undefined) values.delete(key);
      else values.set(key, value);
    },
  });

  return new AccountStore({
    globalState: memento(globalState),
    workspaceState: memento(workspaceState),
    secrets: {
      get: async (key: string) => secrets.get(key),
      store: async (key: string, value: string) => {
        secrets.set(key, value);
      },
      delete: async (key: string) => {
        secrets.delete(key);
      },
    },
  } as never);
}

function runBrowserOAuthTests(): void {
  console.log("Browser OAuth:");
  const url = new URL(buildBrowserAuthorizationUrl(43123, "expected-state", "pkce-challenge"));
  check(
    "uses the Claude subscription authorization endpoint",
    url.origin === "https://claude.com" && url.pathname === "/cai/oauth/authorize"
  );
  check(
    "uses loopback callback and PKCE",
    url.searchParams.get("redirect_uri") === "http://127.0.0.1:43123/callback" &&
      url.searchParams.get("code_challenge") === "pkce-challenge" &&
      url.searchParams.get("code_challenge_method") === "S256"
  );
  check(
    "binds the authorization response to a random state",
    url.searchParams.get("state") === "expected-state"
  );

  const parsed = parseBrowserTokenResponse({
    access_token: "browser-access",
    refresh_token: "browser-refresh",
    expires_in: 3600,
    refresh_token_expires_in: 7200,
    scope: "user:profile user:inference",
    account: { email_address: "browser@example.com" },
    organization: { uuid: "org-browser", name: "Browser Org" },
  });
  check(
    "maps a browser token response to credentials",
    parsed.creds?.accessToken === "browser-access" &&
      parsed.creds.refreshToken === "browser-refresh" &&
      parsed.creds.scopes.join(" ") === "user:profile user:inference"
  );
  check(
    "maps account identity without the CLI",
    parsed.identity?.email === "browser@example.com" && parsed.identity.orgId === "org-browser"
  );
}

function runProfileActivityTests(): void {
  console.log("ProfileActivityRegistry:");
  const storageDir = fs.mkdtempSync(path.join(os.tmpdir(), "cas-activity-test-"));
  const context = { globalStorageUri: { fsPath: storageDir } } as never;
  const owner = new ProfileActivityRegistry(context);
  const observer = new ProfileActivityRegistry(context);
  owner.setActiveProfile("profile-a");
  check("shares active-profile ownership across extension hosts", observer.isActive("profile-a"));
  owner.dispose();
  check("removes the window lease on disposal", !observer.isActive("profile-a"));
  observer.dispose();
  fs.rmSync(storageDir, { recursive: true, force: true });
}

async function runAccountStoreTests(): Promise<void> {
  console.log("AccountStore:");

  const store = createStore();
  const profile = await store.addFromCreds("Broken", {
    accessToken: "stored-access",
    refreshToken: "",
    expiresAt: 111,
    scopes: [],
  });
  await store.syncActiveFromFile({
    accessToken: "fresh-access",
    refreshToken: "fresh-refresh",
    expiresAt: 222,
    scopes: ["user:profile"],
  });
  check(
    "does not repair incomplete profile from unmatched current file",
    (await store.getCreds(profile.id))?.refreshToken === ""
  );
  check("keeps remembered active marker when an unmatched file cannot be identified", store.getActiveId() === profile.id);

  await store.updateIdentity(profile.id, { email: "owner@example.com", orgId: "org-1" });
  await store.syncActiveFromFile(
    {
      accessToken: "rotated-access",
      refreshToken: "rotated-refresh",
      expiresAt: 333,
      scopes: ["user:profile"],
    },
    { email: "owner@example.com", orgId: "org-1" }
  );
  check(
    "imports a fully rotated active file by verified account identity",
    (await store.getCreds(profile.id))?.refreshToken === "rotated-refresh"
  );

  const noRefreshStore = createStore();
  await noRefreshStore.addFromCreds("A", {
    accessToken: "a",
    refreshToken: "",
    expiresAt: 111,
    scopes: [],
  });
  const matched = await noRefreshStore.findByTokens({
    accessToken: "b",
    refreshToken: "",
    expiresAt: 222,
    scopes: [],
  });
  check("does not match accounts by empty refresh token", matched === undefined);

  await store.updateUsage(profile.id, {
    fetchedAt: 333,
    windows: [],
    sessionPercent: null,
    weeklyPercent: null,
    error: "Failed to refresh token: HTTP 400 invalid_grant",
    retryAfter: 444,
  });
  await store.clearUsageError(profile.id);
  const clearedUsage = store.get(profile.id)?.lastUsage;
  check("clearUsageError removes auth error", clearedUsage?.error === undefined);
  check("clearUsageError removes retry backoff", clearedUsage?.retryAfter === undefined);
  check("clearUsageError preserves usage timestamp", clearedUsage?.fetchedAt === 333);

  await store.updateUsage(profile.id, {
    fetchedAt: 555,
    windows: [],
    sessionPercent: null,
    weeklyPercent: null,
    error: "Failed to refresh token: HTTP 400 invalid_grant",
    retryAfter: 666,
  });
  await store.updateCreds(profile.id, {
    accessToken: "reauth-access",
    refreshToken: "reauth-refresh",
    expiresAt: 777,
    scopes: ["user:profile"],
  });
  const reauthedUsage = store.get(profile.id)?.lastUsage;
  check("new credentials clear auth error", reauthedUsage?.error === undefined);
  check("new credentials clear retry backoff", reauthedUsage?.retryAfter === undefined);
}

async function runUsagePollerTests(): Promise<void> {
  console.log("UsagePoller:");
  const { UsagePoller, STALE_ACTIVE_TOKEN_EXPIRED } = await import("../src/usage");
  const store = createStore();
  const profile = await store.addFromCreds("Good", {
    accessToken: "stored-access",
    refreshToken: "stored-refresh",
    expiresAt: Date.now() + 3_600_000,
    scopes: ["user:profile"],
  });
  const poller = new UsagePoller(
    store,
    new TokenRefresher(),
    new CredentialsManager(),
    () => 240,
    () => undefined,
    {
      readProfileCreds: () => ({
        accessToken: "",
        refreshToken: "",
        expiresAt: 0,
        refreshTokenExpiresAt: Date.now() + 7_200_000,
        scopes: ["user:profile"],
      }),
    }
  );
  await (poller as never as { syncProfileConfigCreds(id: string, stored: unknown): Promise<unknown> })
    .syncProfileConfigCreds(profile.id, await store.getCreds(profile.id));
  check(
    "ignores incomplete isolated profile credentials",
    (await store.getCreds(profile.id))?.refreshToken === "stored-refresh"
  );

  const brokenStore = createStore();
  const brokenProfile = await brokenStore.addFromCreds("Broken", {
    accessToken: "stored-access",
    refreshToken: "",
    expiresAt: 0,
    scopes: [],
  });
  const brokenPoller = new UsagePoller(
    brokenStore,
    new TokenRefresher(),
    new CredentialsManager(),
    () => 240,
    () => undefined,
    {
      readProfileCreds: () => ({
        accessToken: "other-access",
        refreshToken: "other-refresh",
        expiresAt: Date.now() + 3_600_000,
        scopes: ["user:profile"],
      }),
    }
  );
  await (brokenPoller as never as { syncProfileConfigCreds(id: string, stored: unknown): Promise<unknown> })
    .syncProfileConfigCreds(brokenProfile.id, await brokenStore.getCreds(brokenProfile.id));
  check(
    "does not import isolated credentials over incomplete stored profile",
    (await brokenStore.getCreds(brokenProfile.id))?.refreshToken === ""
  );

  const restartStore = createStore();
  const refreshExpiry = Date.now() + 30 * 24 * 3_600_000;
  const restartProfile = await restartStore.addFromCreds("Restarted", {
    accessToken: "before-restart-access",
    refreshToken: "before-restart-refresh",
    expiresAt: Date.now() - 3_600_000,
    refreshTokenExpiresAt: refreshExpiry,
    scopes: ["user:profile"],
  });
  const afterRestart = {
    accessToken: "after-restart-access",
    refreshToken: "after-restart-refresh",
    expiresAt: Date.now() + 3_600_000,
    refreshTokenExpiresAt: refreshExpiry,
    scopes: ["user:profile"],
  };
  const restartPoller = new UsagePoller(
    restartStore,
    new TokenRefresher(),
    new CredentialsManager(),
    () => 240,
    () => undefined,
    { readProfileCreds: () => afterRestart }
  );
  await (restartPoller as never as { syncProfileConfigCreds(id: string, stored: unknown): Promise<unknown> })
    .syncProfileConfigCreds(restartProfile.id, await restartStore.getCreds(restartProfile.id));
  check(
    "restart imports Claude's rotated tokens when refresh-token expiry is unchanged",
    (await restartStore.getCreds(restartProfile.id))?.refreshToken === "after-restart-refresh"
  );

  const staleReplica = {
    ...afterRestart,
    refreshToken: "stale-refresh",
  };
  const stalePoller = new UsagePoller(
    restartStore,
    new TokenRefresher(),
    new CredentialsManager(),
    () => 240,
    () => undefined,
    { readProfileCreds: () => staleReplica }
  );
  await (stalePoller as never as { syncProfileConfigCreds(id: string, stored: unknown): Promise<unknown> })
    .syncProfileConfigCreds(restartProfile.id, await restartStore.getCreds(restartProfile.id));
  check(
    "equal-age replica cannot restore an already spent refresh token",
    (await restartStore.getCreds(restartProfile.id))?.refreshToken === "after-restart-refresh"
  );

  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = (async () => {
    fetchCalls++;
    return new Response("{}", { status: 500 });
  }) as typeof fetch;
  try {
    const recoveredStore = createStore();
    const recoveredProfile = await recoveredStore.addFromCreds("Recoverable", {
      accessToken: "spent-access",
      refreshToken: "spent-refresh",
      expiresAt: Date.now() - 3_600_000,
      refreshTokenExpiresAt: refreshExpiry,
      scopes: ["user:profile"],
    });
    await recoveredStore.updateUsage(recoveredProfile.id, {
      fetchedAt: Date.now(),
      windows: [],
      sessionPercent: null,
      weeklyPercent: null,
      error: "Failed to refresh token: HTTP 400 invalid_grant",
    });
    const recoveredPoller = new UsagePoller(
      recoveredStore,
      new TokenRefresher(),
      new CredentialsManager(),
      () => 240,
      () => undefined,
      { readProfileCreds: () => afterRestart }
    );
    await recoveredPoller.pollOne(recoveredProfile.id, false);
    check(
      "recovers a profile marked invalid when Claude persisted a newer generation",
      (await recoveredStore.getCreds(recoveredProfile.id))?.refreshToken ===
        "after-restart-refresh" && fetchCalls === 1
    );
    fetchCalls = 0;

    const skippedStore = createStore();
    const skippedProfile = await skippedStore.addFromCreds("Needs auth", {
      accessToken: "stored-access",
      refreshToken: "stored-refresh",
      expiresAt: 0,
      scopes: ["user:profile"],
    });
    await skippedStore.updateUsage(skippedProfile.id, {
      fetchedAt: Date.now(),
      windows: [],
      sessionPercent: null,
      weeklyPercent: null,
      error:
        "Failed to refresh token: HTTP 400 from token endpoint: {\"error\":\"invalid_grant\"}",
    });
    const skippedPoller = new UsagePoller(
      skippedStore,
      new TokenRefresher(),
      new CredentialsManager(),
      () => 240,
      () => undefined
    );
    await skippedPoller.pollOne(skippedProfile.id, false);
    check("skips automatic retry after invalid_grant", fetchCalls === 0);
    await skippedPoller.pollOne(skippedProfile.id, true);
    check("skips forced retry after invalid_grant", fetchCalls === 0);

    const activeStore = createStore();
    const activeProfile = await activeStore.addFromCreds("Active", {
      accessToken: "expired-access",
      refreshToken: "must-not-be-spent",
      expiresAt: Date.now() - 1,
      scopes: ["user:profile"],
    });
    const activePoller = new UsagePoller(
      activeStore,
      new TokenRefresher(),
      new CredentialsManager(),
      () => 240,
      () => undefined,
      { isProfileActive: () => true }
    );
    await activePoller.pollOne(activeProfile.id, true);
    check("never refreshes a token owned by an active Claude window", fetchCalls === 0);

    const staleSnapshot = activeStore.get(activeProfile.id)?.lastUsage;
    check(
      "an active profile it cannot poll reports staleness instead of freezing",
      staleSnapshot?.error === STALE_ACTIVE_TOKEN_EXPIRED
    );
  } finally {
    globalThis.fetch = originalFetch;
  }

  await runRotatedActiveTokenTests();
}

/**
 * Regression: Claude Code rotates the active account's tokens in place, so the profile's saved
 * copy goes stale and cannot be re-matched to the credentials file. The poller used to give up
 * silently, freezing the card on old percentages while the refresh button appeared to do nothing.
 */
async function runRotatedActiveTokenTests(): Promise<void> {
  const { UsagePoller, STALE_TOKEN_HELD_BY_CLAUDE } = await import("../src/usage");

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cas-rotated-test-"));
  const credPath = path.join(tmpDir, ".credentials.json");
  const previousCredPath = process.env.TEST_CRED_PATH;
  process.env.TEST_CRED_PATH = credPath;

  const originalFetch = globalThis.fetch;
  const bearers: string[] = [];
  globalThis.fetch = (async (_url: string, init?: RequestInit) => {
    const auth = (init?.headers as Record<string, string> | undefined)?.Authorization ?? "";
    bearers.push(auth.replace("Bearer ", ""));
    return new Response(
      JSON.stringify({
        limits: [
          { kind: "session", group: "session", percent: 82, resets_at: null },
          { kind: "weekly_all", group: "weekly", percent: 48, resets_at: null },
        ],
      }),
      { status: 200 }
    );
  }) as unknown as typeof fetch;

  try {
    const store = createStore();
    // What the extension saved before Claude Code rotated the tokens underneath it.
    const profile = await store.addFromCreds("Rotated", {
      accessToken: "spent-access",
      refreshToken: "must-not-be-spent",
      expiresAt: Date.now() - 3_600_000,
      scopes: ["user:profile"],
    });
    await store.updateUsage(profile.id, {
      fetchedAt: Date.now() - 107 * 60_000,
      windows: [],
      sessionPercent: 53,
      weeklyPercent: 30,
    });
    // What Claude Code actually wrote to ~/.claude/.credentials.json.
    new CredentialsManager().writeCreds({
      accessToken: "rotated-access",
      refreshToken: "rotated-refresh",
      expiresAt: Date.now() + 3_600_000,
      scopes: ["user:profile"],
    } as never);

    const poller = new UsagePoller(
      store,
      new TokenRefresher(),
      new CredentialsManager(),
      () => 240,
      () => undefined,
      { isProfileActive: () => true }
    );
    await poller.pollOne(profile.id, true);

    const usage = store.get(profile.id)?.lastUsage;
    check("rotated active account is polled with the live token", bearers[0] === "rotated-access");
    check("rotated active account reports fresh usage", usage?.sessionPercent === 82);
    check("successful poll clears the stale marker", usage?.error === undefined);
    check(
      "reading the live file never overwrites the profile's saved secrets",
      (await store.getCreds(profile.id))?.refreshToken === "must-not-be-spent"
    );

    // A deferred refresh (Claude Code owns the rotating token) must say so, and must not
    // pretend the numbers on screen were just re-fetched.
    const deferredStore = createStore();
    const deferredProfile = await deferredStore.addFromCreds("Deferred", {
      accessToken: "spent-access",
      refreshToken: "must-not-be-spent",
      expiresAt: Date.now() - 3_600_000,
      scopes: ["user:profile"],
    });
    const originalFetchedAt = Date.now() - 42 * 60_000;
    await deferredStore.updateUsage(deferredProfile.id, {
      fetchedAt: originalFetchedAt,
      windows: [],
      sessionPercent: 53,
      weeklyPercent: 30,
    });
    const deferredPoller = new UsagePoller(
      deferredStore,
      new TokenRefresher(),
      new CredentialsManager(),
      () => 240,
      () => undefined,
      { isProfileActive: () => true }
    );
    const refreshed = await (
      deferredPoller as never as {
        refreshCreds(
          id: string,
          creds: unknown,
          force: boolean,
          prev: unknown
        ): Promise<unknown>;
      }
    ).refreshCreds(
      deferredProfile.id,
      await deferredStore.getCreds(deferredProfile.id),
      false,
      deferredStore.get(deferredProfile.id)?.lastUsage
    );
    const deferredUsage = deferredStore.get(deferredProfile.id)?.lastUsage;
    check("deferred refresh still refuses to spend the token", refreshed === null);
    check("deferred refresh is reported", deferredUsage?.error === STALE_TOKEN_HELD_BY_CLAUDE);
    check(
      "a stale marker keeps the original fetch time",
      deferredUsage?.fetchedAt === originalFetchedAt
    );
  } finally {
    globalThis.fetch = originalFetch;
    if (previousCredPath === undefined) delete process.env.TEST_CRED_PATH;
    else process.env.TEST_CRED_PATH = previousCredPath;
  }
}

async function runSwitchServiceTests(): Promise<void> {
  console.log("SwitchService:");

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cas-switch-test-"));
  const credPath = path.join(tmpDir, ".credentials.json");
  process.env.TEST_CRED_PATH = credPath;

  const store = createStore();
  const manager = new CredentialsManager();
  const profile = await store.addFromCreds("Newater2", {
    accessToken: "stored-access",
    refreshToken: "",
    expiresAt: 111,
    scopes: [],
  });
  manager.writeCreds({
    accessToken: "current-access",
    refreshToken: "current-refresh",
    expiresAt: 222,
    scopes: ["user:profile"],
  });

  const service = new SwitchService(store, manager);
  const switchResult = await service.switchTo(profile.id);
  check(
    "incomplete profile switch requests reauthorization",
    !switchResult.ok && switchResult.reauthProfileId === profile.id
  );
  check(
    "switch does not store current login into incomplete profile",
    (await store.getCreds(profile.id))?.refreshToken === ""
  );

  fs.rmSync(tmpDir, { recursive: true, force: true });
}

async function runTokenRefresherTests(): Promise<void> {
  console.log("TokenRefresher:");
  const originalFetch = globalThis.fetch;
  let capturedUrl = "";
  let capturedInit: RequestInit | undefined;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    capturedUrl = String(input);
    capturedInit = init;
    return new Response(
      JSON.stringify({
        access_token: "next-access",
        refresh_token: "next-refresh",
        expires_in: 3600,
        refresh_token_expires_in: 7200,
        scope: "user:profile user:inference",
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }) as typeof fetch;

  try {
    const before = Date.now();
    const refreshed = await new TokenRefresher().refresh({
      accessToken: "old-access",
      refreshToken: "old-refresh",
      expiresAt: 111,
      refreshTokenExpiresAt: 222,
      scopes: ["user:profile", "user:inference"],
      clientId: "custom-client",
    });
    const body = JSON.parse(String(capturedInit?.body));
    const headers = capturedInit?.headers as Record<string, string>;

    check("uses current Claude Code token endpoint", capturedUrl === "https://platform.claude.com/v1/oauth/token");
    check("sends JSON token refresh body", headers["Content-Type"] === "application/json");
    check("sends oauth beta header", headers["anthropic-beta"] === "oauth-2025-04-20");
    check("sends user agent", headers["User-Agent"] === "claude-code-account-switcher");
    check("includes grant type", body.grant_type === "refresh_token");
    check("includes refresh token", body.refresh_token === "old-refresh");
    check("uses credential clientId when present", body.client_id === "custom-client");
    check("includes credential scopes", body.scope === "user:profile user:inference");
    check("stores rotated access token", refreshed.creds?.accessToken === "next-access");
    check("stores rotated refresh token", refreshed.creds?.refreshToken === "next-refresh");
    check("stores refresh token expiry", (refreshed.creds?.refreshTokenExpiresAt ?? 0) >= before + 7_199_000);
    check("updates response scopes", refreshed.creds?.scopes.join(" ") === "user:profile user:inference");

    capturedInit = undefined;
    await new TokenRefresher().refresh({
      accessToken: "old-access",
      refreshToken: "old-refresh",
      expiresAt: 111,
      scopes: [],
    });
    const defaultScopeBody = JSON.parse(String(capturedInit?.body));
    check(
      "uses default Claude Code scopes when missing",
      defaultScopeBody.scope === "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
    );

    let fetchCalls = 0;
    globalThis.fetch = (async () => {
      fetchCalls++;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    const missingRefresh = await new TokenRefresher().refresh({
      accessToken: "old-access",
      refreshToken: "",
      expiresAt: 111,
      scopes: [],
    });
    check("does not request without refresh token", !missingRefresh.ok && fetchCalls === 0);
    check("missing refresh token requires reauthorization", missingRefresh.requiresReauthorization === true);

    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "Refresh token not found or invalid",
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      )) as typeof fetch;
    const invalidGrant = await new TokenRefresher().refresh({
      accessToken: "old-access",
      refreshToken: "dead-refresh",
      expiresAt: 111,
      scopes: ["user:profile"],
    });
    check("invalid_grant requires reauthorization", invalidGrant.requiresReauthorization === true);
    check("invalid_grant error stays recognizable", requiresProfileReauthorization(invalidGrant.error));
  } finally {
    globalThis.fetch = originalFetch;
  }
}

runProfileActivityTests();
runBrowserOAuthTests();
runAccountStoreTests()
  .then(runUsagePollerTests)
  .then(runSwitchServiceTests)
  .then(runTokenRefresherTests)
  .then(() => {
    console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
    process.exit(failures === 0 ? 0 : 1);
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
