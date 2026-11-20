# ThingsBoard AuthZ Security Review

Focus: Authentication, Authorization, IDOR, privilege escalation, broken access control.

## Auth model (brief)

- `ThingsboardSecurityConfiguration`: JWT via `X-Authorization`/`Authorization`; `/api/**` authenticated except `permitAll` paths (`/api/noauth/**`, `/api/images/public/**`, login/refresh, mail OAuth callback, device CA download, WS).
- Method security: `@PreAuthorize` + `DefaultAccessControlService` keyed by `Authority` → `SysAdminPermissions` / `TenantAdminPermissions` / `CustomerUserPermissions`.
- Entity checks: `BaseController.checkEntity*` → `accessControlService.checkPermission` with tenant/customer ownership.

---

## Validated findings

### 1. HIGH — Customer user can change device credentials via `/api/device-with-credentials`

**Primary file:** `application/src/main/java/org/thingsboard/server/controller/DeviceController.java`

**Title:** Broken access control: customer users update device credentials through saveDeviceWithCredentials

**Description:**  
`POST /api/device/credentials` correctly requires `TENANT_ADMIN` and `Operation.WRITE_CREDENTIALS`. Customer users intentionally lack `WRITE_CREDENTIALS` in `CustomerUserPermissions`.  
However, `POST /api/device-with-credentials` is allowed for `CUSTOMER_USER` and only checks `Operation.WRITE` (via `checkEntity`). On update of an existing device, `DeviceServiceImpl.saveDeviceWithCredentials` calls `updateDeviceCredentials`, so a customer can rotate access tokens / MQTT / X.509 / LwM2M credentials for any device assigned to them.

**Impact:** Customer user takes full control of device authentication: impersonate the device on transport APIs, inject/suppress telemetry, disrupt device connectivity by rotating credentials.

**Attack path:**
1. Authenticate as `CUSTOMER_USER` with at least one assigned device.
2. `GET /api/device/{deviceId}/credentials` (allowed: `READ_CREDENTIALS`) to obtain current credential object / device id.
3. `POST /api/device-with-credentials` with body `{ "device": { existing device JSON }, "credentials": { new ACCESS_TOKEN / MQTT_BASIC / … } }`.
4. Permission check uses `Operation.WRITE` only → succeeds.
5. Server updates credentials in DB; attacker uses new credentials against `/api/v1/**` or MQTT/CoAP.

**Evidence:**
- `DeviceController.java:221-236` — `@PreAuthorize` includes `CUSTOMER_USER`; `checkEntity(..., Resource.DEVICE)` → WRITE for updates
- `DeviceController.java:338-346` — dedicated credentials update is `TENANT_ADMIN` + `WRITE_CREDENTIALS`
- `CustomerUserPermissions.java:66-69` — allowed ops include `WRITE` and `READ_CREDENTIALS`, not `WRITE_CREDENTIALS`
- `DeviceServiceImpl.java:197-209` — existing device path updates credentials

**Remediation:**  
For updates through `saveDeviceWithCredentials`, require `Operation.WRITE_CREDENTIALS` (and/or `TENANT_ADMIN` only). Alternatively reject credential changes unless caller has `WRITE_CREDENTIALS`. Keep create-with-credentials tenant-admin-only if customers must not mint credentials.

**Why existing controls do not block:**  
`@PreAuthorize` allows customer users onto the endpoint; ACL only enforces `WRITE` on the device entity, not `WRITE_CREDENTIALS`. The stricter credentials endpoint is a separate code path and is never invoked.

---

### 2. HIGH — Customer user can reassign device/asset/entity-view `customerId` via save APIs (mass assignment)

**Primary file:** `application/src/main/java/org/thingsboard/server/controller/DeviceController.java`

**Title:** IDOR / privilege escalation: customerId mass assignment on entity save bypasses assign/unassign APIs

**Description:**  
Assign/unassign to customer and “make public” are `TENANT_ADMIN`-only and use `Operation.ASSIGN_TO_CUSTOMER`. Customer users may `WRITE` devices/assets/entity views assigned to them. Update flows authorize against the **existing** entity, then persist the request body including attacker-controlled `customerId`.  
Validators only ensure the target customer exists in the same tenant (or treat null as `NULL_UUID`); they do not enforce that the caller may change assignment.

Same pattern on:
- `POST /api/device` (`DeviceController.saveDevice`)
- `POST /api/device-with-credentials`
- `POST /api/asset` (`AssetController.saveAsset`)
- `POST /api/entityView` (`EntityViewController.saveEntityView`)

**Impact:**
- Reassign assigned entities to another customer in the tenant (unauthorized sharing / lateral movement).
- Set `customerId` to the tenant public customer → entity becomes reachable via public login without using `assignDeviceToPublicCustomer`.
- Unassign (`NULL_UUID`) without tenant-admin unassign API.

**Attack path:**
1. Authenticate as `CUSTOMER_USER`; obtain an assigned device via `GET /api/device/{id}`.
2. Obtain target `customerId` (e.g. public customer UUID from a public dashboard URL `publicId`, or another known customer UUID).
3. `POST /api/device` with same device `id`, modified `customerId`.
4. `checkDeviceId(..., WRITE)` passes on the old ownership; `DeviceDataValidator` accepts same-tenant customer; entity is reassigned.
5. Repeat for assets / entity views as needed.

**Evidence:**
- `DeviceController.java:181-200` — customer allowed; update only `checkDeviceId(..., WRITE)`; body `customerId` not forced
- `DeviceController.java:252-301` — assign/unassign/public require `TENANT_ADMIN` + `ASSIGN_TO_CUSTOMER`
- `DeviceDataValidator.java:71-80` — validates customer exists/same tenant only
- `CustomerUserPermissions.java:66-85` — `WRITE` yes; no `ASSIGN_TO_CUSTOMER`
- `AssetController.java:143-155`, `AssetDataValidator.java:71-80` — same pattern
- `EntityViewController.java:132-152`, `EntityViewDataValidator.java` — same pattern

**Remediation:**  
On update for customer users (and preferably for all non-admin callers), force `customerId` from the existing entity (ignore body). Or require `ASSIGN_TO_CUSTOMER` when `customerId` changes. Mirror for asset and entity view.

**Why existing controls do not block:**  
Ownership checks use the stored entity before save; assignment is not re-validated against the new `customerId`. Dedicated assign endpoints are simply not used by this path.

---

### 3. MEDIUM — Refresh token issues full JWTs without 2FA after MFA is enabled

**Primary file:** `application/src/main/java/org/thingsboard/server/service/security/auth/jwt/RefreshTokenAuthenticationProvider.java`

**Title:** MFA bypass via long-lived refresh tokens

**Description:**  
Password login with 2FA enabled returns only a `PRE_VERIFICATION_TOKEN` and sets `refreshToken` to null (`RestAwareAuthenticationSuccessHandler`).  
`RefreshTokenAuthenticationProvider` never calls `TwoFactorAuthService.isTwoFaEnabled`. Enabling/saving 2FA account config does not publish `UserCredentialsInvalidationEvent` / session invalidation.  
Any refresh token issued before 2FA was enabled (or while MFA was off) can call `POST /api/auth/token` and receive a full access+refresh pair, skipping 2FA.

**Impact:** Bypass of second factor for accounts that enable or are forced into 2FA while prior refresh tokens remain valid (often long-lived). Session theft of a pre-MFA refresh token remains useful after MFA enrollment.

**Attack path:**
1. Victim (or attacker with password) logs in before 2FA is configured → stores refresh token.
2. Victim enables 2FA (`POST /api/2fa/account/config`) or admin enforces platform 2FA; existing sessions/tokens are not invalidated.
3. Attacker `POST /api/auth/token` with the old refresh token.
4. Provider rebuilds `SecurityUser` without MFA check; success handler returns full `JwtPair`.
5. Attacker uses access token as a fully authenticated user.

**Evidence:**
- `RestAwareAuthenticationSuccessHandler.java:53-62` — MFA login nulls refresh; otherwise full pair
- `RefreshTokenAuthenticationProvider.java:57-98` — no 2FA check
- `TwoFactorAuthConfigController.java:141-157` — save 2FA config without credential/session invalidation
- Contrast: `AuthController.changePassword` publishes `UserCredentialsInvalidationEvent`

**Remediation:**  
On refresh, if `isTwoFaEnabled`, refuse or return only `PRE_VERIFICATION_TOKEN`. Invalidate refresh/access sessions when 2FA is enabled or made mandatory.

**Why existing controls do not block:**  
MFA is enforced only on the password-login success path. Refresh is a separate provider that trusts an unexpired refresh JWT and does not consult 2FA state; enabling 2FA does not outdate tokens.

---

## Candidates (need more verification)

1. **Alarm update mass assignment** — `AlarmController.saveAlarm` authorizes existing alarm then may persist body fields (`originator`, `customerId`, assignee). Need runtime confirmation that service uses request body unchecked.
2. **Default-public images** — `ImageController.uploadImage` sets `public=true`; unauthenticated `/api/images/public/{key}` (32-char key). Likely intentional for dashboards; confirm whether keys leak via exported dashboards to unintended audiences.
3. **`downloadGatewayDockerCompose` missing `@PreAuthorize`** — still requires authenticated JWT + `checkDeviceId(..., READ_CREDENTIALS)`. Defense-in-depth gap; PRE_VERIFICATION/other authorities fail ACL. Not validated as exploitable alone.
4. **Public dashboard + entity alias IDOR** — public customer tokens + widget aliases might reach non-public entities if alias resolution skips customer checks; needs WS/telemetry subscription tracing beyond this pass.

## Out of scope / not reported

- CSRF on cookie-less JWT
- Missing rate limits (except where they enable auth bypass — not confirmed)
- XSS
- Intentional public dashboard / public device features when using dedicated assign APIs
