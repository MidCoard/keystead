# Zero-Knowledge Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover a Keystead server account and its available vault keys through either a one-time offline recovery kit or a signature from an existing verified device, without giving the server decryption capability.

**Architecture:** Core defines canonical recovery encodings and all secret-side cryptography. Server persists hashes, public keys, opaque envelopes/packages, challenges, approvals, and restricted-session state through JPA/Flyway. Client performs enrollment, local package opening, verified-device approval, replacement-device creation, and password reset; server completion atomically consumes authority and revokes old sessions.

**Tech Stack:** Java 21, JSpecify 1.0, Tink 1.22, JCA HKDF/HMAC/AES-GCM, Spring Boot 3.5/JPA/Flyway, Kotlin/JVM client, JUnit/Kotlin test.

## Global Constraints

- Server-account and vault-key recovery are distinct outcomes and must be reported separately.
- The server never stores a recovery secret, plaintext recovery private key, device private key, unwrapped vault key, plaintext new password, or local passphrase.
- Offline-kit and verified-device paths converge on one short-lived restricted recovery session.
- Failed local decryption does not consume a kit; successful completion consumes the authority exactly once and revokes all prior refresh/access-token generations.
- If no kit and no verified device remains, vault recovery is impossible; no administrator bypass is added.
- Every new public Java type and type use carries explicit JSpecify annotations.
- Server persistence uses JPA repositories/entities and Flyway only; no JDBC templates, native SQL application queries, or filesystem persistence.
- Preserve existing unrelated core/server edits and untracked local design notes.

---

### Task 1: Define canonical recovery-kit and envelope models in core

**Files:**
- Create: `keystead-core/src/main/java/top/focess/keystead/recovery/RecoveryKit.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/recovery/RecoveryKitCodec.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/recovery/RecoveryEnrollmentMaterial.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/recovery/RecoveryPublicKey.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/recovery/RecoveryVaultKeyPackage.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/recovery/RecoveryKitCodecTest.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/recovery/RecoveryModelTest.java`

**Interfaces:**
- Produces: version-1 recovery models with defensive byte-array copies, redacted `toString()`, and `AutoCloseable` secret owners.

- [ ] **Step 1: Write failing canonicalization, malformed-input, and destruction tests**

```java
@Test
void kitRoundTripsCanonicallyAndWipesOnClose() {
    byte[] secret = new byte[32];
    Arrays.fill(secret, (byte) 7);
    RecoveryKit kit = new RecoveryKit(1, "enrollment-1", 3L, secret);
    String encoded = RecoveryKitCodec.encode(kit);
    try (RecoveryKit decoded = RecoveryKitCodec.decode(encoded)) {
        assertEquals(encoded, RecoveryKitCodec.encode(decoded));
        assertFalse(decoded.toString().contains(Base64.getUrlEncoder().encodeToString(secret)));
    }
}
```

Add rejection cases for wrong prefix/version, blank/oversized enrollment id, non-positive generation, non-base64 secret, secret not exactly 32 bytes, checksum mismatch, extra fields, and non-canonical base64url.

- [ ] **Step 2: Run focused tests and confirm missing-package failure**

Run: `.\gradlew.bat :keystead-core:test --tests 'top.focess.keystead.recovery.*' --console=plain`

Expected: compilation fails because `top.focess.keystead.recovery` types do not exist.

- [ ] **Step 3: Implement exact models and printable format**

```java
public final class RecoveryKit implements AutoCloseable {
    public RecoveryKit(int formatVersion, @NonNull String enrollmentId, long generation,
            byte @NonNull [] recoverySecret);
    public int formatVersion();
    public @NonNull String enrollmentId();
    public long generation();
    public byte @NonNull [] recoverySecret();
    public boolean isClosed();
    @Override public void close();
}

public final class RecoveryKitCodec {
    public static @NonNull String encode(@NonNull RecoveryKit kit);
    public static @NonNull RecoveryKit decode(@NonNull String encoded);
}
```

Use `KEYSTEAD-RECOVERY-1.<base64url enrollment UTF-8>.<decimal generation>.<base64url 32-byte secret>.<base64url first 8 SHA-256 bytes of the preceding canonical UTF-8 text>`. Limit the full encoded kit to 512 characters. `RecoveryEnrollmentMaterial` owns kit, account credential, recovery public key, and encrypted private-key envelope and wipes all secret-bearing arrays on close.

- [ ] **Step 4: Run and format core tests**

Run: `.\gradlew.bat :keystead-core:spotlessApply :keystead-core:test --tests 'top.focess.keystead.recovery.*' --console=plain`

Expected: all recovery model/codec tests pass.

- [ ] **Step 5: Commit only core recovery models**

```powershell
git add -- keystead-core/src/main/java/top/focess/keystead/recovery keystead-core/src/test/java/top/focess/keystead/recovery
git commit -m "Add canonical recovery kit models"
```

### Task 2: Implement domain-separated recovery cryptography and approvals

**Files:**
- Create: `keystead-core/src/main/java/top/focess/keystead/recovery/RecoveryCryptoService.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/recovery/DefaultRecoveryCryptoService.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/recovery/RecoveryDeviceRequest.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/recovery/RecoveryDeviceRequestCodec.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/recovery/RecoveryCryptoServiceTest.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/recovery/RecoveryDeviceRequestCodecTest.java`

**Interfaces:**
- Consumes: `DefaultCryptoService`, `DeviceKeyPair`, `VaultHandle`, and Task 1 models.
- Produces: enrollment, envelope opening, recovery package wrapping/opening, account credential derivation, request canonicalization, and fingerprinting.

- [ ] **Step 1: Write failing domain separation and package-binding tests**

```java
@Test
void enrollmentOpensPrivateEnvelopeAndVaultPackageOnlyForBoundContext() {
    try (RecoveryEnrollmentMaterial material = recovery.enroll("enrollment-1", 1L);
            VaultHandle vault = createVault()) {
        RecoveryVaultKeyPackage pkg = recovery.wrapVaultKey(
                vault, material.publicKey(), "user-1", "vault-1");
        try (VaultHandle opened = recovery.openVault(
                vaultId, pkg, material.kit(), material.encryptedPrivateKey())) {
            assertEquals(vault.vaultKeyId(), opened.vaultKeyId());
        }
        assertThrows(CryptoException.class, () ->
                recovery.openVault(otherVaultId, pkg, material.kit(), material.encryptedPrivateKey()));
    }
}
```

Test deterministic credential derivation, credential/envelope key inequality, wrong kit, tampered envelope, wrong enrollment/generation/user/vault/key id, wrong algorithm, canonical request order, unknown fields, fingerprint stability, and secret-free `toString()`.

- [ ] **Step 2: Run focused tests and confirm missing service**

Run: `.\gradlew.bat :keystead-core:test --tests 'top.focess.keystead.recovery.RecoveryCryptoServiceTest' --tests 'top.focess.keystead.recovery.RecoveryDeviceRequestCodecTest' --console=plain`

Expected: compilation fails because the service and request codec do not exist.

- [ ] **Step 3: Implement exact crypto API**

```java
public interface RecoveryCryptoService {
    @NonNull RecoveryEnrollmentMaterial enroll(@NonNull String enrollmentId, long generation);
    @NonNull String accountCredential(@NonNull RecoveryKit kit);
    @NonNull RecoveryVaultKeyPackage wrapVaultKey(@NonNull VaultHandle vault,
            @NonNull RecoveryPublicKey recoveryKey, @NonNull String username,
            @NonNull String vaultId);
    @NonNull VaultHandle openVault(@NonNull DefaultVaultService vaultService,
            @NonNull VaultId vaultId, @NonNull RecoveryVaultKeyPackage keyPackage,
            @NonNull RecoveryKit kit, byte @NonNull [] encryptedPrivateKey);
    byte @NonNull [] requestFingerprint(@NonNull RecoveryDeviceRequest request);
}
```

Implement RFC 5869 HKDF-HMAC-SHA256 locally with extract salt `SHA-256("keystead-recovery-v1|<enrollment>|<generation>")` and distinct expand info values `account-credential` and `private-envelope-key`. Encrypt the Tink recovery private key with AES-256-GCM, random 12-byte nonce, and canonical enrollment AAD. Reuse the existing Tink device hybrid primitive for vault packages with context `keystead-recovery-vault-package-v1|user:<u>|vault:<v>|enrollment:<e>|generation:<g>|key:<k>`.

`RecoveryDeviceRequestCodec.encode` uses length-prefixed UTF-8/binary fields in this fixed order: version, request id, username, nonce, expires-at epoch seconds, device id, proof algorithm/key, wrapping algorithm/key. Fingerprint is the first 10 bytes of SHA-256 encoded as grouped uppercase hex.

- [ ] **Step 4: Run recovery tests and nullness semantics**

Run: `.\gradlew.bat :keystead-core:spotlessApply :keystead-core:test --tests 'top.focess.keystead.recovery.*' --tests top.focess.keystead.NullnessSemanticsTest --console=plain`

Expected: all selected tests pass.

- [ ] **Step 5: Commit the core recovery crypto boundary**

```powershell
git add -- keystead-core/src/main/java/top/focess/keystead/recovery keystead-core/src/test/java/top/focess/keystead/recovery
git commit -m "Add zero-knowledge recovery cryptography"
```

### Task 3: Persist recovery state with Flyway and JPA

**Files:**
- Create: `src/main/resources/db/migration/V20__zero_knowledge_recovery.sql`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryEnrollmentEntity.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryEnrollmentId.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryEnrollmentRepository.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryVaultPackageEntity.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryVaultPackageId.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryVaultPackageRepository.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryChallengeEntity.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryChallengeRepository.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryRequestEntity.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryRequestRepository.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoverySessionEntity.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoverySessionRepository.java`
- Create: `src/test/java/top/focess/keystead/server/recovery/RecoveryPersistenceTest.java`
- Create: `src/test/java/top/focess/keystead/server/recovery/RecoveryMigrationMappingTest.java`

**Interfaces:**
- Produces: JPA repositories for enrollment generations, opaque vault packages, challenges, device requests/approvals, and hashed recovery sessions.

- [ ] **Step 1: Write failing mapping and database-constraint tests**

Test round trips plus unique active generation, positive generation, one request approval, one session consumption, package uniqueness, bounded columns, nonnegative attempts, expiry ordering, and no plaintext-secret/private-key/password column names.

- [ ] **Step 2: Run focused server tests and confirm missing migration/entities**

Run: `.\gradlew.bat test --tests 'top.focess.keystead.server.recovery.*PersistenceTest' --tests 'top.focess.keystead.server.recovery.*MigrationMappingTest' --console=plain`

Expected: tests fail because V20 and entities do not exist.

- [ ] **Step 3: Create the exact schema**

```sql
create table recovery_enrollments (
    username varchar(255) not null,
    enrollment_id varchar(128) not null,
    generation bigint not null,
    credential_hash varchar(255) not null,
    wrapping_algorithm varchar(64) not null,
    wrapping_public_key text not null,
    encrypted_private_key text not null,
    state varchar(32) not null,
    created_at timestamp not null,
    committed_at timestamp,
    consumed_at timestamp,
    primary key (username, enrollment_id, generation),
    constraint ck_recovery_generation check (generation > 0)
);
```

Add `recovery_vault_packages`, `recovery_challenges`, `recovery_device_requests`, and `recovery_sessions` with the keys and lifecycle columns described in the file list. Use ciphertext/text length validation in request/entity constructors and DB checks for state values, attempts `0..5`, and expiry after creation. Repositories extend `JpaRepository`; compare-and-set operations use JPQL `@Modifying` queries only.

- [ ] **Step 4: Run persistence tests**

Run: `.\gradlew.bat spotlessApply test --tests 'top.focess.keystead.server.recovery.*PersistenceTest' --tests 'top.focess.keystead.server.recovery.*MigrationMappingTest' --console=plain`

Expected: all pass against H2; Flyway applies V1 through V20.

- [ ] **Step 5: Commit server recovery persistence**

```powershell
git add -- src/main/resources/db/migration/V20__zero_knowledge_recovery.sql src/main/java/top/focess/keystead/server/recovery src/test/java/top/focess/keystead/server/recovery
git commit -m "Persist zero-knowledge recovery state"
```

### Task 4: Add authenticated enrollment and opaque vault-package APIs

**Files:**
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryEnrollmentRequest.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryEnrollmentResponse.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryVaultPackageRequest.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryVaultPackageResponse.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryEnrollmentService.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryEnrollmentController.java`
- Modify: `src/main/java/top/focess/keystead/server/audit/AuditEventType.java`
- Modify: `src/main/java/top/focess/keystead/server/audit/AuditService.java`
- Create: `src/test/java/top/focess/keystead/server/recovery/RecoveryEnrollmentApiTest.java`

**Interfaces:**
- Produces: authenticated create/replace/status endpoints under `/api/v1/recovery/enrollments` and per-vault package PUT/GET endpoints.

- [ ] **Step 1: Write failing API tests**

Test enrollment creation, pending replacement, old-generation validity until commit, validation, authenticated ownership, manager-authorized package creation, stale vault key id, ciphertext opacity, redacted audit details, and atomic replacement commit.

- [ ] **Step 2: Run API test and confirm 404/missing beans**

Run: `.\gradlew.bat test --tests '*RecoveryEnrollmentApiTest' --console=plain`

Expected: endpoint assertions fail because controllers do not exist.

- [ ] **Step 3: Implement DTOs and service transitions**

```java
public record RecoveryEnrollmentRequest(long generation, @NonNull String accountCredential,
        @NonNull String wrappingAlgorithm, @NonNull String wrappingPublicKey,
        @NonNull String encryptedPrivateKey) {}

@PostMapping
@NonNull ResponseEntity<RecoveryEnrollmentResponse> create(
        @NonNull Principal principal, @Valid @RequestBody @NonNull RecoveryEnrollmentRequest request)
```

Hash `accountCredential` with the configured `PasswordEncoder` before persistence. Never return it. Package requests carry enrollment id/generation, vault key id, algorithm, and base64 ciphertext. Resolve vault owner through `VaultAccessGuard`, require active recipient membership, and validate current key id through the rotation service.

- [ ] **Step 4: Run API and audit tests**

Run: `.\gradlew.bat spotlessApply test --tests '*RecoveryEnrollmentApiTest' --tests '*Audit*Test' --console=plain`

Expected: all selected tests pass.

- [ ] **Step 5: Commit enrollment APIs**

```powershell
git add -- src/main/java/top/focess/keystead/server/recovery src/main/java/top/focess/keystead/server/audit src/test/java/top/focess/keystead/server/recovery
git commit -m "Add recovery enrollment APIs"
```

### Task 5: Implement offline-kit challenge and restricted sessions

**Files:**
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryChallengeRequest.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryChallengeResponse.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryCredentialRequest.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoverySessionResponse.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoverySessionService.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryAuthController.java`
- Modify: `src/main/java/top/focess/keystead/server/security/SecurityConfig.java`
- Create: `src/test/java/top/focess/keystead/server/recovery/OfflineRecoveryApiTest.java`

**Interfaces:**
- Produces: public challenge/credential endpoints and opaque `Recovery <token>` authorization for restricted package reads/completion.

- [ ] **Step 1: Write failing enumeration, expiry, attempts, and single-use tests**

Assert identical challenge status/shape for known and unknown users, generic 401 on wrong/unknown credential, five-attempt limit, 5-minute challenge expiry, 10-minute session expiry, SHA-256-only stored session token, package access scoped to the recovered user, and concurrent credential verification creating at most one active session.

- [ ] **Step 2: Run focused API tests and confirm endpoints are unauthorized/missing**

Run: `.\gradlew.bat test --tests '*OfflineRecoveryApiTest' --console=plain`

Expected: endpoint assertions fail before implementation.

- [ ] **Step 3: Implement generic challenges and restricted session validation**

```java
private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
private static final Duration SESSION_TTL = Duration.ofMinutes(10);
private static final int MAX_ATTEMPTS = 5;

@PostMapping("/challenges")
@NonNull RecoveryChallengeResponse challenge(@Valid @RequestBody @NonNull RecoveryChallengeRequest request)

@PostMapping("/kit")
@NonNull RecoverySessionResponse verify(@Valid @RequestBody @NonNull RecoveryCredentialRequest request)
```

Persist a challenge even when the username/enrollment is absent. On verification, increment attempts through compare-and-set before matching. Generate a 32-byte random session token, persist only base64url SHA-256, and return the token once. Parse `Authorization: Recovery <token>` inside recovery controllers; do not grant a Spring `ROLE_USER` authentication.

- [ ] **Step 4: Run offline recovery tests**

Run: `.\gradlew.bat spotlessApply test --tests '*OfflineRecoveryApiTest' --console=plain`

Expected: all pass with generic external errors.

- [ ] **Step 5: Commit offline recovery sessions**

```powershell
git add -- src/main/java/top/focess/keystead/server/recovery src/main/java/top/focess/keystead/server/security/SecurityConfig.java src/test/java/top/focess/keystead/server/recovery
git commit -m "Add offline recovery sessions"
```

### Task 6: Implement verified-device recovery approval

**Files:**
- Create: `src/main/java/top/focess/keystead/server/identity/DeviceSignatureVerifier.java`
- Modify: `src/main/java/top/focess/keystead/server/identity/IdentityService.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryDeviceRequestPayload.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryDeviceApprovalRequest.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryDeviceRequestResponse.java`
- Modify: `src/main/java/top/focess/keystead/server/recovery/RecoverySessionService.java`
- Modify: `src/main/java/top/focess/keystead/server/recovery/RecoveryAuthController.java`
- Create: `src/test/java/top/focess/keystead/server/recovery/VerifiedDeviceRecoveryApiTest.java`

**Interfaces:**
- Produces: public request creation, authenticated pending-request listing, authenticated approval, and the same restricted session response as Task 5.

- [ ] **Step 1: Write failing fingerprint, signature, revocation, race, and scope tests**

Test canonical core bytes, matching short fingerprint, verified/non-revoked device requirement, wrong account/device/signature, expired request, request-key substitution, one approval winner, no private-key transfer, and optional opaque new-device vault packages.

- [ ] **Step 2: Run focused tests and confirm missing endpoints**

Run: `.\gradlew.bat test --tests '*VerifiedDeviceRecoveryApiTest' --console=plain`

Expected: endpoint assertions fail before implementation.

- [ ] **Step 3: Factor signature verification and implement approval**

```java
@Component
public final class DeviceSignatureVerifier {
    public boolean verifyVerifiedDevice(@NonNull String ownerId, @NonNull String deviceId,
            byte @NonNull [] payload, @NonNull String encodedSignature);
    boolean verifyRegisteredDevice(@NonNull StoredDevice device, byte @NonNull [] payload,
            @NonNull String encodedSignature);
}
```

`IdentityService.proveDevice` delegates to the package-private registered-device method because initial proof precedes verification. Recovery approval calls `verifyVerifiedDevice`, which loads the device internally and requires non-null `verifiedAt` and null `revokedAt`; no package-private entity crosses the identity-package boundary. It then atomically changes `PENDING` to `APPROVED` and issues a `DEVICE_APPROVAL` restricted session.

- [ ] **Step 4: Run device and recovery tests**

Run: `.\gradlew.bat spotlessApply test --tests '*VerifiedDeviceRecoveryApiTest' --tests '*UserDeviceApiTest' --console=plain`

Expected: all pass.

- [ ] **Step 5: Commit verified-device recovery**

```powershell
git add -- src/main/java/top/focess/keystead/server/identity src/main/java/top/focess/keystead/server/recovery src/test/java/top/focess/keystead/server/recovery
git commit -m "Add verified device recovery approval"
```

### Task 7: Complete password reset and replacement-device enrollment atomically

**Files:**
- Modify: `src/main/java/top/focess/keystead/server/identity/UserRepository.java`
- Create: `src/main/java/top/focess/keystead/server/identity/IdentityRecoveryService.java`
- Create: `src/main/java/top/focess/keystead/server/auth/AuthSessionRevocationService.java`
- Modify: `src/main/java/top/focess/keystead/server/auth/AuthService.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryCompletionRequest.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryCompletionResponse.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryCompletionService.java`
- Modify: `src/main/java/top/focess/keystead/server/recovery/RecoveryAuthController.java`
- Create: `src/test/java/top/focess/keystead/server/recovery/RecoveryCompletionApiTest.java`

**Interfaces:**
- Produces: `POST /api/v1/auth/recovery/complete` authorized only by a restricted recovery token.

- [ ] **Step 1: Write failing transactional-completion tests**

Test new password login, old password rejection, token-version increment, all refresh tokens revoked, replacement device verified/enrolled, kit/session consumed, duplicate completion rejected, malformed package rollback, device conflict rollback, failure-before-completion retaining kit, and response listing recovered versus pending vault ids.

- [ ] **Step 2: Run focused test and confirm endpoint failure**

Run: `.\gradlew.bat test --tests '*RecoveryCompletionApiTest' --console=plain`

Expected: endpoint assertions fail before implementation.

- [ ] **Step 3: Implement one transaction with JPA compare-and-set consumption**

```java
@Transactional
public @NonNull RecoveryCompletionResponse complete(@NonNull String recoveryToken,
        @NonNull RecoveryCompletionRequest request) {
    StoredRecoverySession session = sessions.requireActive(recoveryToken, clock.instant());
    identityRecovery.resetPasswordAndEnrollVerifiedDevice(session.username(), request);
    authSessions.revokeAll(session.username());
    if (sessions.consumeActive(session.tokenHash(), clock.instant()) != 1) {
        throw new RecoveryFailedException("Recovery failed");
    }
    enrollments.consumeAuthority(session);
    return coverage.response(session.username(), request.deviceId());
}
```

Encode the new password immediately with `PasswordEncoder`, pass no plaintext beyond the transaction call, and return only public identifiers/status. `UserRepository` uses JPQL to set the new hash, `updatedAt`, and `tokenVersion = tokenVersion + 1`.

- [ ] **Step 4: Run auth, device, and completion tests**

Run: `.\gradlew.bat spotlessApply test --tests '*RecoveryCompletionApiTest' --tests '*AuthApiTest' --tests '*UserDeviceApiTest' --console=plain`

Expected: all pass.

- [ ] **Step 5: Commit atomic completion**

```powershell
git add -- src/main/java/top/focess/keystead/server/auth src/main/java/top/focess/keystead/server/identity src/main/java/top/focess/keystead/server/recovery src/test/java/top/focess/keystead/server/recovery
git commit -m "Complete account recovery atomically"
```

### Task 8: Implement client enrollment, kit recovery, and device approval workflows

**Files:**
- Create: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/RecoveryClient.kt`
- Create: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/RecoveryWorkflow.kt`
- Create: `D:/IdeaProjects/keystead-client/src/test/kotlin/top/focess/keystead/client/RecoveryClientTest.kt`
- Create: `D:/IdeaProjects/keystead-client/src/test/kotlin/top/focess/keystead/client/RecoveryWorkflowTest.kt`
- Modify: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/ServerAuthentication.kt`

**Interfaces:**
- Consumes: core recovery crypto and server endpoints from Tasks 1-7.
- Produces: `generateRecoveryKit`, `recoverWithKit`, `requestDeviceApproval`, `approveRequest`, and `completeRecovery` client operations.

- [ ] **Step 1: Write failing strict-JSON and workflow tests**

Use fake `HttpClient` responses to test every request path/header/body, unknown-field rejection, generic failure mapping, secret-free exceptions, local package decryption before completion, no completion call after wrong kit/tamper, approval signature bytes, missing-vault reporting, input password wiping, and session token clearing.

- [ ] **Step 2: Run client recovery tests and confirm missing classes**

Run from `D:\IdeaProjects\keystead-client`: `.\gradlew.bat test --tests '*RecoveryClientTest' --tests '*RecoveryWorkflowTest' --console=plain`

Expected: compilation fails because recovery client/workflow types do not exist.

- [ ] **Step 3: Implement client interfaces and bounded state**

```kotlin
class RecoveryWorkflow(
    private val client: RecoveryClient,
    private val crypto: RecoveryCryptoService = DefaultRecoveryCryptoService(),
    private val identities: DeviceIdentityStore,
) {
    fun generateRecoveryKit(session: ServerAuthSession): String
    fun recoverWithKit(encodedKit: String, newPassword: CharArray, newDeviceId: String): RecoveryResult
    fun requestDeviceApproval(username: String, newDeviceId: String): PendingRecoveryRequest
    fun approveRequest(session: ServerAuthSession, identity: LocalDeviceIdentity, requestId: String)
}
```

Keep `RecoveryKit`, decrypted recovery private key, vault handles, replacement device private keys, passwords, and session tokens inside `use`/`finally` scopes. Do not store the printable kit in `SecureStorage`; return it once for offline saving.

- [ ] **Step 4: Run client recovery tests**

Run: `.\gradlew.bat test --tests '*RecoveryClientTest' --tests '*RecoveryWorkflowTest' --console=plain`

Expected: all pass.

- [ ] **Step 5: Preserve the no-Git boundary**

Run: `Test-Path -LiteralPath D:\IdeaProjects\keystead-client\.git`

Expected: `False`; do not commit client changes.

### Task 9: Add recovery UI, end-to-end coverage, and documentation

**Files:**
- Create: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/RecoveryViewModel.kt`
- Create: `D:/IdeaProjects/keystead-client/src/test/kotlin/top/focess/keystead/client/RecoveryViewModelTest.kt`
- Modify: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/Main.kt`
- Modify: `D:/IdeaProjects/keystead-client/README.md`
- Create: `src/test/java/top/focess/keystead/server/recovery/RecoveryEndToEndTest.java`
- Modify: `README.md`
- Modify: `keystead-core/README.md`

**Interfaces:**
- Produces: end-user kit generation/replacement, kit entry, approval request/fingerprint, approval, completion, recovered/pending-vault status, and permanent-loss messaging.

- [ ] **Step 1: Write failing view-model and end-to-end tests**

Cover state transitions without placing kit/password/private values in state `toString()`. Assert successful recovery remains `REPLACEMENT_KIT_REQUIRED` until a new enrollment generation and its required packages are committed. Server end-to-end tests enroll, create an opaque vault package, invalidate the password/device, recover through kit, open the package client-side through core, then repeat through device approval. Assert the no-authority path cannot recover.

- [ ] **Step 2: Run tests and confirm missing UI/end-to-end behavior**

Run client: `.\gradlew.bat test --tests '*RecoveryViewModelTest' --console=plain`

Run server: `.\gradlew.bat test --tests '*RecoveryEndToEndTest' --console=plain`

Expected: tests fail before UI orchestration and complete fixture exist.

- [ ] **Step 3: Implement Compose states and update README claims**

```kotlin
sealed interface RecoveryUiState {
    data object Idle : RecoveryUiState
    data class ShowKit(val encodedKit: String) : RecoveryUiState {
        override fun toString() = "ShowKit(<redacted>)"
    }
    data class AwaitingApproval(val requestId: String, val fingerprint: String) : RecoveryUiState
    data class Complete(val recoveredVaults: List<String>, val pendingVaults: List<String>) : RecoveryUiState
}
```

Require offline-storage confirmation before activating a replacement kit. Separate account-restored and per-vault-restored messages. Remove README statements claiming there is no account recovery once tests prove both paths; retain the explicit permanent-loss boundary and do not claim an external audit.

- [ ] **Step 4: Run complete core/server/client suites**

Run core: `.\gradlew.bat test --console=plain`

Run server: `.\gradlew.bat test --console=plain`

Run client from `D:\IdeaProjects\keystead-client`: `.\gradlew.bat test --console=plain`

Expected: every suite passes; report XML test/failure/error/skip totals for each repository.

- [ ] **Step 5: Commit Git-backed documentation and end-to-end tests only**

Core repository:

```powershell
git add -- keystead-core/README.md
git commit -m "Document recovery cryptography"
```

Server repository:

```powershell
git add -- README.md src/test/java/top/focess/keystead/server/recovery/RecoveryEndToEndTest.java
git commit -m "Document tested recovery workflows"
```

Do not commit the client repository.
