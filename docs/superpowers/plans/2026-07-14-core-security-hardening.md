# Keystead Core Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the reproducible Keystead Core lifecycle, memory-lifetime, parsing, context-binding, and filesystem weaknesses while adding compatibility-preserving KDF and secret-memory provider seams.

**Architecture:** One monitor serializes every operation on an unlocked vault handle. Secret owners delegate storage to an explicitly injected provider with wiped heap memory as the default. Crypto formats use bounded inputs, exact algorithm/version checks, canonical KDF parameters, and length-prefixed recovery contexts while retaining legacy readers.

**Tech Stack:** Java 21, JSpecify 1.0 explicit annotations, Tink 1.22.0, Bouncy Castle 1.84, JUnit Jupiter 5.10.3, Gradle 9.6.1, Spotless/AOSP Google Java Format.

## Global Constraints

- Modify only `keystead-core`, `README.md`, and this repository's ignored design/plan artifacts; do not inspect or modify server/client repositories.
- Preserve zero-knowledge behavior: no plaintext secret, recovery secret, vault key, private key, or master password may be persisted, logged, included in an exception, or returned from `toString()`.
- Keep explicit JSpecify `@NonNull`/`@Nullable`; do not add `package-info.java` annotation defaults.
- Keep the legacy `VaultHeader` constructor/accessors, existing PBKDF2 files, existing recovery packages, and existing public methods source-compatible. Binary compatibility is not required before 1.0.
- The user-owned formatting diff in `keystead-core/src/test/java/top/focess/keystead/service/VaultServiceTest.java` must remain uncommitted and excluded from every `git add`.
- Use red-green TDD for every behavioral change. Capture the expected failing assertion before production edits and rerun the focused test after the minimal fix.
- Use these exact limits: stored properties 1,048,576 bytes; envelope ciphertext 1,048,576 bytes; envelope AAD 65,536 bytes; encoded sync profile/envelope 2,097,152 characters each; wrapped device/recovery package 1,048,576 bytes; KDF salt 64 bytes; PBKDF2 iterations 10,000,000; KDF parameter entries 16; parameter names 64 ASCII characters.
- New recovery packages use binary context version 2; opening must try version 2 first and legacy version 1 second.
- Do not add a native-memory dependency or Argon2 implementation in this change.

---

### Task 1: Serialize vault lifecycle and prepared rotation

**Files:**
- Create: `keystead-core/src/test/java/top/focess/keystead/service/VaultHandleConcurrencyTest.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/service/DefaultVaultHandle.java`

**Interfaces:**
- Consumes: existing `VaultHandle`, `PreparedVaultKeyRotation`, `VaultStore.commitMutation`, and `VaultStore.commitVaultKeyRotation` APIs.
- Produces: one monitor per `DefaultVaultHandle`; all public operations that touch `vaultKey`, decrypted views, records, `closed`, or `rotationPrepared` are atomic with `close()` and rotation state.

- [ ] **Step 1: Write the failing concurrent-mutation/rotation test**

Create a test with `CountDownLatch callbackEntered`, `CountDownLatch releaseCallback`, and two executor tasks. The save callback sets title/password, signals `callbackEntered`, and waits. Start `prepareVaultKeyRotation()` while the callback is blocked, release the callback, commit the prepared rotation, and assert the returned rotated handle can reveal the saved password. The test must time out in five seconds rather than hang:

```java
assertTimeoutPreemptively(
        Duration.ofSeconds(5),
        () -> {
            Future<SecretId> save = executor.submit(() -> saveBlockedLogin(source, entered, release));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            Future<PreparedVaultKeyRotation> rotation =
                    executor.submit(source::prepareVaultKeyRotation);
            release.countDown();
            SecretId saved = save.get(2, TimeUnit.SECONDS);
            try (PreparedVaultKeyRotation prepared = rotation.get(2, TimeUnit.SECONDS);
                    VaultHandle rotated = commitPrepared(prepared)) {
                assertPassword(rotated, saved, "concurrent-password");
            }
        });
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```powershell
.\gradlew.bat :keystead-core:test --tests top.focess.keystead.service.VaultHandleConcurrencyTest --console=plain
```

Expected: FAIL because rotation snapshots before the earlier mutation commits, so the saved record is missing after rotation.

- [ ] **Step 3: Serialize parent-handle operations**

Use the `DefaultVaultHandle` instance monitor. Mark every public method that reads or mutates live handle state `synchronized`, including save/update/reveal/delete/list/sync/package/rotation methods, `isClosed()`, and `close()`. Keep the monitor held while caller callbacks execute and while `store.commitMutation` runs. Keep `beginPreparedRotation`, `releasePreparedRotation`, and `completePreparedRotation` synchronized. The required transition remains:

```java
private synchronized @NonNull PreparedVaultKeyRotation beginPreparedRotation(
        @NonNull VaultKey targetKey, @Nullable DeviceVaultKeyPackage stagedPackage) {
    requireOpen();
    if (rotationPrepared) {
        targetKey.close();
        throw new IllegalStateException("Vault key rotation is already prepared");
    }
    rotationPrepared = true;
    try {
        return new DefaultPreparedVaultKeyRotation(targetKey, stagedPackage);
    } catch (RuntimeException | Error error) {
        rotationPrepared = false;
        targetKey.close();
        throw error;
    }
}
```

Make the prepared object methods that read/mutate `committed`, `closed`, `targetTransferred`, `acceptedPackageFingerprints`, or `targetKey` synchronized. `commitWithDevicePackage` must coordinate final parent closure through `completePreparedRotation()` before transferring the target key.

- [ ] **Step 4: Run focused lifecycle tests and verify GREEN**

Run:

```powershell
.\gradlew.bat :keystead-core:test --tests top.focess.keystead.service.VaultHandleConcurrencyTest --tests top.focess.keystead.service.PreparedVaultKeyRotationTest --console=plain
```

Expected: PASS; no timeout, the concurrent save survives, and existing prepared-rotation behavior remains green.

- [ ] **Step 5: Commit Task 1**

```powershell
git add -- keystead-core/src/main/java/top/focess/keystead/service/DefaultVaultHandle.java keystead-core/src/test/java/top/focess/keystead/service/VaultHandleConcurrencyTest.java
git commit -m "Serialize vault lifecycle operations"
```

### Task 2: Add atomic pluggable secret memory ownership

**Files:**
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/SecretMemory.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/SecretMemoryProvider.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/HeapSecretMemoryProvider.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/memory/SecretMemoryProviderTest.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/memory/SecretBuffer.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/crypto/VaultKey.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/crypto/DeviceKeyPair.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/crypto/DefaultCryptoService.java`
- Modify: `keystead-core/src/test/java/top/focess/keystead/memory/SecretBufferTest.java`
- Modify: `keystead-core/src/test/java/top/focess/keystead/crypto/CryptoServiceTest.java`

**Interfaces:**
- Produces: `SecretMemoryProvider.protect(byte[])`, `SecretMemory.copyBytes(Consumer<byte[]>)`, `SecretBuffer.fromUtf8(byte[], SecretMemoryProvider)`, `SecretBuffer.fromChars(char[], SecretMemoryProvider)`, and a `DefaultCryptoService` constructor accepting a provider.
- Preserves: all existing constructors/factories default to `SecretMemoryProvider.heap()`.

- [ ] **Step 1: Write failing provider and close/access atomicity tests**

Test that an injected recording provider is invoked, that input arrays are still caller-owned, and that a concurrent close waits for an in-flight callback:

```java
Future<?> access = executor.submit(() -> buffer.copyBytes(bytes -> {
    entered.countDown();
    await(release);
    assertArrayEquals("secret".getBytes(UTF_8), bytes);
}));
assertTrue(entered.await(2, SECONDS));
Future<?> close = executor.submit(buffer::close);
assertThrows(TimeoutException.class, () -> close.get(100, MILLISECONDS));
release.countDown();
access.get(2, SECONDS);
close.get(2, SECONDS);
assertThrows(SecretDestroyedException.class, () -> buffer.copyBytes(bytes -> fail()));
```

Add equivalent package-level tests for `VaultKey.copyBytes` and `DeviceKeyPair.copyPrivateKey`.

- [ ] **Step 2: Run focused tests and verify RED**

```powershell
.\gradlew.bat :keystead-core:test --tests top.focess.keystead.memory.SecretMemoryProviderTest --tests top.focess.keystead.memory.SecretBufferTest --tests top.focess.keystead.crypto.CryptoServiceTest --console=plain
```

Expected: compile/test failure because provider interfaces, overloads, and atomic callback behavior do not exist.

- [ ] **Step 3: Implement provider-backed ownership**

Use these public contracts:

```java
public interface SecretMemory extends AutoCloseable {
    int length();
    boolean isClosed();
    void copyBytes(@NonNull Consumer<byte[]> consumer);
    @Override void close();
}

@FunctionalInterface
public interface SecretMemoryProvider {
    @NonNull SecretMemory protect(byte @NonNull [] value);
    static @NonNull SecretMemoryProvider heap() {
        return HeapSecretMemoryProvider.instance();
    }
}
```

`HeapSecretMemoryProvider` must defensively copy the input. Its storage methods are synchronized; `copyBytes` keeps the monitor for the complete callback and wipes the temporary copy in `finally`; `close` wipes the owned array before setting `closed`.

Refactor `SecretBuffer` to delegate byte ownership to `SecretMemory`. Existing factories call `SecretMemoryProvider.heap()`. Refactor `VaultKey` and the private half of `DeviceKeyPair` the same way. Add `DeviceKeyPair.copyPrivateKey(Consumer<byte[]>)`; retain `privateKey()` with `@Deprecated(forRemoval = false)` and implement it by cloning inside the callback.

Add this compatibility constructor path in `DefaultCryptoService`:

```java
public DefaultCryptoService(
        @NonNull SecureRandom random,
        @NonNull AeadCipher aeadCipher,
        @NonNull SecretMemoryProvider memoryProvider) {
    this.random = Objects.requireNonNull(random, "random");
    this.aeadCipher = Objects.requireNonNull(aeadCipher, "aeadCipher");
    this.memoryProvider = Objects.requireNonNull(memoryProvider, "memoryProvider");
    this.aeadCiphers = aeadCiphers(aeadCipher);
}
```

All old constructors delegate with `SecretMemoryProvider.heap()`.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run the command from Step 2. Expected: PASS with deterministic close-waits-for-callback behavior and unchanged crypto round trips.

- [ ] **Step 5: Commit Task 2**

```powershell
git add -- keystead-core/src/main/java/top/focess/keystead/memory keystead-core/src/main/java/top/focess/keystead/crypto/VaultKey.java keystead-core/src/main/java/top/focess/keystead/crypto/DeviceKeyPair.java keystead-core/src/main/java/top/focess/keystead/crypto/DefaultCryptoService.java keystead-core/src/test/java/top/focess/keystead/memory keystead-core/src/test/java/top/focess/keystead/crypto/CryptoServiceTest.java
git commit -m "Abstract atomic secret memory ownership"
```

### Task 3: Remove avoidable secret-bearing heap copies

**Files:**
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/WipeableByteArrayOutputStream.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/memory/WipeableByteArrayOutputStreamTest.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/memory/SecretBuffer.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/generator/DefaultMfaSecretGenerator.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/generator/DefaultGpgKeyGenerator.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/generator/GpgKeyPolicy.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/recovery/RecoveryKitCodec.java`
- Modify: corresponding memory/generator/recovery tests.

**Interfaces:**
- Produces: `RecoveryKitCodec.encodeSecret(RecoveryKit): SecretBuffer` and `RecoveryKitCodec.decode(SecretBuffer): RecoveryKit`.
- Preserves: deprecated `RecoveryKitCodec.encode(RecoveryKit): String` and `decode(String)` for compatibility.

- [ ] **Step 1: Write failing memory-copy regression tests**

Add tests for:

```java
try (SecretBuffer encoded = RecoveryKitCodec.encodeSecret(kit);
        RecoveryKit decoded = RecoveryKitCodec.decode(encoded)) {
    assertEquals(kit.enrollmentId(), decoded.enrollmentId());
    assertEquals(kit.generation(), decoded.generation());
    assertArrayEquals(secret, decoded.recoverySecret());
}
```

Use a deterministic `SecureRandom` to assert the MFA RFC 4648 Base32 output without converting production intermediates to `String`. Test `WipeableByteArrayOutputStream.close()` by reflectively reading its inherited backing array and asserting every byte is zero. Test that an invalid `GpgKeyPolicy` leaves the caller's passphrase unchanged.

- [ ] **Step 2: Run focused tests and verify RED**

```powershell
.\gradlew.bat :keystead-core:test --tests top.focess.keystead.recovery.RecoveryKitCodecTest --tests top.focess.keystead.generator.DefaultMfaSecretGeneratorTest --tests top.focess.keystead.generator.DefaultGpgKeyGeneratorTest --tests top.focess.keystead.memory.WipeableByteArrayOutputStreamTest --console=plain
```

Expected: compile failures for new safe APIs/stream and a failing invalid-policy ownership assertion.

- [ ] **Step 3: Implement mutable encodings and wipeable stream**

`WipeableByteArrayOutputStream` extends `ByteArrayOutputStream`; its synchronized `close()` fills `buf[0..buf.length)` with zero and sets `count = 0`. It exposes `toSecretBuffer(SecretMemoryProvider)` that copies only `count` bytes into a temporary, builds the buffer, and wipes the temporary.

Replace MFA `StringBuilder` with a pre-sized `char[]`:

```java
int outputLength = (secret.length * 8 + 4) / 5;
char[] output = new char[outputLength];
int outputIndex = 0;
// append each five-bit symbol directly to output[outputIndex++]
```

Use `WipeableByteArrayOutputStream` in GPG private-key serialization. Validate every non-secret `GpgKeyPolicy` argument before copying the passphrase; never wipe caller-owned input in a constructor.

Implement recovery-kit safe encoding with mutable ASCII byte arrays and `Base64.Encoder.encode(byte[])`. Digest the body bytes directly, assemble the final bytes, call `SecretBuffer.fromUtf8`, and wipe every temporary. The safe decoder copies bytes from the `SecretBuffer`, parses dot positions without constructing a full `String`, Base64-decodes byte slices, and constructs `String` only for the public enrollment ID and generation. Mark the legacy secret-`String` encoder `@Deprecated(forRemoval = false)` and document heap-dump exposure.

Replace convenience charset calls in `SecretBuffer` with explicit encoder/decoder work arrays and wipe those arrays in all success/error paths.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run Step 2's command. Expected: PASS and no plaintext/private-key value in exception or `toString()` output.

- [ ] **Step 5: Commit Task 3**

```powershell
git add -- keystead-core/src/main/java/top/focess/keystead/memory keystead-core/src/main/java/top/focess/keystead/generator keystead-core/src/main/java/top/focess/keystead/recovery/RecoveryKitCodec.java keystead-core/src/test/java/top/focess/keystead/memory keystead-core/src/test/java/top/focess/keystead/generator keystead-core/src/test/java/top/focess/keystead/recovery/RecoveryKitCodecTest.java
git commit -m "Reduce avoidable secret heap copies"
```

### Task 4: Enforce crypto versions, key sizes, and resource ceilings

**Files:**
- Create: `keystead-core/src/main/java/top/focess/keystead/model/SecurityLimits.java`
- Modify: `EncryptedEnvelope.java`, `VaultHeader.java`, `DeviceVaultKeyPackage.java`, `EncryptedSyncRecord.java`, `DefaultCryptoService.java`, `JdkAesGcmCipher.java`, `TinkAesGcmCipher.java`.
- Modify: corresponding model/crypto/service tests.

**Interfaces:**
- Produces: named constants containing the exact Global Constraints limits.
- Enforces: version 1 during decryption and 32-byte AES-256 keys at both cipher entry points and `VaultKey` construction.

- [ ] **Step 1: Write one-over-the-limit and unsupported-version tests**

Use `assertThrows` for ciphertext `MAX_ENVELOPE_CIPHERTEXT_BYTES + 1`, AAD `MAX_ENVELOPE_AAD_BYTES + 1`, device package `MAX_WRAPPED_KEY_PACKAGE_BYTES + 1`, sync strings `MAX_ENCODED_SYNC_CHARACTERS + 1`, salt `MAX_KDF_SALT_BYTES + 1`, AES keys of 16/24/31/33 bytes, and an otherwise-valid envelope copied with version 2. Test exact maxima are accepted where allocation is reasonable.

- [ ] **Step 2: Run focused tests and verify RED**

```powershell
.\gradlew.bat :keystead-core:test --tests top.focess.keystead.model.ModelTest --tests top.focess.keystead.service.DeviceVaultKeyPackageTest --tests top.focess.keystead.service.SyncExportTest --tests top.focess.keystead.service.SyncImportConflictTest --tests top.focess.keystead.crypto.CryptoServiceTest --tests top.focess.keystead.crypto.CryptoProviderTest --console=plain
```

Expected: new limit/version/key-size assertions fail.

- [ ] **Step 3: Implement exact validation before copies or crypto work**

Create `SecurityLimits` with the exact constants from Global Constraints. Constructors validate lengths before `Arrays.copyOf`. `DefaultCryptoService.decrypt` starts with:

```java
if (envelope.version() != 1) {
    throw new CryptoException("Unsupported encrypted envelope version");
}
```

Both AES-256 cipher implementations reject `keyBytes.length != 32` before constructing provider objects. `VaultKey` applies the same invariant. Do not include rejected data in messages.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run Step 2's command. Expected: PASS; over-limit inputs fail before provider calls.

- [ ] **Step 5: Commit Task 4**

```powershell
git add -- keystead-core/src/main/java/top/focess/keystead/model keystead-core/src/main/java/top/focess/keystead/service/DeviceVaultKeyPackage.java keystead-core/src/main/java/top/focess/keystead/service/EncryptedSyncRecord.java keystead-core/src/main/java/top/focess/keystead/crypto keystead-core/src/test/java/top/focess/keystead/model keystead-core/src/test/java/top/focess/keystead/service/DeviceVaultKeyPackageTest.java keystead-core/src/test/java/top/focess/keystead/service/SyncExportTest.java keystead-core/src/test/java/top/focess/keystead/service/SyncImportConflictTest.java keystead-core/src/test/java/top/focess/keystead/crypto
git commit -m "Bound core cryptographic inputs"
```

### Task 5: Add canonical KDF provider abstraction and header compatibility

**Files:**
- Create: `keystead-core/src/main/java/top/focess/keystead/crypto/KdfParameters.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/crypto/PasswordKeyDerivation.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/crypto/Pbkdf2KeyDerivation.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/crypto/KdfProviderTest.java`
- Modify: `VaultHeader.java`, `DefaultCryptoService.java`, `DefaultVaultService.java`, `FileVaultStore.java`, `BackupArchiveCodec.java`, and their tests.

**Interfaces:**
- Produces: immutable `KdfParameters`, pluggable `PasswordKeyDerivation`, and `DefaultCryptoService.supportsPasswordKdf(String)`.
- Preserves: legacy PBKDF2 constructor/accessors and properties; new canonical entries are `kdf.parameter.<name>=<decimal integer>`.

- [ ] **Step 1: Write failing provider/header compatibility tests**

Test a recording provider with algorithm `TEST-KDF`, parameters `iterations=3` and `memoryKiB=64`, and verify `DefaultCryptoService` selects it exactly. Verify an unknown algorithm is rejected without calling PBKDF2. Round-trip a legacy PBKDF2 header and a generic header through `FileVaultStore` and `BackupArchiveCodec`; assert old property fixtures still open.

- [ ] **Step 2: Run focused tests and verify RED**

```powershell
.\gradlew.bat :keystead-core:test --tests top.focess.keystead.crypto.KdfProviderTest --tests top.focess.keystead.store.FileVaultStoreTest --tests top.focess.keystead.service.VaultBackupServiceTest --tests top.focess.keystead.service.VaultServiceTest --console=plain
```

Expected: compile failures for KDF provider types and generic header construction.

- [ ] **Step 3: Implement immutable canonical KDF parameters**

Use this API:

```java
public record KdfParameters(
        @NonNull String algorithm,
        byte @NonNull [] salt,
        @NonNull Map<String, Integer> parameters) {
    public static final String ITERATIONS = "iterations";
    public static @NonNull KdfParameters pbkdf2(
            @NonNull String algorithm, byte @NonNull [] salt, int iterations);
    public int required(@NonNull String name);
}

public interface PasswordKeyDerivation {
    @NonNull String algorithm();
    byte @NonNull [] derive(
            char @NonNull [] password, @NonNull KdfParameters parameters, int outputBytes);
}
```

Validate algorithm/name/value/count/salt limits in the compact constructor and defensively copy salt/map. `Pbkdf2KeyDerivation` accepts only `iterations`, caps it at 10,000,000, clears `PBEKeySpec`, wipes password copies, and returns exactly `outputBytes`.

Convert `VaultHeader` from record to final class with value equality/hash code. Retain the old constructor and all old accessor names; add a constructor/accessor for `KdfParameters`. Device-package headers retain their existing non-password representation and are not passed to password KDF providers.

Register PBKDF2 SHA-256/SHA-512 providers by default. Add a full constructor accepting `Collection<PasswordKeyDerivation>`; reject duplicate algorithms. `DefaultVaultService` asks `crypto.supportsPasswordKdf` and passes `header.kdfParameters()`.

File/backup writers emit legacy fields plus sorted `kdf.parameter.*` entries. Readers prefer canonical entries when present and otherwise synthesize `iterations` from old fields. Unknown parameters remain preserved but the selected provider decides whether to accept them.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run Step 2's command. Expected: PASS for legacy and generic round trips, exact provider selection, and fail-closed unknown algorithms.

- [ ] **Step 5: Commit Task 5**

```powershell
git add -- keystead-core/src/main/java/top/focess/keystead/crypto keystead-core/src/main/java/top/focess/keystead/model/VaultHeader.java keystead-core/src/main/java/top/focess/keystead/service/DefaultVaultService.java keystead-core/src/main/java/top/focess/keystead/service/BackupArchiveCodec.java keystead-core/src/main/java/top/focess/keystead/store/FileVaultStore.java keystead-core/src/test/java/top/focess/keystead/crypto/KdfProviderTest.java keystead-core/src/test/java/top/focess/keystead/store/FileVaultStoreTest.java keystead-core/src/test/java/top/focess/keystead/service/VaultBackupServiceTest.java
git commit -m "Abstract password key derivation"
```

### Task 6: Canonically bind recovery wrapping contexts

**Files:**
- Create: `keystead-core/src/main/java/top/focess/keystead/recovery/RecoveryContextCodec.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/recovery/RecoveryContextCodecTest.java`
- Modify: `DefaultRecoveryCryptoService.java`
- Modify: `RecoveryCryptoServiceTest.java`

**Interfaces:**
- Produces: package-private `RecoveryContextCodec.version2(...)` and `legacyVersion1(...)` byte arrays.
- Preserves: opening old packages by a controlled second decryption attempt.

- [ ] **Step 1: Write failing collision and legacy-compatibility tests**

Use the two tuples from the review:

```java
byte[] first = version2("u", "v", "e", 1L, "k|generation:2|key:z");
byte[] second = version2("u", "v", "e|generation:1|key:k", 2L, "z");
assertFalse(Arrays.equals(first, second));
assertArrayEquals(
        legacyVersion1("u", "v", "e", 1L, "k|generation:2|key:z"),
        legacyVersion1("u", "v", "e|generation:1|key:k", 2L, "z"));
```

Create a recovery package manually with the legacy context and assert the updated service still opens it. Assert newly wrapped packages open with v2 and fail if any field changes.

- [ ] **Step 2: Run focused tests and verify RED**

```powershell
.\gradlew.bat :keystead-core:test --tests top.focess.keystead.recovery.RecoveryContextCodecTest --tests top.focess.keystead.recovery.RecoveryCryptoServiceTest --console=plain
```

Expected: compile failure because the codec does not exist.

- [ ] **Step 3: Implement versioned length-prefix encoding and fallback**

Version 2 is `KRC2`, then five fields (`username`, `vaultId`, `enrollmentId`, `generation`, `keyId`). Text fields are strict UTF-8 preceded by a four-byte big-endian length; generation is one eight-byte big-endian signed long and must be positive. Enforce 64 KiB per text field and wipe encoded temporary arrays.

`wrapVaultKey` always uses `version2`. `openVault` decrypts the recovery private key once, tries provisioning with v2, and on `CryptoException` tries legacy v1. If both fail, throw `CryptoException("Could not open recovery vault package", secondFailure)` without field values. Wipe both contexts, ciphertext, and private key in `finally`.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run Step 2's command. Expected: PASS; v2 contexts do not collide and legacy packages still open.

- [ ] **Step 5: Commit Task 6**

```powershell
git add -- keystead-core/src/main/java/top/focess/keystead/recovery keystead-core/src/test/java/top/focess/keystead/recovery
git commit -m "Canonically bind recovery contexts"
```

### Task 7: Bound and contain FileVaultStore paths

**Files:**
- Modify: `keystead-core/src/main/java/top/focess/keystead/store/FileVaultStore.java`
- Modify: `keystead-core/src/test/java/top/focess/keystead/store/FileVaultStoreTest.java`

**Interfaces:**
- Produces: bounded property loading and static no-follow containment for every managed descendant.
- Preserves: a caller-selected vault root may itself be a symlink; descendants created/managed beneath the normalized root may not be symlinks.

- [ ] **Step 1: Write failing oversized-file and symlink tests**

Write `vault.properties` with `MAX_STORED_PROPERTIES_BYTES + 1` bytes and assert `loadVaultHeader` throws `StoreException` mentioning only the size limit. Where link creation succeeds, point `secrets` at an outside directory, call `saveSecretRecord`, assert rejection, and assert the outside directory remains unchanged. Use a JUnit assumption only when the platform denies link creation.

- [ ] **Step 2: Run focused tests and verify RED**

```powershell
.\gradlew.bat :keystead-core:test --tests top.focess.keystead.store.FileVaultStoreTest --console=plain
```

Expected: oversized properties are currently loaded and the static symlink is followed.

- [ ] **Step 3: Implement bounded reads and static descendant validation**

Normalize the constructor root:

```java
this.vaultDirectory =
        Objects.requireNonNull(vaultDirectory, "vaultDirectory").toAbsolutePath().normalize();
```

Before every managed open/create/move/delete/list, call a helper that normalizes the target, requires `target.startsWith(vaultDirectory)`, and walks existing components below the root with `Files.isSymbolicLink(component)`. Throw `StoreException("Vault path contains a symbolic link", null)` without exposing the external target.

Replace direct `Properties.load(Files.newInputStream(path))` with `readNBytes(MAX_STORED_PROPERTIES_BYTES + 1)`. Reject the extra byte before parsing, load from `ByteArrayInputStream`, and wipe the byte array in `finally`.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run Step 2's command. Expected: PASS; outside directory unchanged and maximum-size handling deterministic.

- [ ] **Step 5: Commit Task 7**

```powershell
git add -- keystead-core/src/main/java/top/focess/keystead/store/FileVaultStore.java keystead-core/src/test/java/top/focess/keystead/store/FileVaultStoreTest.java
git commit -m "Contain and bound file vault storage"
```

### Task 8: Document memory guarantees and verify the whole core

**Files:**
- Modify: `README.md`
- Modify: core tests only if the complete run reveals a regression directly caused by Tasks 1-7.

**Interfaces:**
- Produces: accurate documentation of provider extensibility, native-memory boundaries, deprecated compatibility APIs, limits, and KDF migration behavior.

- [ ] **Step 1: Update the technical README**

Document all of the following without marketing guarantees:

- `SecretBuffer` is a provider-backed facade; heap is default and native locked memory is optional future work.
- Wiping reduces lifetime but cannot defeat a debugger, injected agent, privileged process reader, copying GC, JIT/native temporary, or provider-owned copy.
- `VirtualLock`/`mlock` prevent paging, not live-memory reading.
- New password KDFs require an explicit provider plus canonical header parameters and migration tests; unknown algorithms fail closed.
- The safe recovery-kit API is preferred; legacy `String` encoding is heap-dump visible.
- List the enforced file/envelope/package/KDF limits.

- [ ] **Step 2: Run formatting and the complete Core suite**

```powershell
.\gradlew.bat :keystead-core:test spotlessCheck --console=plain --no-daemon
```

Expected: 0 failures, 0 errors, and successful Spotless checks. Read all `TEST-*.xml` files and report the actual suite/test/skipped totals.

- [ ] **Step 3: Verify repository scope and secret redaction**

```powershell
git diff --check
git status --short
git diff --name-only 4b7bee2..HEAD
rg -n "D:\\IdeaProjects|core-security-hardening" README.md docs/superpowers/specs/2026-07-14-core-security-hardening-design.md docs/superpowers/plans/2026-07-14-core-security-hardening.md
```

Expected: no local path in tracked documentation; only Core/design/plan/README files changed; the sole uncommitted tracked diff is the preserved `VaultServiceTest` formatting.

- [ ] **Step 4: Commit documentation**

```powershell
git add -- README.md
git commit -m "Document core memory security boundaries"
```

- [ ] **Step 5: Run final branch review**

Generate a review package from merge base `4b7bee2` through `HEAD`. The reviewer must check every design requirement, concurrency correctness, wipe/ownership behavior, compatibility, limit placement before allocation, zero-knowledge/redaction, JSpecify annotations, and test evidence. Fix every Critical/Important issue and rerun its focused tests plus the complete command from Step 2.
