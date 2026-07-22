package top.focess.keystead.recovery;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.service.CreateVaultRequest;
import top.focess.keystead.service.DefaultVaultService;
import top.focess.keystead.service.DeviceVaultKeyPackage;
import top.focess.keystead.service.VaultHandle;
import top.focess.keystead.store.FileVaultStore;

class RecoveryCryptoServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-14T00:00:00Z"), ZoneOffset.UTC);
    private static final VaultId VAULT_ID =
            new VaultId(UUID.fromString("50000000-0000-0000-0000-000000000001"));

    @TempDir Path tempDir;

    @Test
    void enrollmentWrapsAndRecoversVaultOnlyForBoundContext() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("source")), CLOCK);
        DefaultVaultService recoveredService =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("recovered")), CLOCK);

        try (RecoveryEnrollmentMaterial enrollment = recovery.enroll("enrollment-1", 1L);
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(VAULT_ID), masterPassword())) {
            RecoveryVaultKeyPackage keyPackage =
                    recovery.wrapVaultKey(
                            source, enrollment.publicKey(), "alice", VAULT_ID.value().toString());
            try (VaultHandle recovered =
                    recovery.openVault(
                            recoveredService,
                            VAULT_ID,
                            keyPackage,
                            enrollment.kit(),
                            enrollment.encryptedPrivateKey())) {
                assertEquals(source.vaultKeyId(), recovered.vaultKeyId());
            }

            RecoveryVaultKeyPackage wrongUser =
                    new RecoveryVaultKeyPackage(
                            "mallory",
                            keyPackage.vaultId(),
                            keyPackage.vaultKeyId(),
                            keyPackage.enrollmentId(),
                            keyPackage.generation(),
                            keyPackage.keyAlgorithm(),
                            keyPackage.encryptedVaultKey());
            CryptoException wrongUserFailure =
                    assertThrows(
                            CryptoException.class,
                            () ->
                                    recovery.openVault(
                                            recoveredService,
                                            VAULT_ID,
                                            wrongUser,
                                            enrollment.kit(),
                                            enrollment.encryptedPrivateKey()));
            assertEquals("Could not open recovery vault package", wrongUserFailure.getMessage());
            assertInstanceOf(CryptoException.class, wrongUserFailure.getCause());
            assertFalse(wrongUserFailure.toString().contains("mallory"));

            RecoveryVaultKeyPackage wrongKeyId =
                    new RecoveryVaultKeyPackage(
                            keyPackage.username(),
                            keyPackage.vaultId(),
                            new KeyId("different-vault-key"),
                            keyPackage.enrollmentId(),
                            keyPackage.generation(),
                            keyPackage.keyAlgorithm(),
                            keyPackage.encryptedVaultKey());
            assertThrows(
                    CryptoException.class,
                    () ->
                            recovery.openVault(
                                    recoveredService,
                                    VAULT_ID,
                                    wrongKeyId,
                                    enrollment.kit(),
                                    enrollment.encryptedPrivateKey()));
        }
    }

    @Test
    void opensManuallyConstructedLegacyVersion1Package() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(
                        new FileVaultStore(tempDir.resolve("legacy-source")), CLOCK);
        DefaultVaultService recoveredService =
                new DefaultVaultService(
                        new FileVaultStore(tempDir.resolve("legacy-target")), CLOCK);

        try (RecoveryEnrollmentMaterial enrollment = recovery.enroll("legacy-enrollment", 3L);
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(VAULT_ID), masterPassword())) {
            RecoveryVaultKeyPackage legacyPackage =
                    legacyPackage(source, enrollment.publicKey(), "alice");

            try (VaultHandle recovered =
                    recovery.openVault(
                            recoveredService,
                            VAULT_ID,
                            legacyPackage,
                            enrollment.kit(),
                            enrollment.encryptedPrivateKey())) {
                assertEquals(source.vaultKeyId(), recovered.vaultKeyId());
            }
        }
    }

    @Test
    void newlyWrappedPackagesUseVersion2Context() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("v2-source")), CLOCK);
        DefaultVaultService legacyTarget =
                new DefaultVaultService(
                        new FileVaultStore(tempDir.resolve("v1-context-target")), CLOCK);
        DefaultVaultService version2Target =
                new DefaultVaultService(
                        new FileVaultStore(tempDir.resolve("v2-context-target")), CLOCK);

        try (DeviceKeyPair keyPair = new DefaultCryptoService().generateDeviceKeyPair();
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(VAULT_ID), masterPassword())) {
            byte[] publicKeyBytes = keyPair.publicKey();
            byte[] version2Context = null;
            byte[] legacyContext = null;
            try {
                RecoveryPublicKey publicKey =
                        new RecoveryPublicKey(
                                "v2-enrollment", 2L, keyPair.keyAlgorithm(), publicKeyBytes);
                RecoveryVaultKeyPackage keyPackage =
                        recovery.wrapVaultKey(
                                source, publicKey, "alice", VAULT_ID.value().toString());
                DeviceVaultKeyPackage devicePackage =
                        new DeviceVaultKeyPackage(
                                keyPackage.vaultKeyId(),
                                keyPackage.keyAlgorithm(),
                                keyPackage.encryptedVaultKey());
                version2Context =
                        RecoveryContextCodec.version2(
                                keyPackage.username(),
                                keyPackage.vaultId(),
                                keyPackage.enrollmentId(),
                                keyPackage.generation(),
                                keyPackage.vaultKeyId().value());
                legacyContext =
                        RecoveryContextCodec.legacyVersion1(
                                keyPackage.username(),
                                keyPackage.vaultId(),
                                keyPackage.enrollmentId(),
                                keyPackage.generation(),
                                keyPackage.vaultKeyId().value());
                byte[] finalVersion2Context = version2Context;
                byte[] finalLegacyContext = legacyContext;
                keyPair.copyPrivateKey(
                        privateKey -> {
                            assertThrows(
                                    CryptoException.class,
                                    () ->
                                            legacyTarget.provisionVault(
                                                    VAULT_ID,
                                                    devicePackage,
                                                    privateKey,
                                                    finalLegacyContext));
                            try (VaultHandle recovered =
                                    version2Target.provisionVault(
                                            VAULT_ID,
                                            devicePackage,
                                            privateKey,
                                            finalVersion2Context)) {
                                assertEquals(source.vaultKeyId(), recovered.vaultKeyId());
                            }
                        });
            } finally {
                Arrays.fill(publicKeyBytes, (byte) 0);
                if (version2Context != null) {
                    Arrays.fill(version2Context, (byte) 0);
                }
                if (legacyContext != null) {
                    Arrays.fill(legacyContext, (byte) 0);
                }
            }
        }
    }

    @Test
    void wrongKitAndTamperedPrivateEnvelopeCannotRecover() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("source-wrong")), CLOCK);
        DefaultVaultService recoveredService =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("target-wrong")), CLOCK);

        try (RecoveryEnrollmentMaterial enrollment = recovery.enroll("enrollment-1", 1L);
                RecoveryEnrollmentMaterial other = recovery.enroll("enrollment-2", 1L);
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(VAULT_ID), masterPassword())) {
            RecoveryVaultKeyPackage keyPackage =
                    recovery.wrapVaultKey(
                            source, enrollment.publicKey(), "alice", VAULT_ID.value().toString());
            assertThrows(
                    CryptoException.class,
                    () ->
                            recovery.openVault(
                                    recoveredService,
                                    VAULT_ID,
                                    keyPackage,
                                    other.kit(),
                                    enrollment.encryptedPrivateKey()));

            byte[] tampered = enrollment.encryptedPrivateKey();
            tampered[tampered.length - 1] ^= 1;
            assertThrows(
                    CryptoException.class,
                    () ->
                            recovery.openVault(
                                    recoveredService,
                                    VAULT_ID,
                                    keyPackage,
                                    enrollment.kit(),
                                    tampered));
        }
    }

    @Test
    void accountCredentialIsDeterministicAndDomainBound() {
        byte[] secret = bytes(32, (byte) 12);
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService(new SecureRandom());
        try (RecoveryKit first = new RecoveryKit(1, "enrollment-1", 1L, secret);
                RecoveryKit same = new RecoveryKit(1, "enrollment-1", 1L, secret);
                RecoveryKit otherGeneration = new RecoveryKit(1, "enrollment-1", 2L, secret)) {
            byte[] firstCredential = recovery.accountCredential(first);
            byte[] sameCredential = recovery.accountCredential(same);
            byte[] otherCredential = recovery.accountCredential(otherGeneration);
            try {
                assertArrayEquals(firstCredential, sameCredential);
                assertFalse(Arrays.equals(firstCredential, otherCredential));
                assertEquals(32, firstCredential.length);
            } finally {
                Arrays.fill(firstCredential, (byte) 0);
                Arrays.fill(sameCredential, (byte) 0);
                Arrays.fill(otherCredential, (byte) 0);
            }
        }
    }

    @Test
    void recoveryServiceTextDoesNotExposeSecretMaterial() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        assertEquals("DefaultRecoveryCryptoService(<redacted>)", recovery.toString());
    }

    @Test
    void enrollRejectsNonPositiveGeneration() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        assertThrows(IllegalArgumentException.class, () -> recovery.enroll("enrollment-1", 0L));
        assertThrows(IllegalArgumentException.class, () -> recovery.enroll("enrollment-1", -1L));
    }

    @Test
    void wrapVaultKeyRejectsMismatchedVaultId() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(
                        new FileVaultStore(tempDir.resolve("mismatch-source")), CLOCK);
        try (RecoveryEnrollmentMaterial enrollment = recovery.enroll("enrollment-1", 1L);
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(VAULT_ID), masterPassword())) {
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            recovery.wrapVaultKey(
                                    source,
                                    enrollment.publicKey(),
                                    "alice",
                                    "50000000-0000-0000-0000-000000000099"));
        }
    }

    @Test
    void openVaultRejectsVaultIdAndGenerationMismatch() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("id-source")), CLOCK);
        DefaultVaultService recoveredService =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("id-target")), CLOCK);
        VaultId wrongVaultId = new VaultId(UUID.fromString("50000000-0000-0000-0000-000000000099"));
        try (RecoveryEnrollmentMaterial enrollment = recovery.enroll("enrollment-1", 1L);
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(VAULT_ID), masterPassword())) {
            RecoveryVaultKeyPackage keyPackage =
                    recovery.wrapVaultKey(
                            source, enrollment.publicKey(), "alice", VAULT_ID.value().toString());
            assertThrows(
                    CryptoException.class,
                    () ->
                            recovery.openVault(
                                    recoveredService,
                                    wrongVaultId,
                                    keyPackage,
                                    enrollment.kit(),
                                    enrollment.encryptedPrivateKey()));
            RecoveryVaultKeyPackage wrongGeneration =
                    new RecoveryVaultKeyPackage(
                            keyPackage.username(),
                            keyPackage.vaultId(),
                            keyPackage.vaultKeyId(),
                            keyPackage.enrollmentId(),
                            keyPackage.generation() + 1L,
                            keyPackage.keyAlgorithm(),
                            keyPackage.encryptedVaultKey());
            assertThrows(
                    CryptoException.class,
                    () ->
                            recovery.openVault(
                                    recoveredService,
                                    VAULT_ID,
                                    wrongGeneration,
                                    enrollment.kit(),
                                    enrollment.encryptedPrivateKey()));
        }
    }

    @Test
    void openVaultRejectsMalformedPrivateKeyEnvelope() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("env-source")), CLOCK);
        DefaultVaultService recoveredService =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("env-target")), CLOCK);
        try (RecoveryEnrollmentMaterial enrollment = recovery.enroll("enrollment-1", 1L);
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(VAULT_ID), masterPassword())) {
            RecoveryVaultKeyPackage keyPackage =
                    recovery.wrapVaultKey(
                            source, enrollment.publicKey(), "alice", VAULT_ID.value().toString());
            assertThrows(
                    CryptoException.class,
                    () ->
                            recovery.openVault(
                                    recoveredService,
                                    VAULT_ID,
                                    keyPackage,
                                    enrollment.kit(),
                                    new byte[5]));
            byte[] wrongMagic = enrollment.encryptedPrivateKey().clone();
            wrongMagic[0] ^= 1;
            assertThrows(
                    CryptoException.class,
                    () ->
                            recovery.openVault(
                                    recoveredService,
                                    VAULT_ID,
                                    keyPackage,
                                    enrollment.kit(),
                                    wrongMagic));
        }
    }

    private static char[] masterPassword() {
        return "correct horse battery staple".toCharArray();
    }

    private static byte[] bytes(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private static RecoveryVaultKeyPackage legacyPackage(
            VaultHandle source, RecoveryPublicKey recoveryKey, String username) {
        byte[] publicKey = recoveryKey.publicKey();
        byte[] context =
                historicalLegacyContext(
                        username,
                        VAULT_ID.value().toString(),
                        recoveryKey.enrollmentId(),
                        recoveryKey.generation(),
                        source.vaultKeyId().value());
        byte[] ciphertext = null;
        try {
            DeviceVaultKeyPackage wrapped = source.wrapVaultKeyPackageForDevice(publicKey, context);
            ciphertext = wrapped.encryptedVaultKey();
            return new RecoveryVaultKeyPackage(
                    username,
                    VAULT_ID.value().toString(),
                    wrapped.vaultKeyId(),
                    recoveryKey.enrollmentId(),
                    recoveryKey.generation(),
                    wrapped.keyAlgorithm(),
                    ciphertext);
        } finally {
            Arrays.fill(publicKey, (byte) 0);
            Arrays.fill(context, (byte) 0);
            if (ciphertext != null) {
                Arrays.fill(ciphertext, (byte) 0);
            }
        }
    }

    @Test
    void nonceRandomFailureStillWipesAllocatedNonce() {
        FailingNonceRandom random = new FailingNonceRandom();
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService(random);

        assertThrows(
                IllegalStateException.class,
                () -> recovery.enroll("random-failure-enrollment", 1L));

        assertNotNull(random.failedNonce);
        assertArrayEquals(new byte[12], random.failedNonce);
    }

    private static byte[] historicalLegacyContext(
            String username, String vaultId, String enrollmentId, long generation, String keyId) {
        return ("keystead-recovery-vault-package-v1|user:"
                        + username
                        + "|vault:"
                        + vaultId
                        + "|enrollment:"
                        + enrollmentId
                        + "|generation:"
                        + generation
                        + "|key:"
                        + keyId)
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static final class FailingNonceRandom extends SecureRandom {

        private int calls;
        private byte[] failedNonce;

        @Override
        public void nextBytes(byte[] bytes) {
            calls++;
            Arrays.fill(bytes, (byte) calls);
            if (calls == 2) {
                failedNonce = bytes;
                throw new IllegalStateException("deliberate nonce failure");
            }
        }
    }
}
