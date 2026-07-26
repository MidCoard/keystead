package top.focess.keystead.recovery;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.VaultFingerprint;
import top.focess.keystead.service.CreateVaultRequest;
import top.focess.keystead.service.DefaultVaultService;
import top.focess.keystead.service.DeviceVaultKeyPackage;
import top.focess.keystead.service.VaultHandle;

class RecoveryCryptoServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-14T00:00:00Z"), ZoneOffset.UTC);

    @TempDir Path tempDir;

    private Path vaultFile(String name) {
        return tempDir.resolve(name + ".kv");
    }

    @Test
    void enrollmentWrapsAndRecoversVaultOnlyForBoundContext() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        DefaultVaultService recoveredService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (RecoveryEnrollmentMaterial enrollment = recovery.enroll("enrollment-1", 1L);
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(vaultFile("source")), masterPassword())) {
            RecoveryVaultKeyPackage keyPackage =
                    recovery.wrapVaultKey(source, enrollment.publicKey(), "alice");
            try (VaultHandle recovered =
                    recovery.openVault(
                            recoveredService,
                            vaultFile("recovered"),
                            keyPackage,
                            enrollment.kit(),
                            enrollment.encryptedPrivateKey())) {
                assertEquals(source.vaultKeyId(), recovered.vaultKeyId());
            }

            RecoveryVaultKeyPackage wrongUser =
                    new RecoveryVaultKeyPackage(
                            "mallory",
                            keyPackage.fingerprint(),
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
                                            vaultFile("recovered-wrong-user"),
                                            wrongUser,
                                            enrollment.kit(),
                                            enrollment.encryptedPrivateKey()));
            assertFalse(wrongUserFailure.toString().contains("mallory"));

            RecoveryVaultKeyPackage wrongKeyId =
                    new RecoveryVaultKeyPackage(
                            keyPackage.username(),
                            keyPackage.fingerprint(),
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
                                    vaultFile("recovered-wrong-key"),
                                    wrongKeyId,
                                    enrollment.kit(),
                                    enrollment.encryptedPrivateKey()));
        }
    }

    @Test
    void newlyWrappedPackagesUseVersion2Context() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        DefaultVaultService version2Target =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (DeviceKeyPair keyPair = new DefaultCryptoService().generateDeviceKeyPair();
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(vaultFile("v2-source")), masterPassword())) {
            byte[] publicKeyBytes = keyPair.publicKey();
            byte[] version2Context = null;
            try {
                RecoveryPublicKey publicKey =
                        new RecoveryPublicKey(
                                "v2-enrollment", 2L, keyPair.keyAlgorithm(), publicKeyBytes);
                RecoveryVaultKeyPackage keyPackage =
                        recovery.wrapVaultKey(source, publicKey, "alice");
                DeviceVaultKeyPackage devicePackage =
                        new DeviceVaultKeyPackage(
                                VaultFingerprint.fromHexString(keyPackage.fingerprint()),
                                keyPackage.vaultKeyId(),
                                keyPackage.keyAlgorithm(),
                                keyPackage.encryptedVaultKey());
                version2Context =
                        RecoveryContextCodec.version2(
                                keyPackage.username(),
                                keyPackage.fingerprint(),
                                keyPackage.enrollmentId(),
                                keyPackage.generation(),
                                keyPackage.vaultKeyId().value());
                byte[] finalVersion2Context = version2Context;
                keyPair.copyPrivateKey(
                        privateKey -> {
                            try (VaultHandle recovered =
                                    version2Target.provisionVault(
                                            vaultFile("v2-context-target"),
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
            }
        }
    }

    @Test
    void wrongKitAndTamperedPrivateEnvelopeCannotRecover() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        DefaultVaultService recoveredService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (RecoveryEnrollmentMaterial enrollment = recovery.enroll("enrollment-1", 1L);
                RecoveryEnrollmentMaterial other = recovery.enroll("enrollment-2", 1L);
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(vaultFile("source-wrong")),
                                masterPassword())) {
            RecoveryVaultKeyPackage keyPackage =
                    recovery.wrapVaultKey(source, enrollment.publicKey(), "alice");
            assertThrows(
                    CryptoException.class,
                    () ->
                            recovery.openVault(
                                    recoveredService,
                                    vaultFile("target-wrong"),
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
                                    vaultFile("target-wrong"),
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
    void openVaultRejectsGenerationMismatch() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        DefaultVaultService recoveredService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (RecoveryEnrollmentMaterial enrollment = recovery.enroll("enrollment-1", 1L);
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(vaultFile("id-source")), masterPassword())) {
            RecoveryVaultKeyPackage keyPackage =
                    recovery.wrapVaultKey(source, enrollment.publicKey(), "alice");
            RecoveryVaultKeyPackage wrongGeneration =
                    new RecoveryVaultKeyPackage(
                            keyPackage.username(),
                            keyPackage.fingerprint(),
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
                                    vaultFile("id-target"),
                                    wrongGeneration,
                                    enrollment.kit(),
                                    enrollment.encryptedPrivateKey()));
        }
    }

    @Test
    void openVaultRejectsMalformedPrivateKeyEnvelope() {
        RecoveryCryptoService recovery = new DefaultRecoveryCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        DefaultVaultService recoveredService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (RecoveryEnrollmentMaterial enrollment = recovery.enroll("enrollment-1", 1L);
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(vaultFile("env-source")),
                                masterPassword())) {
            RecoveryVaultKeyPackage keyPackage =
                    recovery.wrapVaultKey(source, enrollment.publicKey(), "alice");
            assertThrows(
                    CryptoException.class,
                    () ->
                            recovery.openVault(
                                    recoveredService,
                                    vaultFile("env-target"),
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
                                    vaultFile("env-target"),
                                    keyPackage,
                                    enrollment.kit(),
                                    wrongMagic));
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

    private static char[] masterPassword() {
        return "correct horse battery staple".toCharArray();
    }

    private static byte[] bytes(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
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
