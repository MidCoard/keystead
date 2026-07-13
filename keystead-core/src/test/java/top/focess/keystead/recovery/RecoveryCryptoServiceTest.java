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
import top.focess.keystead.model.VaultId;
import top.focess.keystead.service.CreateVaultRequest;
import top.focess.keystead.service.DefaultVaultService;
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
            assertThrows(
                    CryptoException.class,
                    () ->
                            recovery.openVault(
                                    recoveredService,
                                    VAULT_ID,
                                    wrongUser,
                                    enrollment.kit(),
                                    enrollment.encryptedPrivateKey()));
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

    private static char[] masterPassword() {
        return "correct horse battery staple".toCharArray();
    }

    private static byte[] bytes(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }
}
