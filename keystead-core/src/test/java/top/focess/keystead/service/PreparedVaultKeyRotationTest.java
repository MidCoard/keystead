package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretId;

class PreparedVaultKeyRotationTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-14T00:00:00Z"), ZoneOffset.UTC);
    private static final byte[] CONTEXT =
            "vault:vault-1:device:laptop-1".getBytes(StandardCharsets.UTF_8);

    @TempDir Path tempDir;

    private Path vaultFile(String name) {
        return tempDir.resolve(name + ".kv");
    }

    @Test
    void wrapsTargetBeforeJournalCommitAndCommitsThroughSelfPackage() {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source = service.createVault(vaultFile("commit"), masterPassword())) {
            SecretId secretId = saveLogin(source);
            KeyId sourceKeyId = source.vaultKeyId();

            try (PreparedVaultKeyRotation rotation = source.prepareVaultKeyRotation()) {
                assertEquals(source.vaultFingerprint(), rotation.vaultFingerprint());
                assertEquals(sourceKeyId, rotation.sourceVaultKeyId());
                assertNotEquals(sourceKeyId, rotation.targetVaultKeyId());
                assertFalse(rotation.isCommitted());
                assertThrows(
                        IllegalStateException.class,
                        () -> source.deleteSecret(new SecretId(UUID.randomUUID())));

                DeviceVaultKeyPackage selfPackage =
                        rotation.wrapVaultKeyPackageForDevice(device.publicKey(), CONTEXT);
                assertEquals(rotation.targetVaultKeyId(), selfPackage.vaultKeyId());
                assertFalse(
                        rotation.toString()
                                .contains(
                                        Base64.getEncoder()
                                                .encodeToString(selfPackage.encryptedVaultKey())));

                try (VaultHandle rotated = rotation.commitWithDevicePackage(selfPackage)) {
                    assertTrue(rotation.isCommitted());
                    assertTrue(source.isClosed());
                    assertEquals(rotation.targetVaultKeyId(), rotated.vaultKeyId());
                    assertPassword(rotated, secretId);
                }
            }

            try (VaultHandle reopened =
                    service.openVaultWithDeviceKey(
                            vaultFile("commit"), privateKeyBytes(device), CONTEXT)) {
                assertPassword(reopened, secretId);
            }
        }
    }

    @Test
    void closingWithoutCommitPreservesOldVaultAndReleasesSourceHandle() {
        DefaultVaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle source = service.createVault(vaultFile("abort"), masterPassword())) {
            KeyId sourceKeyId = source.vaultKeyId();
            try (PreparedVaultKeyRotation ignored = source.prepareVaultKeyRotation()) {
                assertThrows(
                        IllegalStateException.class,
                        () -> source.deleteSecret(new SecretId(UUID.randomUUID())));
            }

            source.deleteSecret(new SecretId(UUID.randomUUID()));
            assertEquals(sourceKeyId, source.vaultKeyId());
        }

        try (VaultHandle reopened = service.openVault(vaultFile("abort"), masterPassword())) {
            assertNotNull(reopened.vaultKeyId());
        }
    }

    @Test
    void rejectsPackageThatWasNotProducedByThisPreparation() {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source = service.createVault(vaultFile("mismatch"), masterPassword());
                PreparedVaultKeyRotation rotation = source.prepareVaultKeyRotation()) {
            DeviceVaultKeyPackage generated =
                    rotation.wrapVaultKeyPackageForDevice(device.publicKey(), CONTEXT);
            byte[] tampered = generated.encryptedVaultKey();
            tampered[tampered.length - 1] ^= 1;
            DeviceVaultKeyPackage substituted =
                    new DeviceVaultKeyPackage(
                            generated.fingerprint(),
                            generated.vaultKeyId(),
                            generated.keyAlgorithm(),
                            tampered);

            assertThrows(
                    ValidationException.class, () -> rotation.commitWithDevicePackage(substituted));
            assertFalse(rotation.isCommitted());
        }

        try (VaultHandle reopened = service.openVault(vaultFile("mismatch"), masterPassword())) {
            assertNotNull(reopened.vaultKeyId());
        }
    }

    @Test
    void resumesFromExactStagedSelfPackageAfterTargetKeyWasDestroyed() {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        DeviceVaultKeyPackage staged;
        SecretId secretId;
        try (DeviceKeyPair device = crypto.generateDeviceKeyPair()) {
            try (VaultHandle source = service.createVault(vaultFile("resume"), masterPassword())) {
                secretId = saveLogin(source);
                try (PreparedVaultKeyRotation rotation = source.prepareVaultKeyRotation()) {
                    staged = rotation.wrapVaultKeyPackageForDevice(device.publicKey(), CONTEXT);
                }
            }

            try (VaultHandle source = service.openVault(vaultFile("resume"), masterPassword());
                    PreparedVaultKeyRotation resumed =
                            source.resumeVaultKeyRotation(
                                    staged, privateKeyBytes(device), CONTEXT);
                    VaultHandle rotated = resumed.commitWithDevicePackage(staged)) {
                assertEquals(staged.vaultKeyId(), resumed.targetVaultKeyId());
                assertTrue(resumed.isCommitted());
                assertPassword(rotated, secretId);
            }

            try (VaultHandle reopened =
                    service.openVaultWithDeviceKey(
                            vaultFile("resume"), privateKeyBytes(device), CONTEXT)) {
                assertPassword(reopened, secretId);
            }
        }
    }

    @Test
    void resumeRejectsWrongDeviceContextWithoutChangingOldVault() {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source =
                        service.createVault(vaultFile("wrong-context"), masterPassword())) {
            DeviceVaultKeyPackage staged;
            try (PreparedVaultKeyRotation rotation = source.prepareVaultKeyRotation()) {
                staged = rotation.wrapVaultKeyPackageForDevice(device.publicKey(), CONTEXT);
            }

            byte[] wrongContext = "wrong-context".getBytes(StandardCharsets.UTF_8);
            assertThrows(
                    RuntimeException.class,
                    () ->
                            source.resumeVaultKeyRotation(
                                    staged, privateKeyBytes(device), wrongContext));
            assertNotNull(source.vaultKeyId());
        }
    }

    private static SecretId saveLogin(VaultHandle vault) {
        try (SecretBuffer username = SecretBuffer.fromChars("alice@example.com".toCharArray());
                SecretBuffer password = SecretBuffer.fromChars("secret-password".toCharArray())) {
            return vault.saveLogin(
                    draft ->
                            draft.title("GitHub")
                                    .username(username)
                                    .password(password)
                                    .url("https://github.com"));
        }
    }

    private static void assertPassword(VaultHandle vault, SecretId secretId) {
        vault.withLogin(
                secretId,
                view ->
                        view.withPassword(
                                password ->
                                        assertArrayEquals(
                                                "secret-password".toCharArray(), password)));
    }

    private static char[] masterPassword() {
        return "correct horse battery staple".toCharArray();
    }

    private static byte[] privateKeyBytes(DeviceKeyPair device) {
        final byte[][] output = new byte[1][];
        device.copyPrivateKey(bytes -> output[0] = bytes.clone());
        return output[0];
    }
}
