package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.FileVaultStore;

class VaultHandleConcurrencyTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-14T00:00:00Z"), ZoneOffset.UTC);
    private static final VaultId VAULT_ID =
            new VaultId(UUID.fromString("50000000-0000-0000-0000-000000000001"));
    private static final byte[] CONTEXT =
            "vault:concurrent:device:local".getBytes(StandardCharsets.UTF_8);

    @TempDir Path tempDir;

    @Test
    void mutationThatStartsBeforeRotationIsIncludedInRotatedVault() {
        DefaultVaultService service =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("rotation")), CLOCK);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch callbackEntered = new CountDownLatch(1);
        CountDownLatch releaseCallback = new CountDownLatch(1);

        try (VaultHandle source =
                service.createVault(new CreateVaultRequest(VAULT_ID), masterPassword())) {
            assertTimeoutPreemptively(
                    Duration.ofSeconds(5),
                    () -> {
                        Future<SecretId> save =
                                executor.submit(
                                        () ->
                                                saveBlockedLogin(
                                                        source, callbackEntered, releaseCallback));
                        assertTrue(callbackEntered.await(2, TimeUnit.SECONDS));
                        Future<PreparedVaultKeyRotation> rotation =
                                executor.submit(source::prepareVaultKeyRotation);
                        releaseCallback.countDown();
                        SecretId saved = save.get(2, TimeUnit.SECONDS);
                        try (PreparedVaultKeyRotation prepared = rotation.get(2, TimeUnit.SECONDS);
                                VaultHandle rotated = commitPrepared(prepared)) {
                            assertPassword(rotated, saved, "concurrent-password");
                        }
                    });
        } finally {
            releaseCallback.countDown();
            executor.shutdownNow();
        }
    }

    private static SecretId saveBlockedLogin(
            VaultHandle source, CountDownLatch callbackEntered, CountDownLatch releaseCallback) {
        try (SecretBuffer password = SecretBuffer.fromChars("concurrent-password".toCharArray())) {
            return source.saveLogin(
                    draft -> {
                        draft.title("Concurrent login").password(password);
                        callbackEntered.countDown();
                        await(releaseCallback);
                    });
        }
    }

    private static VaultHandle commitPrepared(PreparedVaultKeyRotation prepared) {
        DefaultCryptoService crypto = new DefaultCryptoService();
        try (DeviceKeyPair device = crypto.generateDeviceKeyPair()) {
            DeviceVaultKeyPackage keyPackage =
                    prepared.wrapVaultKeyPackageForDevice(device.publicKey(), CONTEXT);
            return prepared.commitWithDevicePackage(keyPackage);
        }
    }

    private static void assertPassword(
            VaultHandle vault, SecretId secretId, String expectedPassword) {
        vault.withLogin(
                secretId,
                view ->
                        view.withPassword(
                                password ->
                                        assertArrayEquals(
                                                expectedPassword.toCharArray(), password)));
    }

    private static void await(CountDownLatch latch) {
        try {
            assertTrue(latch.await(2, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for test latch", e);
        }
    }

    private static char[] masterPassword() {
        return "correct horse battery staple".toCharArray();
    }
}
