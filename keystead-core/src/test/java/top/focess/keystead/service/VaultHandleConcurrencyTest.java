package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.DeletedSecretRecord;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.VaultHeader;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.FileVaultStore;
import top.focess.keystead.store.VaultKeyRotation;
import top.focess.keystead.store.VaultMutation;
import top.focess.keystead.store.VaultStore;

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
        DefaultCryptoService crypto = new DefaultCryptoService();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch callbackEntered = new CountDownLatch(1);
        CountDownLatch releaseCallback = new CountDownLatch(1);
        CountDownLatch rotationAttempted = new CountDownLatch(1);
        AtomicReference<Thread> rotationWorker = new AtomicReference<>();

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source =
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
                                executor.submit(
                                        () -> {
                                            rotationWorker.set(Thread.currentThread());
                                            rotationAttempted.countDown();
                                            return source.prepareVaultKeyRotation();
                                        });
                        assertTrue(rotationAttempted.await(2, TimeUnit.SECONDS));
                        awaitBlockedOrDone(rotation, rotationWorker.get());
                        releaseCallback.countDown();
                        SecretId saved = save.get(2, TimeUnit.SECONDS);
                        try (PreparedVaultKeyRotation prepared = rotation.get(2, TimeUnit.SECONDS);
                                VaultHandle rotated = commitPrepared(prepared, device)) {
                            assertPassword(rotated, saved, "concurrent-password");
                        }
                    });
        } finally {
            releaseCallback.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void closeWaitsForPreparedCommitToFinishLifecycleTransition() {
        BlockingRotationVaultStore store =
                new BlockingRotationVaultStore(new FileVaultStore(tempDir.resolve("commit-close")));
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService service = new DefaultVaultService(store, CLOCK);
        ExecutorService executor = Executors.newFixedThreadPool(2);

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source =
                        service.createVault(new CreateVaultRequest(VAULT_ID), masterPassword())) {
            SecretId secretId = saveLogin(source, "commit-close-password");
            try (PreparedVaultKeyRotation prepared = source.prepareVaultKeyRotation()) {
                DeviceVaultKeyPackage keyPackage =
                        prepared.wrapVaultKeyPackageForDevice(device.publicKey(), CONTEXT);
                assertTimeoutPreemptively(
                        Duration.ofSeconds(20),
                        () -> {
                            Future<VaultHandle> commit =
                                    executor.submit(
                                            () -> prepared.commitWithDevicePackage(keyPackage));
                            assertTrue(store.commitEntered.await(5, TimeUnit.SECONDS));

                            CountDownLatch closeAttempted = new CountDownLatch(1);
                            AtomicReference<Thread> closeWorker = new AtomicReference<>();
                            Future<?> close =
                                    executor.submit(
                                            () -> {
                                                closeWorker.set(Thread.currentThread());
                                                closeAttempted.countDown();
                                                source.close();
                                            });
                            assertTrue(closeAttempted.await(2, TimeUnit.SECONDS));
                            awaitBlockedOrDone(close, closeWorker.get());
                            assertFalse(
                                    close.isDone(),
                                    "source.close() completed while durable commit was paused");

                            store.releaseCommit.countDown();
                            try (VaultHandle rotated = commit.get(5, TimeUnit.SECONDS)) {
                                close.get(5, TimeUnit.SECONDS);
                                assertTrue(source.isClosed());
                                assertPassword(rotated, secretId, "commit-close-password");
                            }
                        });
            }
        } finally {
            store.releaseCommit.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void preparedWrapWaitsForParentLifecycleMonitor() {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService service =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("wrap-close")), CLOCK);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source =
                        service.createVault(new CreateVaultRequest(VAULT_ID), masterPassword());
                PreparedVaultKeyRotation prepared = source.prepareVaultKeyRotation()) {
            assertTimeoutPreemptively(
                    Duration.ofSeconds(5),
                    () -> {
                        CountDownLatch wrapAttempted = new CountDownLatch(1);
                        AtomicReference<Thread> wrapWorker = new AtomicReference<>();
                        Future<DeviceVaultKeyPackage> wrap;
                        synchronized (source) {
                            wrap =
                                    executor.submit(
                                            () -> {
                                                wrapWorker.set(Thread.currentThread());
                                                wrapAttempted.countDown();
                                                return prepared.wrapVaultKeyPackageForDevice(
                                                        device.publicKey(), CONTEXT);
                                            });
                            assertTrue(wrapAttempted.await(2, TimeUnit.SECONDS));
                            awaitBlockedOrDone(wrap, wrapWorker.get());
                            assertFalse(
                                    wrap.isDone(),
                                    "prepared wrap bypassed the parent lifecycle monitor");
                        }
                        assertTrue(
                                prepared.targetVaultKeyId()
                                        .equals(wrap.get(2, TimeUnit.SECONDS).vaultKeyId()));
                    });
        } finally {
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

    private static SecretId saveLogin(VaultHandle source, String passwordText) {
        try (SecretBuffer password = SecretBuffer.fromChars(passwordText.toCharArray())) {
            return source.saveLogin(
                    draft -> draft.title("Lifecycle commit login").password(password));
        }
    }

    private static VaultHandle commitPrepared(
            PreparedVaultKeyRotation prepared, DeviceKeyPair device) {
        DeviceVaultKeyPackage keyPackage =
                prepared.wrapVaultKeyPackageForDevice(device.publicKey(), CONTEXT);
        return prepared.commitWithDevicePackage(keyPackage);
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

    private static void awaitBlockedOrDone(Future<?> future, Thread worker) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (!future.isDone() && worker.getState() != Thread.State.BLOCKED) {
            if (System.nanoTime() >= deadline) {
                throw new AssertionError("Worker neither completed nor blocked within timeout");
            }
            Thread.onSpinWait();
        }
    }

    private static char[] masterPassword() {
        return "correct horse battery staple".toCharArray();
    }

    private static final class BlockingRotationVaultStore implements VaultStore {

        private final VaultStore delegate;
        private final CountDownLatch commitEntered = new CountDownLatch(1);
        private final CountDownLatch releaseCommit = new CountDownLatch(1);

        private BlockingRotationVaultStore(VaultStore delegate) {
            this.delegate = delegate;
        }

        @Override
        public void saveVaultHeader(@NonNull VaultHeader header) {
            delegate.saveVaultHeader(header);
        }

        @Override
        public @NonNull Optional<VaultHeader> loadVaultHeader(@NonNull VaultId vaultId) {
            return delegate.loadVaultHeader(vaultId);
        }

        @Override
        public long nextRevision(@NonNull VaultId vaultId) {
            return delegate.nextRevision(vaultId);
        }

        @Override
        public void recordRevision(@NonNull VaultId vaultId, long revision) {
            delegate.recordRevision(vaultId, revision);
        }

        @Override
        public void commitMutation(@NonNull VaultId vaultId, @NonNull VaultMutation mutation) {
            delegate.commitMutation(vaultId, mutation);
        }

        @Override
        public void commitVaultKeyRotation(@NonNull VaultKeyRotation rotation) {
            commitEntered.countDown();
            await(releaseCommit);
            delegate.commitVaultKeyRotation(rotation);
        }

        @Override
        public void saveSecretRecord(@NonNull EncryptedSecretRecord record) {
            delegate.saveSecretRecord(record);
        }

        @Override
        public @NonNull Optional<EncryptedSecretRecord> loadSecretRecord(
                @NonNull VaultId vaultId, @NonNull SecretId secretId) {
            return delegate.loadSecretRecord(vaultId, secretId);
        }

        @Override
        public void deleteSecretRecord(@NonNull VaultId vaultId, @NonNull SecretId secretId) {
            delegate.deleteSecretRecord(vaultId, secretId);
        }

        @Override
        public void saveDeletedSecretRecord(@NonNull DeletedSecretRecord record) {
            delegate.saveDeletedSecretRecord(record);
        }

        @Override
        public @NonNull Optional<DeletedSecretRecord> loadDeletedSecretRecord(
                @NonNull VaultId vaultId, @NonNull SecretId secretId) {
            return delegate.loadDeletedSecretRecord(vaultId, secretId);
        }

        @Override
        public void deleteDeletedSecretRecord(
                @NonNull VaultId vaultId, @NonNull SecretId secretId) {
            delegate.deleteDeletedSecretRecord(vaultId, secretId);
        }

        @Override
        public @NonNull List<SecretMetadata> listMetadata(@NonNull VaultId vaultId) {
            return delegate.listMetadata(vaultId);
        }

        @Override
        public @NonNull List<EncryptedSecretRecord> listSecretRecords(@NonNull VaultId vaultId) {
            return delegate.listSecretRecords(vaultId);
        }

        @Override
        public @NonNull List<DeletedSecretRecord> listDeletedSecretRecords(
                @NonNull VaultId vaultId) {
            return delegate.listDeletedSecretRecords(vaultId);
        }
    }
}
