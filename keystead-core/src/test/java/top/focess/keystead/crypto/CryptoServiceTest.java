package top.focess.keystead.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;

class CryptoServiceTest {

    private final DefaultCryptoService crypto = new DefaultCryptoService();

    @Test
    void encryptDecryptRoundTripReturnsPlaintext() {
        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] plaintext = new byte[] {1, 2, 3};
            byte[] aad = new byte[] {4, 5, 6};

            EncryptedEnvelope envelope =
                    crypto.encrypt(key, plaintext, aad, Instant.parse("2026-07-02T00:00:00Z"));
            byte[] opened = crypto.decrypt(key, envelope, aad);

            assertArrayEquals(plaintext, opened);
            assertFalse(Arrays.equals(plaintext, envelope.ciphertext()));
        }
    }

    @Test
    void decryptRejectsChangedAad() {
        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            EncryptedEnvelope envelope =
                    crypto.encrypt(
                            key,
                            new byte[] {1, 2, 3},
                            new byte[] {4, 5, 6},
                            Instant.parse("2026-07-02T00:00:00Z"));

            assertThrows(
                    CryptoException.class,
                    () -> crypto.decrypt(key, envelope, new byte[] {4, 5, 7}));
        }
    }

    @Test
    void encryptingSamePlaintextTwiceUsesDifferentNonceAndCiphertext() {
        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] plaintext = new byte[] {1, 2, 3};
            byte[] aad = new byte[] {4, 5, 6};

            EncryptedEnvelope first =
                    crypto.encrypt(key, plaintext, aad, Instant.parse("2026-07-02T00:00:00Z"));
            EncryptedEnvelope second =
                    crypto.encrypt(key, plaintext, aad, Instant.parse("2026-07-02T00:00:00Z"));

            assertFalse(Arrays.equals(first.nonce(), second.nonce()));
            assertFalse(Arrays.equals(first.ciphertext(), second.ciphertext()));
        }
    }

    @Test
    void decryptRejectsEnvelopeEncryptedUnderDifferentKeyId() {
        try (VaultKey encryptingKey = crypto.generateVaultKey(new KeyId("vault-key-a"));
                VaultKey wrongKey = crypto.generateVaultKey(new KeyId("vault-key-b"))) {
            EncryptedEnvelope envelope =
                    crypto.encrypt(
                            encryptingKey,
                            new byte[] {1, 2, 3},
                            new byte[] {4, 5, 6},
                            Instant.parse("2026-07-02T00:00:00Z"));

            CryptoException ex =
                    assertThrows(
                            CryptoException.class,
                            () -> crypto.decrypt(wrongKey, envelope, new byte[] {4, 5, 6}));

            assertNull(ex.getCause(), "wrong key id should be rejected before GCM is attempted");
            assertTrue(ex.getMessage().toLowerCase().contains("key id"));
        }
    }

    @Test
    void decryptRejectsUnapprovedEnvelopeAlgorithm() {
        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            EncryptedEnvelope envelope =
                    new EncryptedEnvelope(
                            1,
                            "AES-ECB",
                            key.keyId(),
                            new byte[12],
                            new byte[] {4, 5, 6},
                            new byte[] {1, 2, 3},
                            Instant.parse("2026-07-02T00:00:00Z"));

            CryptoException ex =
                    assertThrows(
                            CryptoException.class,
                            () -> crypto.decrypt(key, envelope, new byte[] {4, 5, 6}));

            assertNull(ex.getCause());
            assertTrue(ex.getMessage().toLowerCase().contains("unsupported"));
        }
    }

    @Test
    void wrongMasterPasswordCannotUnwrapVaultKey() {
        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] salt = crypto.randomSalt();
            byte[] wrapped =
                    crypto.wrapVaultKey(
                            key, new char[] {'c', 'o', 'r', 'r', 'e', 'c', 't'}, salt, 120_000);

            assertThrows(
                    CryptoException.class,
                    () ->
                            crypto.unwrapVaultKey(
                                    new KeyId("vault-key"),
                                    wrapped,
                                    new char[] {'w', 'r', 'o', 'n', 'g'},
                                    salt,
                                    120_000));
        }
    }

    @Test
    void approvedSha512KdfCanWrapAndUnwrapVaultKey() {
        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] salt = crypto.randomSalt();
            byte[] wrapped =
                    crypto.wrapVaultKey(
                            key,
                            new char[] {'c', 'o', 'r', 'r', 'e', 'c', 't'},
                            salt,
                            120_000,
                            CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA512);

            try (VaultKey opened =
                    crypto.unwrapVaultKey(
                            new KeyId("vault-key"),
                            wrapped,
                            new char[] {'c', 'o', 'r', 'r', 'e', 'c', 't'},
                            salt,
                            120_000,
                            CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA512)) {
                assertArrayEquals(rawKeyBytes(key), rawKeyBytes(opened));
            }
        }
    }

    @Test
    void closingVaultKeyWipesOwnedBytes() {
        VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"));

        key.close();

        assertTrue(key.isClosed());
        assertTrue(key.toString().contains("keyBytes=[REDACTED 32 bytes]"));
        assertTrue(key.toString().contains("closed=true"));
        assertArrayEquals(new byte[32], rawKeyBytes(key));
        assertThrows(
                SecretKeyDestroyedException.class,
                () -> key.copyBytes(bytes -> fail("closed key should not be readable")));
    }

    @Test
    void vaultKeyCloseWaitsForInFlightCallback() throws Exception {
        VaultKey key =
                new VaultKey(
                        new KeyId("vault-key"), new byte[] {1, 2, 3}, SecretMemoryProvider.heap());
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch closeStarted = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> access =
                    executor.submit(
                            () ->
                                    key.copyBytes(
                                            bytes -> {
                                                entered.countDown();
                                                await(release);
                                                assertArrayEquals(new byte[] {1, 2, 3}, bytes);
                                            }));
            assertTrue(entered.await(2, TimeUnit.SECONDS));

            Future<?> close =
                    executor.submit(
                            () -> {
                                closeStarted.countDown();
                                key.close();
                            });
            assertTrue(closeStarted.await(2, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> close.get(100, TimeUnit.MILLISECONDS));

            release.countDown();
            access.get(2, TimeUnit.SECONDS);
            close.get(2, TimeUnit.SECONDS);
            assertTrue(key.toString().contains("keyBytes=[REDACTED 3 bytes]"));
            assertTrue(key.toString().contains("closed=true"));
            assertThrows(
                    SecretKeyDestroyedException.class,
                    () -> key.copyBytes(bytes -> fail("closed key should not be readable")));
        } finally {
            release.countDown();
            key.close();
            executor.shutdownNow();
        }
    }

    @Test
    void devicePrivateKeyCloseWaitsForInFlightCallback() throws Exception {
        DeviceKeyPair keyPair =
                new DeviceKeyPair(
                        "test",
                        new byte[] {4, 5},
                        new byte[] {1, 2, 3},
                        SecretMemoryProvider.heap());
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch closeStarted = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> access =
                    executor.submit(
                            () ->
                                    keyPair.copyPrivateKey(
                                            bytes -> {
                                                entered.countDown();
                                                await(release);
                                                assertArrayEquals(new byte[] {1, 2, 3}, bytes);
                                            }));
            assertTrue(entered.await(2, TimeUnit.SECONDS));

            Future<?> close =
                    executor.submit(
                            () -> {
                                closeStarted.countDown();
                                keyPair.close();
                            });
            assertTrue(closeStarted.await(2, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> close.get(100, TimeUnit.MILLISECONDS));

            release.countDown();
            access.get(2, TimeUnit.SECONDS);
            close.get(2, TimeUnit.SECONDS);
            assertTrue(keyPair.toString().contains("privateKey=[REDACTED 3 bytes]"));
            assertTrue(keyPair.toString().contains("closed=true"));
            assertThrows(
                    SecretKeyDestroyedException.class,
                    () ->
                            keyPair.copyPrivateKey(
                                    bytes -> fail("closed private key should not be readable")));
        } finally {
            release.countDown();
            keyPair.close();
            executor.shutdownNow();
        }
    }

    @Test
    void injectedProviderOwnsEveryGeneratedAndUnwrappedPrivateKey() {
        AtomicInteger calls = new AtomicInteger();
        SecretMemoryProvider provider =
                value -> {
                    calls.incrementAndGet();
                    return SecretMemoryProvider.heap().protect(value);
                };
        DefaultCryptoService injected =
                new DefaultCryptoService(new SecureRandom(), new TinkAesGcmCipher(), provider);

        try (VaultKey original = injected.generateVaultKey(new KeyId("vault-key"));
                DeviceKeyPair device = injected.generateDeviceKeyPair()) {
            byte[] salt = injected.randomSalt();
            char[] password = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
            byte[] wrapped = injected.wrapVaultKey(original, password, salt, 10_000);
            try (VaultKey passwordOpened =
                    injected.unwrapVaultKey(original.keyId(), wrapped, password, salt, 10_000)) {
                byte[] context = new byte[] {9, 8, 7};
                byte[] deviceWrapped =
                        injected.wrapVaultKeyForDevice(original, device.publicKey(), context);
                AtomicReference<VaultKey> deviceOpened = new AtomicReference<>();
                device.copyPrivateKey(
                        privateKey ->
                                deviceOpened.set(
                                        injected.unwrapVaultKeyFromDevicePackage(
                                                original.keyId(),
                                                deviceWrapped,
                                                privateKey,
                                                context)));
                try (VaultKey ignored = deviceOpened.get()) {
                    assertEquals(4, calls.get());
                }
            } finally {
                Arrays.fill(password, '\0');
            }
        }
    }

    @Test
    void injectedProviderCopiesCallerOwnedVaultAndDeviceKeyInputs() {
        AtomicInteger calls = new AtomicInteger();
        SecretMemoryProvider provider =
                value -> {
                    calls.incrementAndGet();
                    return SecretMemoryProvider.heap().protect(value);
                };
        byte[] vaultInput = new byte[] {1, 2, 3};
        byte[] publicInput = new byte[] {4, 5};
        byte[] privateInput = new byte[] {6, 7, 8};

        try (VaultKey vaultKey = new VaultKey(new KeyId("vault-key"), vaultInput, provider);
                DeviceKeyPair device =
                        new DeviceKeyPair("test", publicInput, privateInput, provider)) {
            Arrays.fill(vaultInput, (byte) 0);
            Arrays.fill(publicInput, (byte) 0);
            Arrays.fill(privateInput, (byte) 0);

            assertEquals(2, calls.get());
            vaultKey.copyBytes(bytes -> assertArrayEquals(new byte[] {1, 2, 3}, bytes));
            assertArrayEquals(new byte[] {4, 5}, device.publicKey());
            device.copyPrivateKey(bytes -> assertArrayEquals(new byte[] {6, 7, 8}, bytes));
        }
    }

    private static byte[] rawKeyBytes(VaultKey key) {
        try {
            Field field = VaultKey.class.getDeclaredField("keyBytes");
            field.setAccessible(true);
            Object memory = field.get(key);
            Field bytesField = memory.getClass().getDeclaredField("bytes");
            bytesField.setAccessible(true);
            return ((byte[]) bytesField.get(memory)).clone();
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            assertTrue(latch.await(2, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }
}
