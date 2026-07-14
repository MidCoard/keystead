package top.focess.keystead.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.model.KeyId;

class KdfProviderTest {

    @Test
    void selectsTheExplicitlyRegisteredProviderWithCanonicalParameters() {
        AtomicInteger calls = new AtomicInteger();
        AtomicReference<KdfParameters> recorded = new AtomicReference<>();
        PasswordKeyDerivation provider =
                new PasswordKeyDerivation() {
                    @Override
                    public @NonNull String algorithm() {
                        return "TEST-KDF";
                    }

                    @Override
                    public byte @NonNull [] derive(
                            char @NonNull [] password,
                            @NonNull KdfParameters parameters,
                            int outputBytes) {
                        calls.incrementAndGet();
                        recorded.set(parameters);
                        assertArrayEquals(new char[] {'s', 'e', 'c', 'r', 'e', 't'}, password);
                        assertEquals(32, outputBytes);
                        byte[] result = new byte[outputBytes];
                        Arrays.fill(result, (byte) 7);
                        return result;
                    }
                };
        DefaultCryptoService crypto = service(List.of(provider));
        KdfParameters parameters =
                new KdfParameters(
                        "TEST-KDF", new byte[] {1, 2, 3}, Map.of("memoryKiB", 64, "iterations", 3));

        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] wrapped =
                    crypto.wrapVaultKey(key, new char[] {'s', 'e', 'c', 'r', 'e', 't'}, parameters);
            assertEquals(1, calls.get());
            assertEquals(parameters, recorded.get());

            try (VaultKey ignored =
                    crypto.unwrapVaultKey(
                            key.keyId(),
                            wrapped,
                            new char[] {'s', 'e', 'c', 'r', 'e', 't'},
                            parameters)) {
                assertEquals(2, calls.get());
                assertEquals(parameters, recorded.get());
            }
        }
    }

    @Test
    void unknownAlgorithmFailsClosedWithoutCallingAnyProvider() {
        AtomicInteger calls = new AtomicInteger();
        PasswordKeyDerivation provider = recordingProvider("PBKDF2WithHmacSHA256", calls);
        DefaultCryptoService crypto = service(List.of(provider));
        KdfParameters unknown =
                new KdfParameters("UNKNOWN-KDF", new byte[] {1}, Map.of("iterations", 1));

        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            assertFalse(crypto.supportsPasswordKdf("UNKNOWN-KDF"));
            assertThrows(
                    CryptoException.class,
                    () -> crypto.wrapVaultKey(key, new char[] {'x'}, unknown));
            assertEquals(0, calls.get());
        }
    }

    @Test
    void rejectsDuplicateProviderAlgorithms() {
        PasswordKeyDerivation first = recordingProvider("TEST-KDF", new AtomicInteger());
        PasswordKeyDerivation second = recordingProvider("TEST-KDF", new AtomicInteger());

        assertThrows(IllegalArgumentException.class, () -> service(List.of(first, second)));
    }

    @Test
    void defaultRegistrySupportsBothLegacyPbkdf2Algorithms() {
        DefaultCryptoService crypto = new DefaultCryptoService();

        assertTrue(crypto.supportsPasswordKdf(CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA256));
        assertTrue(crypto.supportsPasswordKdf(CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA512));
    }

    @Test
    void pbkdf2RejectsExcessiveIterationsAndUnknownParametersBeforeDerivation() {
        Pbkdf2KeyDerivation provider =
                new Pbkdf2KeyDerivation(CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA256);

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        provider.derive(
                                new char[] {'x'},
                                KdfParameters.pbkdf2(provider.algorithm(), new byte[0], 10_000_001),
                                32));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        provider.derive(
                                new char[] {'x'},
                                new KdfParameters(
                                        provider.algorithm(),
                                        new byte[0],
                                        Map.of("iterations", 1, "memoryKiB", 64)),
                                32));
    }

    @Test
    void pbkdf2ConstructorFailureLeavesCallerPasswordIntact() {
        Pbkdf2KeyDerivation provider =
                new Pbkdf2KeyDerivation(CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA256);
        char[] password = new char[] {'s', 'e', 'c', 'r', 'e', 't'};

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        provider.derive(
                                password,
                                KdfParameters.pbkdf2(provider.algorithm(), new byte[0], 1),
                                32));
        assertArrayEquals(new char[] {'s', 'e', 'c', 'r', 'e', 't'}, password);
    }

    @Test
    void wrapWipesDerivedKeyWhenRandomFails() {
        AtomicReference<byte[]> derived = new AtomicReference<>();
        PasswordKeyDerivation provider = keyRecordingProvider("TEST-KDF", derived);
        SecureRandom throwingRandom =
                new SecureRandom() {
                    @Override
                    public void nextBytes(byte @NonNull [] bytes) {
                        throw new TestFailure();
                    }
                };
        DefaultCryptoService crypto =
                new DefaultCryptoService(
                        throwingRandom,
                        new TinkAesGcmCipher(),
                        SecretMemoryProvider.heap(),
                        List.of(provider));
        KdfParameters parameters =
                new KdfParameters("TEST-KDF", new byte[] {1}, Map.of("iterations", 1));

        try (VaultKey key =
                new VaultKey(new KeyId("vault-key"), new byte[32], SecretMemoryProvider.heap())) {
            assertThrows(
                    TestFailure.class,
                    () -> crypto.wrapVaultKey(key, new char[] {'x'}, parameters));
        }
        assertArrayEquals(new byte[32], derived.get());
    }

    @Test
    void unwrapWipesDerivedKeyWhenNonceCopyFails() {
        AtomicReference<byte[]> derived = new AtomicReference<>();
        PasswordKeyDerivation provider = keyRecordingProvider("TEST-KDF", derived);
        AeadCipher invalidNonceCipher =
                new AeadCipher() {
                    @Override
                    public @NonNull String algorithm() {
                        return DefaultCryptoService.PAYLOAD_ALGORITHM;
                    }

                    @Override
                    public int nonceSizeBytes() {
                        return -1;
                    }

                    @Override
                    public byte @NonNull [] encrypt(
                            byte @NonNull [] keyBytes,
                            byte @NonNull [] nonce,
                            byte @NonNull [] plaintext,
                            byte @NonNull [] aad) {
                        throw new AssertionError("not called");
                    }

                    @Override
                    public byte @NonNull [] decrypt(
                            byte @NonNull [] keyBytes,
                            byte @NonNull [] nonce,
                            byte @NonNull [] ciphertext,
                            byte @NonNull [] aad) {
                        throw new AssertionError("not called");
                    }
                };
        DefaultCryptoService crypto =
                new DefaultCryptoService(
                        new SecureRandom(),
                        invalidNonceCipher,
                        SecretMemoryProvider.heap(),
                        List.of(provider));
        KdfParameters parameters =
                new KdfParameters("TEST-KDF", new byte[] {1}, Map.of("iterations", 1));

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        crypto.unwrapVaultKey(
                                new KeyId("vault-key"),
                                new byte[] {1},
                                new char[] {'x'},
                                parameters));
        assertArrayEquals(new byte[32], derived.get());
    }

    @Test
    void kdfParametersAreCanonicalImmutableAndBounded() {
        byte[] salt = new byte[] {1, 2};
        java.util.LinkedHashMap<String, Integer> values = new java.util.LinkedHashMap<>();
        values.put("memoryKiB", 64);
        values.put("iterations", 3);
        KdfParameters parameters = new KdfParameters("TEST-KDF", salt, values);
        salt[0] = 9;
        values.clear();

        assertArrayEquals(new byte[] {1, 2}, parameters.salt());
        assertEquals(
                List.of("iterations", "memoryKiB"),
                parameters.parameters().keySet().stream().toList());
        assertEquals(3, parameters.required("iterations"));
        assertThrows(
                UnsupportedOperationException.class, () -> parameters.parameters().put("x", 1));
        byte[] returnedSalt = parameters.salt();
        returnedSalt[0] = 8;
        assertArrayEquals(new byte[] {1, 2}, parameters.salt());

        assertThrows(
                IllegalArgumentException.class,
                () -> new KdfParameters("", new byte[] {1}, Map.of("x", 1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> new KdfParameters("TEST", new byte[65], Map.of("x", 1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> new KdfParameters("TEST", new byte[0], Map.of("", 1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> new KdfParameters("TEST", new byte[0], Map.of("non-ascii-\u00e9", 1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> new KdfParameters("TEST", new byte[0], Map.of("x".repeat(65), 1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> new KdfParameters("TEST", new byte[0], Map.of("x", 0)));
        java.util.Map<String, Integer> tooMany = new java.util.HashMap<>();
        for (int index = 0; index < 17; index++) {
            tooMany.put("p" + index, 1);
        }
        assertThrows(
                IllegalArgumentException.class,
                () -> new KdfParameters("TEST", new byte[0], tooMany));
        assertThrows(IllegalArgumentException.class, () -> parameters.required("missing"));
    }

    private static @NonNull PasswordKeyDerivation recordingProvider(
            @NonNull String algorithm, @NonNull AtomicInteger calls) {
        return new PasswordKeyDerivation() {
            @Override
            public @NonNull String algorithm() {
                return algorithm;
            }

            @Override
            public byte @NonNull [] derive(
                    char @NonNull [] password, @NonNull KdfParameters parameters, int outputBytes) {
                calls.incrementAndGet();
                return new byte[outputBytes];
            }
        };
    }

    private static @NonNull PasswordKeyDerivation keyRecordingProvider(
            @NonNull String algorithm, @NonNull AtomicReference<byte[]> derived) {
        return new PasswordKeyDerivation() {
            @Override
            public @NonNull String algorithm() {
                return algorithm;
            }

            @Override
            public byte @NonNull [] derive(
                    char @NonNull [] password, @NonNull KdfParameters parameters, int outputBytes) {
                byte[] result = new byte[outputBytes];
                Arrays.fill(result, (byte) 7);
                derived.set(result);
                return result;
            }
        };
    }

    private static @NonNull DefaultCryptoService service(
            @NonNull List<PasswordKeyDerivation> providers) {
        return new DefaultCryptoService(
                new SecureRandom(), new TinkAesGcmCipher(), SecretMemoryProvider.heap(), providers);
    }

    private static final class TestFailure extends RuntimeException {}
}
