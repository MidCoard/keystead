package top.focess.keystead.store;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.crypto.TinkAesGcmCipher;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.KeySlot;
import top.focess.keystead.model.SlotType;
import top.focess.keystead.model.VaultFingerprint;
import top.focess.keystead.model.VaultHeader;

class VaultFileFormatTest {

    private static final String KDF_ALGORITHM = DefaultCryptoService.KDF_ALGORITHM;
    private static final int ITERATIONS = 1000;

    private final DefaultCryptoService crypto =
            new DefaultCryptoService(
                    new SecureRandom(), new TinkAesGcmCipher(), SecretMemoryProvider.heap());

    private record WrittenVault(byte[] file, byte[] wrapped, VaultHeader header) {}

    @Test
    void roundTripPreservesBodyHeaderAndFingerprint() {
        char[] passphrase = "correct horse battery staple".toCharArray();
        byte[] salt = crypto.randomSalt();
        KeyId keyId = new KeyId("vault-key");
        byte[] body =
                "the quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);
        Instant createdAt = Instant.parse("2026-07-02T00:00:00Z");
        Instant updatedAt = Instant.parse("2026-07-03T00:00:00Z");

        WrittenVault written =
                writeVault(passphrase, salt, keyId, body, createdAt, updatedAt, keyId);
        VaultFileFormat.OpenedFile opened =
                VaultFileFormat.open(crypto, written.file(), passphrase);
        try (VaultKey ignored = opened.vaultKey()) {
            assertArrayEquals(body, opened.containerBody());
            assertEquals(VaultFileFormat.FORMAT_VERSION, opened.header().formatVersion());
            assertEquals(keyId, opened.header().vaultKeyId());
            assertEquals(
                    KdfParameters.pbkdf2(KDF_ALGORITHM, salt, ITERATIONS),
                    opened.header().firstPassphraseSlot().orElseThrow().kdfParameters());
            assertEquals(createdAt, opened.header().createdAt());
            assertEquals(updatedAt, opened.header().updatedAt());
            VaultFingerprint expected =
                    crypto.deriveFingerprint(
                            passphrase,
                            opened.header().firstPassphraseSlot().orElseThrow().kdfParameters());
            assertEquals(expected, opened.fingerprint());
        }
    }

    @Test
    void openRejectsWrongPassphrase() {
        char[] passphrase = "correct horse battery staple".toCharArray();
        byte[] body = "secret body".getBytes(StandardCharsets.UTF_8);
        WrittenVault written = writeDefaultVault(passphrase, body);

        char[] wrong = "wrong passphrase".toCharArray();
        assertThrows(
                CryptoException.class, () -> VaultFileFormat.open(crypto, written.file(), wrong));
    }

    @Test
    void openRejectsTamperedCiphertext() {
        char[] passphrase = "correct horse battery staple".toCharArray();
        byte[] body = "secret body with enough length".getBytes(StandardCharsets.UTF_8);
        WrittenVault written = writeDefaultVault(passphrase, body);

        byte[] tampered = written.file().clone();
        // The envelope ends with ciphertext then a 12-byte encryptedAt, so the byte just before
        // that trailer is the last ciphertext byte; flipping it breaks the AEAD tag.
        tampered[tampered.length - 13] ^= 0x01;
        assertThrows(
                CryptoException.class, () -> VaultFileFormat.open(crypto, tampered, passphrase));
    }

    @Test
    void openRejectsTamperedHeaderTimestamp() {
        char[] passphrase = "correct horse battery staple".toCharArray();
        byte[] body = "secret body".getBytes(StandardCharsets.UTF_8);
        byte[] salt = crypto.randomSalt();
        KeyId keyId = new KeyId("vault-key");
        WrittenVault written =
                writeVault(
                        passphrase,
                        salt,
                        keyId,
                        body,
                        Instant.parse("2026-07-02T00:00:00Z"),
                        Instant.parse("2026-07-03T00:00:00Z"),
                        keyId);

        int headerEnd =
                headerEndOffset(KDF_ALGORITHM, salt, keyId.value(), written.wrapped().length);
        byte[] tampered = written.file().clone();
        // Flip the last byte of the header (the last byte of updatedAt). The header is the
        // container
        // AAD, so the AEAD tag no longer verifies: unwrap still succeeds, decrypt fails.
        tampered[headerEnd - 1] ^= 0x01;
        assertThrows(
                CryptoException.class, () -> VaultFileFormat.open(crypto, tampered, passphrase));
    }

    @Test
    void openRejectsBadMagic() {
        byte[] notVault = "not a keystead vault file".getBytes(StandardCharsets.UTF_8);
        assertThrows(
                StoreException.class,
                () -> VaultFileFormat.open(crypto, notVault, "any".toCharArray()));
    }

    @Test
    void openRejectsUnsupportedVersion() {
        char[] passphrase = "correct horse battery staple".toCharArray();
        WrittenVault written =
                writeDefaultVault(passphrase, "body".getBytes(StandardCharsets.UTF_8));

        byte[] tampered = written.file().clone();
        tampered[VaultFileFormat.MAGIC.length] = 99;
        assertThrows(
                StoreException.class, () -> VaultFileFormat.open(crypto, tampered, passphrase));
    }

    @Test
    void openRejectsTruncatedFile() {
        char[] passphrase = "correct horse battery staple".toCharArray();
        WrittenVault written =
                writeDefaultVault(passphrase, "body".getBytes(StandardCharsets.UTF_8));

        byte[] truncated = Arrays.copyOf(written.file(), 4);
        assertThrows(
                StoreException.class, () -> VaultFileFormat.open(crypto, truncated, passphrase));
    }

    @Test
    void fingerprintIsStableAcrossVaultKeyRotation() {
        char[] passphrase = "passphrase".toCharArray();
        byte[] salt = crypto.randomSalt();
        KdfParameters kdf = KdfParameters.pbkdf2(KDF_ALGORITHM, salt, ITERATIONS);

        VaultFingerprint first;
        try (VaultKey firstKey = crypto.generateVaultKey(new KeyId("k1"))) {
            crypto.wrapVaultKey(firstKey, passphrase, salt, ITERATIONS);
            first = crypto.deriveFingerprint(passphrase, kdf);
        }
        // A rotation rewraps a different data-encryption key under the same passphrase+salt, so the
        // wrapping key (and therefore the fingerprint) is unchanged.
        try (VaultKey secondKey = crypto.generateVaultKey(new KeyId("k2"))) {
            crypto.wrapVaultKey(secondKey, passphrase, salt, ITERATIONS);
            VaultFingerprint rotated = crypto.deriveFingerprint(passphrase, kdf);
            assertEquals(first, rotated);
        }
    }

    @Test
    void fingerprintChangesWithSalt() {
        char[] passphrase = "passphrase".toCharArray();
        byte[] salt1 = new byte[16];
        byte[] salt2 = new byte[16];
        salt2[0] = 1;

        VaultFingerprint first =
                crypto.deriveFingerprint(
                        passphrase, KdfParameters.pbkdf2(KDF_ALGORITHM, salt1, ITERATIONS));
        VaultFingerprint second =
                crypto.deriveFingerprint(
                        passphrase, KdfParameters.pbkdf2(KDF_ALGORITHM, salt2, ITERATIONS));
        assertNotEquals(first, second);
    }

    private WrittenVault writeDefaultVault(char[] passphrase, byte[] body) {
        byte[] salt = crypto.randomSalt();
        KeyId keyId = new KeyId("vault-key");
        return writeVault(
                passphrase,
                salt,
                keyId,
                body,
                Instant.parse("2026-07-02T00:00:00Z"),
                Instant.parse("2026-07-03T00:00:00Z"),
                keyId);
    }

    private WrittenVault writeVault(
            char[] passphrase,
            byte[] salt,
            KeyId encryptingKeyId,
            byte[] body,
            Instant createdAt,
            Instant updatedAt,
            KeyId headerKeyId) {
        KdfParameters kdf = KdfParameters.pbkdf2(KDF_ALGORITHM, salt, ITERATIONS);
        try (VaultKey vaultKey = crypto.generateVaultKey(encryptingKeyId)) {
            byte[] wrapped = crypto.wrapVaultKey(vaultKey, passphrase, salt, ITERATIONS);
            VaultFingerprint fingerprint = crypto.deriveFingerprint(passphrase, kdf);
            KeySlot slot = new KeySlot(SlotType.PASSPHRASE, new KeyId("passphrase"), kdf, wrapped);
            VaultHeader header =
                    new VaultHeader(
                            VaultFileFormat.FORMAT_VERSION,
                            fingerprint,
                            headerKeyId,
                            List.of(slot),
                            createdAt,
                            updatedAt);
            byte[] file = VaultFileFormat.write(crypto, header, vaultKey, body, Instant.now());
            return new WrittenVault(file, wrapped, header);
        }
    }

    /** Computes the byte offset where the v2 header ends (start of the envelope). */
    private static int headerEndOffset(
            String kdfAlgorithm, byte[] salt, String vaultKeyId, int wrappedVaultKeyLength) {
        int algoBytes = kdfAlgorithm.getBytes(StandardCharsets.UTF_8).length;
        int keyIdBytes = vaultKeyId.getBytes(StandardCharsets.UTF_8).length;
        int slotKeyIdBytes = "passphrase".getBytes(StandardCharsets.UTF_8).length;
        int paramNameBytes = KdfParameters.ITERATIONS.getBytes(StandardCharsets.UTF_8).length;
        return VaultFileFormat.MAGIC.length
                + 1 // version
                + VaultFingerprint.BYTES // fingerprint
                + 2 // vault key id length
                + keyIdBytes
                + 2 // slot count
                + 1 // slot type
                + 2 // slot key id length
                + slotKeyIdBytes
                + 2 // kdf algorithm length
                + algoBytes
                + 2 // kdf salt length
                + salt.length
                + 2 // kdf parameter count (single "iterations" entry)
                + 2 // parameter name length
                + paramNameBytes
                + 4 // parameter value
                + 4 // wrapped key length
                + wrappedVaultKeyLength
                + 12 // createdAt
                + 12; // updatedAt
    }
}
