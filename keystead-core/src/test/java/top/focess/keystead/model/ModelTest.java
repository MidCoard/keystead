package top.focess.keystead.model;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ModelTest {

    @Test
    void identifiersRejectNullValues() {
        assertThrows(NullPointerException.class, () -> new VaultId(null));
        assertThrows(NullPointerException.class, () -> new SecretId(null));
        assertThrows(NullPointerException.class, () -> new KeyId(null));
    }

    @Test
    void metadataRejectsNullValuesAndCopiesTags() {
        Set<String> tags = Set.of("work", "github");
        SecretMetadata metadata =
                new SecretMetadata(
                        new SecretId(UUID.randomUUID()),
                        SecretType.LOGIN_PASSWORD,
                        "GitHub",
                        tags,
                        Instant.parse("2026-07-02T00:00:00Z"),
                        Instant.parse("2026-07-02T00:01:00Z"),
                        1L);

        assertEquals(tags, metadata.tags());
        assertThrows(UnsupportedOperationException.class, () -> metadata.tags().add("new"));
        assertThrows(
                NullPointerException.class,
                () ->
                        new SecretMetadata(
                                metadata.id(),
                                null,
                                metadata.title(),
                                metadata.tags(),
                                metadata.createdAt(),
                                metadata.updatedAt(),
                                metadata.revision()));
    }

    @Test
    void encryptedEnvelopeCopiesArraysAndRedactsToString() {
        byte[] nonce = new byte[] {1, 2, 3};
        byte[] aad = new byte[] {4, 5, 6};
        byte[] ciphertext = new byte[] {7, 8, 9};
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        1,
                        "AES-256-GCM",
                        new KeyId("vault-key"),
                        nonce,
                        aad,
                        ciphertext,
                        Instant.parse("2026-07-02T00:00:00Z"));

        nonce[0] = 99;
        aad[0] = 99;
        ciphertext[0] = 99;

        assertArrayEquals(new byte[] {1, 2, 3}, envelope.nonce());
        assertArrayEquals(new byte[] {4, 5, 6}, envelope.aad());
        assertArrayEquals(new byte[] {7, 8, 9}, envelope.ciphertext());
        assertFalse(envelope.toString().contains("[7, 8, 9]"));
        assertTrue(envelope.toString().contains("ciphertext=[REDACTED"));
    }

    @Test
    void vaultHeaderRedactsWrappedVaultKey() {
        VaultHeader header =
                new VaultHeader(
                        new VaultId(UUID.randomUUID()),
                        1,
                        "PBKDF2WithHmacSHA256",
                        new byte[] {1, 2},
                        120_000,
                        new KeyId("vault-key"),
                        new byte[] {3, 4},
                        Instant.parse("2026-07-02T00:00:00Z"),
                        Instant.parse("2026-07-02T00:01:00Z"));

        assertTrue(header.toString().contains("wrappedVaultKey=[REDACTED"));
        assertFalse(header.toString().contains("3, 4"));
    }
}
