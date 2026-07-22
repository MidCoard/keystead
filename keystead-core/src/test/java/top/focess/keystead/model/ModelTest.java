package top.focess.keystead.model;

import static org.junit.jupiter.api.Assertions.*;
import static top.focess.keystead.model.SecurityLimits.MAX_ENVELOPE_AAD_BYTES;
import static top.focess.keystead.model.SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES;
import static top.focess.keystead.model.SecurityLimits.MAX_KDF_SALT_BYTES;
import static top.focess.keystead.model.SecurityLimits.MAX_WRAPPED_KEY_PACKAGE_BYTES;

import java.time.Instant;
import java.util.Map;
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
        SecretClassification classification =
                new SecretClassification(
                        "development", "github", "github.com", "alice@example.com", Set.of("work"));
        SecretMetadata metadata =
                new SecretMetadata(
                        new SecretId(UUID.randomUUID()),
                        SecretType.LOGIN_PASSWORD,
                        new SecretProfile(
                                "GitHub", classification, tags, Map.of("project", "keystead")),
                        Instant.parse("2026-07-02T00:00:00Z"),
                        Instant.parse("2026-07-02T00:01:00Z"),
                        1L);

        assertEquals("GitHub", metadata.profile().title());
        assertEquals(Map.of("project", "keystead"), metadata.profile().attributes());
        assertEquals(classification, metadata.classification());
        assertEquals(tags, metadata.tags());
        assertThrows(UnsupportedOperationException.class, () -> metadata.tags().add("new"));
        assertThrows(
                NullPointerException.class,
                () ->
                        new SecretMetadata(
                                metadata.id(),
                                null,
                                metadata.title(),
                                metadata.classification(),
                                metadata.tags(),
                                metadata.createdAt(),
                                metadata.updatedAt(),
                                metadata.revision()));
    }

    @Test
    void metadataRejectsUpdatedTimeBeforeCreatedTime() {
        Instant createdAt = Instant.parse("2026-07-02T00:01:00Z");
        Instant updatedAt = Instant.parse("2026-07-02T00:00:00Z");

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new SecretMetadata(
                                new SecretId(UUID.randomUUID()),
                                SecretType.LOGIN_PASSWORD,
                                "GitHub",
                                Set.of("work"),
                                createdAt,
                                updatedAt,
                                1L));
    }

    @Test
    void metadataRejectsZeroRevisionBecauseCommittedRowsStartAtOne() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new SecretMetadata(
                                new SecretId(UUID.randomUUID()),
                                SecretType.LOGIN_PASSWORD,
                                "GitHub",
                                Set.of("work"),
                                Instant.parse("2026-07-02T00:00:00Z"),
                                Instant.parse("2026-07-02T00:01:00Z"),
                                0L));
    }

    @Test
    void encryptedRecordRejectsRevisionDifferentFromMetadataRevision() {
        SecretMetadata metadata =
                new SecretMetadata(
                        new SecretId(UUID.randomUUID()),
                        SecretType.API_TOKEN,
                        "GitHub token",
                        Set.of("work"),
                        Instant.parse("2026-07-02T00:00:00Z"),
                        Instant.parse("2026-07-02T00:01:00Z"),
                        4L);
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        1,
                        "AES-256-GCM",
                        new KeyId("vault-key"),
                        new byte[] {1, 2, 3},
                        new byte[] {4, 5, 6},
                        new byte[] {7, 8, 9},
                        Instant.parse("2026-07-02T00:01:00Z"));

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSecretRecord(
                                new VaultId(UUID.randomUUID()), metadata, envelope, 5L));
    }

    @Test
    void deletedRecordRejectsZeroRevisionBecauseCommittedRowsStartAtOne() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new DeletedSecretRecord(
                                new VaultId(UUID.randomUUID()),
                                new SecretId(UUID.randomUUID()),
                                SecretType.API_TOKEN,
                                0L,
                                Instant.parse("2026-07-02T00:01:00Z")));
    }

    @Test
    void classificationNormalizesBlankFieldsAndCopiesLabels() {
        SecretClassification classification =
                new SecretClassification(
                        " development ",
                        " github ",
                        " github.com ",
                        " alice@example.com ",
                        Set.of(" work ", ""));

        assertEquals("development", classification.category());
        assertEquals("github", classification.provider());
        assertEquals("github.com", classification.software());
        assertEquals("alice@example.com", classification.account());
        assertEquals(Set.of("work"), classification.labels());
        assertThrows(UnsupportedOperationException.class, () -> classification.labels().add("new"));
        assertEquals(
                SecretClassification.none(), new SecretClassification(" ", null, "", "", Set.of()));
    }

    @Test
    void classificationCanonicalizesTaxonomyFieldsButPreservesAccountCase() {
        SecretClassification classification =
                new SecretClassification(
                        " Development ",
                        " GitHub ",
                        " GitHub.COM ",
                        " Alice@Example.COM ",
                        Set.of(" Work ", "work", " Personal "));

        assertEquals("development", classification.category());
        assertEquals("github", classification.provider());
        assertEquals("github.com", classification.software());
        assertEquals("Alice@Example.COM", classification.account());
        assertEquals(Set.of("work", "personal"), classification.labels());
    }

    @Test
    void taxonomyFactoriesCreateCommonClassifications() {
        SecretClassification development =
                SecretTaxonomy.development(
                        SecretTaxonomy.PROVIDER_GITHUB,
                        SecretTaxonomy.SOFTWARE_GITHUB,
                        "alice@example.com");
        SecretClassification communication =
                SecretTaxonomy.communication(
                        SecretTaxonomy.PROVIDER_WECHAT, SecretTaxonomy.SOFTWARE_WECHAT, "alice");

        assertEquals("development", development.category());
        assertEquals("github", development.provider());
        assertEquals("github.com", development.software());
        assertEquals("communication", communication.category());
        assertEquals("wechat", communication.provider());
        assertEquals("wechat", communication.software());
    }

    @Test
    void taxonomyPresetsCoverCommonDevelopmentAndCommunicationSecrets() {
        assertEquals(
                new SecretClassification(
                        "development", "github", "github.com", "alice@example.com"),
                SecretTaxonomy.githubDevelopment("alice@example.com"));
        assertEquals(
                new SecretClassification("development", "ssh", "openssh", "workstation"),
                SecretTaxonomy.sshDevelopment("workstation"));
        assertEquals(
                new SecretClassification("development", "gpg", "gpg", "alice@example.com"),
                SecretTaxonomy.gpgDevelopment("alice@example.com"));
        assertEquals(
                new SecretClassification("communication", "google", "google", "alice"),
                SecretTaxonomy.googleCommunication("alice"));
        assertEquals(
                new SecretClassification("communication", "wechat", "wechat", "alice"),
                SecretTaxonomy.wechatCommunication("alice"));
    }

    @Test
    void taxonomySuggestionsUseOnlySecretTypeTitleAndAccountMetadata() {
        assertEquals(
                SecretTaxonomy.githubDevelopment("alice@example.com"),
                SecretTaxonomy.suggest(
                        SecretType.API_TOKEN, " GitHub deployment token ", "alice@example.com"));
        assertEquals(
                SecretTaxonomy.sshDevelopment("workstation"),
                SecretTaxonomy.suggest(SecretType.SSH_KEY, "workstation key", "workstation"));
        assertEquals(
                SecretTaxonomy.gpgDevelopment("Alice@Example.COM"),
                SecretTaxonomy.suggest(
                        SecretType.GPG_KEY, "primary signing key", "Alice@Example.COM"));
        assertEquals(
                new SecretClassification(
                        "communication", "google", "google-authenticator", "alice"),
                SecretTaxonomy.suggest(SecretType.MFA_SECRET, "Google Authenticator", "alice"));
        assertEquals(
                SecretTaxonomy.wechatCommunication("alice"),
                SecretTaxonomy.suggest(SecretType.LOGIN_PASSWORD, "WeChat password", "alice"));
        assertEquals(
                SecretClassification.none(),
                SecretTaxonomy.suggest(SecretType.GENERIC_SECRET, "misc", null));
    }

    @Test
    void profileOwnsTitleClassificationTagsAndAttributes() {
        SecretProfile profile =
                new SecretProfile(
                        " GitHub main ",
                        new SecretClassification(
                                "development",
                                "github",
                                "github.com",
                                "alice@example.com",
                                Set.of("work")),
                        Set.of(" code ", ""),
                        Map.of(" environment ", " production ", "", "ignored", "blank", " "));

        assertEquals("GitHub main", profile.title());
        assertEquals("development", profile.classification().category());
        assertEquals(Set.of("code"), profile.tags());
        assertEquals(Map.of("environment", "production"), profile.attributes());
        assertThrows(UnsupportedOperationException.class, () -> profile.tags().add("new"));
        assertThrows(UnsupportedOperationException.class, () -> profile.attributes().put("x", "y"));
    }

    @Test
    void secretTypesCoverDeveloperAndAuthenticationMaterials() {
        assertNotNull(SecretType.valueOf("SSH_KEY"));
        assertNotNull(SecretType.valueOf("API_TOKEN"));
        assertNotNull(SecretType.valueOf("GPG_KEY"));
        assertNotNull(SecretType.valueOf("MFA_SECRET"));
        assertNotNull(SecretType.valueOf("CERTIFICATE"));
        assertNotNull(SecretType.valueOf("GENERIC_SECRET"));
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
    void encryptedEnvelopeAcceptsExactResourceLimits() {
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        1,
                        "AES-256-GCM",
                        new KeyId("vault-key"),
                        new byte[12],
                        new byte[MAX_ENVELOPE_AAD_BYTES],
                        new byte[MAX_ENVELOPE_CIPHERTEXT_BYTES],
                        Instant.parse("2026-07-02T00:00:00Z"));

        assertEquals(MAX_ENVELOPE_AAD_BYTES, envelope.aad().length);
        assertEquals(MAX_ENVELOPE_CIPHERTEXT_BYTES, envelope.ciphertext().length);
    }

    @Test
    void encryptedEnvelopeRejectsInputsOverResourceLimits() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedEnvelope(
                                1,
                                "AES-256-GCM",
                                new KeyId("vault-key"),
                                new byte[12],
                                new byte[MAX_ENVELOPE_AAD_BYTES + 1],
                                new byte[1],
                                Instant.parse("2026-07-02T00:00:00Z")));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedEnvelope(
                                1,
                                "AES-256-GCM",
                                new KeyId("vault-key"),
                                new byte[12],
                                new byte[1],
                                new byte[MAX_ENVELOPE_CIPHERTEXT_BYTES + 1],
                                Instant.parse("2026-07-02T00:00:00Z")));
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

    @Test
    void vaultHeaderRejectsUpdatedTimeBeforeCreatedTime() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new VaultHeader(
                                new VaultId(UUID.randomUUID()),
                                1,
                                "PBKDF2WithHmacSHA256",
                                new byte[] {1, 2},
                                120_000,
                                new KeyId("vault-key"),
                                new byte[] {3, 4},
                                Instant.parse("2026-07-02T00:01:00Z"),
                                Instant.parse("2026-07-02T00:00:00Z")));
    }

    @Test
    void vaultHeaderAcceptsExactSaltAndWrappedKeyLimits() {
        VaultHeader header =
                new VaultHeader(
                        new VaultId(UUID.randomUUID()),
                        1,
                        "PBKDF2WithHmacSHA256",
                        new byte[MAX_KDF_SALT_BYTES],
                        120_000,
                        new KeyId("vault-key"),
                        new byte[MAX_WRAPPED_KEY_PACKAGE_BYTES],
                        Instant.parse("2026-07-02T00:00:00Z"),
                        Instant.parse("2026-07-02T00:01:00Z"));

        assertEquals(MAX_KDF_SALT_BYTES, header.kdfSalt().length);
        assertEquals(MAX_WRAPPED_KEY_PACKAGE_BYTES, header.wrappedVaultKey().length);
    }

    @Test
    void vaultHeaderRejectsSaltAndWrappedKeyOverResourceLimits() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new VaultHeader(
                                new VaultId(UUID.randomUUID()),
                                1,
                                "PBKDF2WithHmacSHA256",
                                new byte[MAX_KDF_SALT_BYTES + 1],
                                120_000,
                                new KeyId("vault-key"),
                                new byte[1],
                                Instant.parse("2026-07-02T00:00:00Z"),
                                Instant.parse("2026-07-02T00:01:00Z")));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new VaultHeader(
                                new VaultId(UUID.randomUUID()),
                                1,
                                "PBKDF2WithHmacSHA256",
                                new byte[1],
                                120_000,
                                new KeyId("vault-key"),
                                new byte[MAX_WRAPPED_KEY_PACKAGE_BYTES + 1],
                                Instant.parse("2026-07-02T00:00:00Z"),
                                Instant.parse("2026-07-02T00:01:00Z")));
    }

    @Test
    void encryptedEnvelopeRejectsNonPositiveVersion() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedEnvelope(
                                0,
                                "AES-256-GCM",
                                new KeyId("vault-key"),
                                new byte[12],
                                new byte[1],
                                new byte[1],
                                Instant.parse("2026-07-02T00:00:00Z")));
    }

    @Test
    void vaultHeaderRejectsNonPositiveFormatVersion() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new VaultHeader(
                                new VaultId(UUID.randomUUID()),
                                0,
                                "PBKDF2WithHmacSHA256",
                                new byte[] {1, 2},
                                120_000,
                                new KeyId("vault-key"),
                                new byte[] {3, 4},
                                Instant.parse("2026-07-02T00:00:00Z"),
                                Instant.parse("2026-07-02T00:01:00Z")));
    }
}
