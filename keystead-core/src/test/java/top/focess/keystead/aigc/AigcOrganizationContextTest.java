package top.focess.keystead.aigc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretClassification;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SecretProfile;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.VaultId;

class AigcOrganizationContextTest {

    @Test
    void encryptedRecordContextUsesOnlyMetadataAndNeverPayloadBytes() {
        Instant createdAt = Instant.parse("2026-07-03T00:00:00Z");
        Instant updatedAt = Instant.parse("2026-07-03T00:01:00Z");
        SecretMetadata metadata =
                new SecretMetadata(
                        new SecretId(UUID.fromString("11111111-1111-1111-1111-111111111111")),
                        SecretType.API_TOKEN,
                        new SecretProfile(
                                "GitHub deployment token",
                                new SecretClassification(
                                        "development",
                                        "github",
                                        "github.com",
                                        "alice@example.com",
                                        Set.of("work")),
                                Set.of("deploy"),
                                Map.of("environment", "production")),
                        createdAt,
                        updatedAt,
                        7L);
        EncryptedSecretRecord record =
                new EncryptedSecretRecord(
                        new VaultId(UUID.fromString("22222222-2222-2222-2222-222222222222")),
                        metadata,
                        new EncryptedEnvelope(
                                1,
                                "AES-256-GCM",
                                new KeyId("vault-key"),
                                "nonce-sentinel".getBytes(StandardCharsets.UTF_8),
                                "aad-sentinel".getBytes(StandardCharsets.UTF_8),
                                "plain-password-sentinel".getBytes(StandardCharsets.UTF_8),
                                updatedAt),
                        7L);

        AigcOrganizationContext context = AigcOrganizationContext.from(record);

        assertEquals(SecretType.API_TOKEN, context.secretType());
        assertEquals("GitHub deployment token", context.title());
        assertEquals("development", context.classification().category());
        assertEquals(Set.of("deploy"), context.tags());
        assertEquals(Map.of("environment", "production"), context.attributes());

        String promptText = context.toPromptText();
        assertTrue(promptText.contains("GitHub deployment token"));
        assertTrue(promptText.contains("github.com"));
        assertTrue(promptText.contains("revision=7"));
        assertFalse(promptText.contains("plain-password-sentinel"));
        assertFalse(promptText.contains("nonce-sentinel"));
        assertFalse(promptText.contains("aad-sentinel"));
    }
}
