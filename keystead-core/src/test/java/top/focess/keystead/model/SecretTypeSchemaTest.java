package top.focess.keystead.model;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

class SecretTypeSchemaTest {

    @Test
    void loginPasswordSchemaDefinesExpectedFields() {
        SecretTypeSchema schema = SecretTypeSchema.forType(SecretType.LOGIN_PASSWORD);
        assertEquals(SecretType.LOGIN_PASSWORD, schema.type());
        assertEquals(List.of("username", "password", "url", "notes"), schema.fieldNames());
        assertTrue(schema.field("username").required());
        assertEquals(SecretFieldType.SECRET, schema.field("username").type());
        assertEquals(SecretFieldType.TEXT, schema.field("url").type());
        assertFalse(schema.field("url").required());
        assertTrue(schema.field("password").revealable());
    }

    @Test
    void sshKeySchemaMarksPrivateKeySecretAndRequired() {
        SecretTypeSchema schema = SecretTypeSchema.forType(SecretType.SSH_KEY);
        assertEquals(List.of("publicKey", "privateKey", "passphrase"), schema.fieldNames());
        assertEquals(SecretFieldType.TEXT, schema.field("publicKey").type());
        assertEquals(SecretFieldType.SECRET, schema.field("privateKey").type());
        assertTrue(schema.field("privateKey").required());
        assertFalse(schema.field("passphrase").required());
    }

    @Test
    void genericSecretAllowsCustomFieldsAndHasNoFixedFields() {
        SecretTypeSchema schema = SecretTypeSchema.forType(SecretType.GENERIC_SECRET);
        assertTrue(schema.allowsCustomFields());
        assertTrue(schema.fieldNames().isEmpty());
    }

    @Test
    void typedSecretsDoNotAllowCustomFields() {
        assertFalse(SecretTypeSchema.forType(SecretType.LOGIN_PASSWORD).allowsCustomFields());
        assertFalse(SecretTypeSchema.forType(SecretType.SSH_KEY).allowsCustomFields());
    }

    @Test
    void defaultsCoverEverySecretType() {
        List<SecretTypeSchema> defaults = SecretTypeSchema.defaults();
        assertEquals(SecretType.values().length, defaults.size());
        for (SecretType type : SecretType.values()) {
            assertNotNull(SecretTypeSchema.forType(type), "missing schema for " + type);
        }
    }

    @Test
    void fieldLookupReturnsNullForUnknownField() {
        SecretTypeSchema schema = SecretTypeSchema.forType(SecretType.LOGIN_PASSWORD);
        assertNull(schema.field("does-not-exist"));
    }
}
