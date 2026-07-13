package top.focess.keystead.model;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

class SecretTypeSchemaTest {

    @Test
    void fieldSchemaCarriesImportExportAndLengthContract() {
        SecretFieldSchema field =
                new SecretFieldSchema(
                        " privateKey ",
                        SecretFieldType.SECRET,
                        true,
                        true,
                        List.of("private_key", "key"),
                        "privateKey",
                        8192);

        assertEquals("privateKey", field.name());
        assertEquals(List.of("private_key", "key"), field.importAliases());
        assertEquals("privateKey", field.exportName());
        assertEquals(8192, field.maxLength());
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new SecretFieldSchema(
                                "x", SecretFieldType.TEXT, false, false, List.of(" "), "x", null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new SecretFieldSchema("x", SecretFieldType.TEXT, false, false, List.of(), "x", 0));
    }

    @Test
    void loginPasswordSchemaDefinesExpectedFields() {
        SecretTypeSchema schema = SecretTypeSchema.forType(SecretType.LOGIN_PASSWORD);
        assertEquals(SecretType.LOGIN_PASSWORD, schema.type());
        assertEquals(List.of("username", "password", "url", "notes"), schema.fieldNames());
        assertEquals(List.of("username", "password"), schema.requiredFieldNames());
        assertEquals(List.of("url", "notes"), schema.optionalFieldNames());
        assertEquals(List.of("username", "password", "notes"), schema.secretFieldNames());
        assertEquals(List.of("url"), schema.publicFieldNames());
        assertEquals(
                List.of("username", "password", "url", "notes"), schema.revealableFieldNames());
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
        assertEquals(SecretFieldType.SECRET, schema.customFieldType());
        assertTrue(schema.customFieldsRevealable());
        assertTrue(schema.fieldNames().isEmpty());
        assertTrue(schema.requiredFieldNames().isEmpty());
        assertTrue(schema.optionalFieldNames().isEmpty());
        assertTrue(schema.secretFieldNames().isEmpty());
        assertTrue(schema.publicFieldNames().isEmpty());
        assertTrue(schema.revealableFieldNames().isEmpty());
    }

    @Test
    void typedSecretsDoNotAllowCustomFields() {
        SecretTypeSchema loginSchema = SecretTypeSchema.forType(SecretType.LOGIN_PASSWORD);
        SecretTypeSchema sshKeySchema = SecretTypeSchema.forType(SecretType.SSH_KEY);

        assertFalse(loginSchema.allowsCustomFields());
        assertNull(loginSchema.customFieldType());
        assertFalse(loginSchema.customFieldsRevealable());
        assertFalse(sshKeySchema.allowsCustomFields());
        assertNull(sshKeySchema.customFieldType());
        assertFalse(sshKeySchema.customFieldsRevealable());
    }

    @Test
    void schemaRejectsContradictoryCustomFieldPolicy() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new SecretTypeSchema(SecretType.GENERIC_SECRET, List.of(), true, null, true));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new SecretTypeSchema(
                                SecretType.LOGIN_PASSWORD,
                                List.of(),
                                false,
                                SecretFieldType.SECRET,
                                false));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new SecretTypeSchema(
                                SecretType.LOGIN_PASSWORD, List.of(), false, null, true));
    }

    @Test
    void schemaRejectsDuplicateFieldNames() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new SecretTypeSchema(
                                SecretType.API_TOKEN,
                                List.of(
                                        new SecretFieldSchema(
                                                "token", SecretFieldType.SECRET, true, true),
                                        new SecretFieldSchema(
                                                "token", SecretFieldType.TEXT, false, false)),
                                false));
    }

    @Test
    void schemaFieldNamesAreTrimmedBeforeLookupAndDuplicateChecks() {
        SecretFieldSchema field =
                new SecretFieldSchema(" token ", SecretFieldType.SECRET, true, true);
        SecretTypeSchema schema = new SecretTypeSchema(SecretType.API_TOKEN, List.of(field), false);

        assertEquals("token", field.name());
        assertEquals(List.of("token"), schema.fieldNames());
        assertNotNull(schema.field("token"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new SecretTypeSchema(
                                SecretType.API_TOKEN,
                                List.of(
                                        new SecretFieldSchema(
                                                "token", SecretFieldType.SECRET, true, true),
                                        new SecretFieldSchema(
                                                " token ", SecretFieldType.TEXT, false, false)),
                                false));
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
