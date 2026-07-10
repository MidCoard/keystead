package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import org.junit.jupiter.api.Test;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.SecretTypeSchema;

class SecretTypeSchemaValidatorTest {

    @Test
    void acceptsAllRequiredFieldsPresent() {
        SecretTypeSchema schema = SecretTypeSchema.forType(SecretType.SSH_KEY);
        SecretTypeSchemaValidator.validate(schema, Set.of("publicKey", "privateKey", "passphrase"));
        SecretTypeSchemaValidator.validate(schema, Set.of("publicKey", "privateKey"));
    }

    @Test
    void rejectsMissingRequiredField() {
        SecretTypeSchema schema = SecretTypeSchema.forType(SecretType.SSH_KEY);
        assertThrows(
                ValidationException.class,
                () -> SecretTypeSchemaValidator.validate(schema, Set.of("publicKey")));
    }

    @Test
    void rejectsUnknownFieldForTypedSecret() {
        SecretTypeSchema schema = SecretTypeSchema.forType(SecretType.SSH_KEY);
        assertThrows(
                ValidationException.class,
                () ->
                        SecretTypeSchemaValidator.validate(
                                schema, Set.of("publicKey", "privateKey", "bogus")));
    }

    @Test
    void acceptsCustomFieldsForGenericSecret() {
        SecretTypeSchema schema = SecretTypeSchema.forType(SecretType.GENERIC_SECRET);
        SecretTypeSchemaValidator.validate(schema, Set.of("anything", "whatever"));
        SecretTypeSchemaValidator.validate(schema, Set.of());
    }

    @Test
    void rejectsBlankCustomFieldNames() {
        SecretTypeSchema schema = SecretTypeSchema.forType(SecretType.GENERIC_SECRET);

        assertThrows(
                ValidationException.class,
                () -> SecretTypeSchemaValidator.validate(schema, Set.of(" ")));
    }

    @Test
    void rejectsBlankRequiredFieldEvenWhenSetNameMatches() {
        SecretTypeSchema schema = SecretTypeSchema.forType(SecretType.LOGIN_PASSWORD);
        assertThrows(
                ValidationException.class,
                () -> SecretTypeSchemaValidator.validate(schema, Set.of("username", "url")));
    }
}
