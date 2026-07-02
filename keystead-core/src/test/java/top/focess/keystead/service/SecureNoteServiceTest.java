package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.FileVaultStore;

class SecureNoteServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-02T00:00:00Z"), ZoneOffset.UTC);
    private static final VaultId VAULT_ID =
            new VaultId(UUID.fromString("20000000-0000-0000-0000-000000000001"));

    @TempDir Path tempDir;

    @Test
    void createSaveReopenAndReadSecureNote() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            secretId = saveNote(vault);
        }

        try (VaultHandle vault = service.openVault(VAULT_ID, master())) {
            vault.withSecureNote(
                    secretId,
                    view -> {
                        assertEquals("Recovery", view.metadata().title());
                        assertEquals(SecretType.SECURE_NOTE, view.metadata().type());
                        view.withBody(
                                chars ->
                                        assertArrayEquals(
                                                chars("very private recovery note"), chars));
                    });
        }
    }

    @Test
    void secureNoteViewIsInvalidAfterCallbackReturns() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        AtomicReference<SecureNoteView> captured = new AtomicReference<>();

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            SecretId secretId = saveNote(vault);
            vault.withSecureNote(secretId, captured::set);
        }

        assertThrows(SecretDestroyedException.class, () -> captured.get().withBody(chars -> {}));
    }

    @Test
    void saveSecureNoteRequiresTitleAndBody() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            assertThrows(
                    ValidationException.class,
                    () ->
                            vault.saveSecureNote(
                                    draft ->
                                            draft.body(
                                                    SecretBuffer.fromChars(
                                                            chars("very private recovery note")))));
            assertThrows(
                    ValidationException.class,
                    () -> vault.saveSecureNote(draft -> draft.title("Recovery")));
        }
    }

    @Test
    void persistedSecureNoteDoesNotContainPlaintextBody() throws IOException {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            secretId = saveNote(vault);
        }

        String file =
                Files.readString(
                        tempDir.resolve("secrets").resolve(secretId.value() + ".properties"));
        assertFalse(file.contains("very private recovery note"));
    }

    @Test
    void openingSecureNoteAsLoginIsRejected() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            SecretId secretId = saveNote(vault);

            assertThrows(ValidationException.class, () -> vault.withLogin(secretId, view -> {}));
        }
    }

    private static SecretId saveNote(VaultHandle vault) {
        try (SecretBuffer body = SecretBuffer.fromChars(chars("very private recovery note"))) {
            return vault.saveSecureNote(
                    draft -> draft.title("Recovery").tag("personal").body(body));
        }
    }

    private static char[] master() {
        return chars("correct horse battery staple");
    }

    private static char[] chars(String value) {
        return value.toCharArray();
    }
}
