package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretType;

class SecureNoteServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-02T00:00:00Z"), ZoneOffset.UTC);

    @TempDir Path tempDir;

    private Path vaultFile() {
        return tempDir.resolve("vault.kv");
    }

    @Test
    void createSaveReopenAndReadSecureNote() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
            secretId = saveNote(vault);
        }

        try (VaultHandle vault = service.openVault(vaultFile(), master())) {
            vault.withSecureNote(
                    secretId,
                    view -> {
                        assertEquals("Recovery", view.metadata().title());
                        assertEquals(SecretType.SECURE_NOTE, view.metadata().secretType());
                        view.withBody(
                                chars ->
                                        assertArrayEquals(
                                                chars("very private recovery note"), chars));
                    });
        }
    }

    @Test
    void secureNoteViewIsInvalidAfterCallbackReturns() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        AtomicReference<SecureNoteView> captured = new AtomicReference<>();

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
            SecretId secretId = saveNote(vault);
            vault.withSecureNote(secretId, captured::set);
        }

        assertThrows(SecretDestroyedException.class, () -> captured.get().withBody(chars -> {}));
    }

    @Test
    void saveSecureNoteRequiresTitleAndBody() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
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
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
            saveNote(vault);
        }

        byte[] bytes = Files.readAllBytes(vaultFile());
        assertFalse(
                new String(bytes, StandardCharsets.UTF_8).contains("very private recovery note"));
    }

    @Test
    void openingSecureNoteAsLoginIsRejected() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
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
