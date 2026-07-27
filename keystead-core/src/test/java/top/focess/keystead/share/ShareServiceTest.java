package top.focess.keystead.share;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.TinkAesGcmCipher;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.SecurityLimits;
import top.focess.keystead.service.ValidationException;

class ShareServiceTest {

    private static final Instant NOW = Instant.parse("2026-07-25T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String STRONG_PASSPHRASE = "CorrectHorse42!";

    private final DefaultCryptoService crypto =
            new DefaultCryptoService(
                    new SecureRandom(), new TinkAesGcmCipher(), SecretMemoryProvider.heap());
    private final ShareService share = new ShareService(crypto, CLOCK);

    private static char[] passphrase() {
        return STRONG_PASSPHRASE.toCharArray();
    }

    private static ShareDraft loginDraft() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("url", "https://example.com");
        fields.put("username", "alice");
        fields.put("password", "s3cret-pw");
        fields.put("notes", "personal account");
        return new ShareDraft(SecretType.LOGIN_PASSWORD, "Alice login", fields);
    }

    @Test
    void roundTripsLoginPasswordShare() {
        String encoded = share.create(loginDraft(), passphrase());

        assertTrue(encoded.startsWith("keystead-share:v1:"));
        ShareContents contents = share.open(encoded, passphrase());

        assertEquals(SecretType.LOGIN_PASSWORD, contents.secretType());
        assertEquals("Alice login", contents.title());
        assertEquals(4, contents.fields().size());
        assertEquals("https://example.com", contents.fields().get("url"));
        assertEquals("alice", contents.fields().get("username"));
        assertEquals("s3cret-pw", contents.fields().get("password"));
        assertEquals("personal account", contents.fields().get("notes"));
        assertEquals(NOW, contents.createdAt());
        assertNull(contents.expiresAt());
        assertNull(contents.sharerNote());
        assertFalse(contents.shareId().isBlank());
    }

    @Test
    void roundTripsEverySecretType() {
        for (SecretType type : SecretType.values()) {
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("field-a", "value-a");
            fields.put("field-b", "value-b");
            ShareDraft draft = new ShareDraft(type, type.name() + " share", fields);

            String encoded = share.create(draft, passphrase());
            ShareContents contents = share.open(encoded, passphrase());

            assertEquals(type, contents.secretType());
            assertEquals("value-a", contents.fields().get("field-a"));
            assertEquals("value-b", contents.fields().get("field-b"));
        }
    }

    @Test
    void roundTripsNoteAndExpiry() {
        Instant expires = NOW.plusSeconds(3600);
        ShareDraft draft =
                new ShareDraft(
                        SecretType.SECURE_NOTE,
                        "note",
                        Map.of("body", "the note body"),
                        "from bob",
                        expires,
                        0);

        String encoded = share.create(draft, passphrase());
        ShareContents contents = share.open(encoded, passphrase());

        assertEquals("from bob", contents.sharerNote());
        assertEquals(expires, contents.expiresAt());
        assertEquals("the note body", contents.fields().get("body"));
    }

    @Test
    void emptyFieldsRoundTrip() {
        ShareDraft draft = new ShareDraft(SecretType.GENERIC_SECRET, "empty", Map.of());
        String encoded = share.create(draft, passphrase());
        ShareContents contents = share.open(encoded, passphrase());
        assertTrue(contents.fields().isEmpty());
    }

    @Test
    void fieldsAreSortedByNameOnTheWire() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("zebra", "z");
        fields.put("alpha", "a");
        fields.put("mike", "m");
        ShareDraft draft = new ShareDraft(SecretType.GENERIC_SECRET, "sorted", fields);

        String encoded = share.create(draft, passphrase());
        ShareContents contents = share.open(encoded, passphrase());

        // TreeMap ensures deterministic ordering regardless of insertion order.
        assertEquals("a", contents.fields().get("alpha"));
        assertEquals("m", contents.fields().get("mike"));
        assertEquals("z", contents.fields().get("zebra"));
    }

    @Test
    void wrongPassphraseFailsWithCryptoException() {
        String encoded = share.create(loginDraft(), passphrase());

        assertThrows(
                CryptoException.class,
                () -> share.open(encoded, "WrongPassphrase99!".toCharArray()));
    }

    @Test
    void expiredShareIsRejectedOnOpen() {
        Instant pastExpiry = NOW.minusSeconds(60);
        ShareDraft draft =
                new ShareDraft(
                        SecretType.GENERIC_SECRET,
                        "expired",
                        Map.of("k", "v"),
                        null,
                        pastExpiry,
                        0);

        String encoded = share.create(draft, passphrase());
        ValidationException ex =
                assertThrows(ValidationException.class, () -> share.open(encoded, passphrase()));
        assertTrue(ex.getMessage().toLowerCase().contains("expired"));
    }

    @Test
    void notYetExpiredShareOpens() {
        Instant futureExpiry = NOW.plusSeconds(60);
        ShareDraft draft =
                new ShareDraft(
                        SecretType.GENERIC_SECRET,
                        "valid",
                        Map.of("k", "v"),
                        null,
                        futureExpiry,
                        0);

        String encoded = share.create(draft, passphrase());
        ShareContents contents = share.open(encoded, passphrase());
        assertEquals(futureExpiry, contents.expiresAt());
    }

    @Test
    void tooWeakPassphraseRejectedAtCreateAndWiped() {
        char[] weak = "short1".toCharArray();
        int length = weak.length;
        ValidationException ex =
                assertThrows(ValidationException.class, () -> share.create(loginDraft(), weak));
        assertTrue(ex.getMessage().toLowerCase().contains("passphrase"));
        assertArrayEquals(new char[length], weak);
    }

    @Test
    void passphraseIsWipedAfterCreate() {
        char[] pass = passphrase();
        int length = pass.length;
        share.create(loginDraft(), pass);
        assertArrayEquals(new char[length], pass);
    }

    @Test
    void passphraseIsWipedAfterOpen() {
        char[] pass = passphrase();
        int length = pass.length;
        String encoded = share.create(loginDraft(), pass.clone());
        share.open(encoded, pass);
        assertArrayEquals(new char[length], pass);
    }

    @Test
    void passphraseIsWipedAfterOpenFailure() {
        char[] pass = passphrase();
        String encoded = share.create(loginDraft(), pass.clone());
        char[] wrong = "WrongPassphrase99!".toCharArray();
        int wrongLength = wrong.length;
        assertThrows(CryptoException.class, () -> share.open(encoded, wrong));
        assertArrayEquals(new char[wrongLength], wrong);
    }

    @Test
    void iterationsBelowMinimumRejected() {
        ShareDraft draft =
                new ShareDraft(SecretType.GENERIC_SECRET, "x", Map.of("k", "v"), null, null, 1_000);
        assertThrows(ValidationException.class, () -> share.create(draft, passphrase()));
    }

    @Test
    void customIterationsAboveMinimumRoundTrip() {
        ShareDraft draft =
                new ShareDraft(
                        SecretType.GENERIC_SECRET, "x", Map.of("k", "v"), null, null, 200_000);
        String encoded = share.create(draft, passphrase());
        ShareContents contents = share.open(encoded, passphrase());
        assertEquals("v", contents.fields().get("k"));
    }

    @Test
    void shareStringIsBase64urlWithoutPadding() {
        String encoded = share.create(loginDraft(), passphrase());
        String body = encoded.substring("keystead-share:v1:".length());
        assertFalse(body.contains("="));
        assertFalse(body.contains("+"));
        assertFalse(body.contains("/"));
    }

    @Test
    void toStringRedactsFieldValues() {
        String encoded = share.create(loginDraft(), passphrase());
        ShareContents contents = share.open(encoded, passphrase());
        String string = contents.toString();
        assertFalse(string.contains("s3cret-pw"));
        assertFalse(string.contains("alice"));
        assertTrue(string.contains("redacted"));
    }

    @Test
    void draftRejectsBlankTitle() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ShareDraft(SecretType.GENERIC_SECRET, "   ", Map.of("k", "v")));
    }

    @Test
    void draftRejectsBlankFieldName() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put(" ", "v");
        assertThrows(
                IllegalArgumentException.class,
                () -> new ShareDraft(SecretType.GENERIC_SECRET, "t", fields));
    }

    @Test
    void draftFieldsPreserveInsertionOrder() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("zeta", "1");
        fields.put("alpha", "2");
        fields.put("mike", "3");
        ShareDraft draft = new ShareDraft(SecretType.GENERIC_SECRET, "order", fields);

        // The unmodifiable snapshot preserves the caller's insertion order (Map.copyOf would
        // give an unspecified iteration order).
        assertEquals(List.of("zeta", "alpha", "mike"), new ArrayList<>(draft.fields().keySet()));
    }

    @Test
    void contentsFieldsIterateInSortedWireOrder() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("zeta", "1");
        fields.put("alpha", "2");
        fields.put("mike", "3");
        ShareDraft draft = new ShareDraft(SecretType.GENERIC_SECRET, "order", fields);

        ShareContents contents = share.open(share.create(draft, passphrase()), passphrase());

        // The wire format sorts fields by name; the recovered snapshot preserves that order.
        assertEquals(List.of("alpha", "mike", "zeta"), new ArrayList<>(contents.fields().keySet()));
    }

    @Test
    void draftRejectsNegativeIterations() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new ShareDraft(
                                SecretType.GENERIC_SECRET, "t", Map.of("k", "v"), null, null, -1));
    }

    @Test
    void toStringAlsoRedactsTitle() {
        ShareContents contents = share.open(share.create(loginDraft(), passphrase()), passphrase());
        assertFalse(contents.toString().contains("Alice login"));
    }

    @Test
    void oversizedFieldValueIsRejected() {
        String tooLarge = "x".repeat(SecurityLimits.SHARE_MAX_FIELD_VALUE_BYTES + 1);
        ShareDraft draft = new ShareDraft(SecretType.GENERIC_SECRET, "big", Map.of("k", tooLarge));
        ValidationException ex =
                assertThrows(ValidationException.class, () -> share.create(draft, passphrase()));
        assertTrue(ex.getMessage().toLowerCase().contains("field value"));
    }
}
