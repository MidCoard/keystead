package top.focess.keystead.share;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.TinkAesGcmCipher;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.service.ValidationException;

class ShareCodecTest {

    private static final Instant NOW = Instant.parse("2026-07-25T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String PREFIX = "keystead-share:v1:";
    private static final char[] PASSPHRASE = "CorrectHorse42!".toCharArray();

    private final DefaultCryptoService crypto =
            new DefaultCryptoService(
                    new SecureRandom(), new TinkAesGcmCipher(), SecretMemoryProvider.heap());
    private final ShareService share = new ShareService(crypto, CLOCK);

    private String freshShare() {
        return share.create(
                new ShareDraft(SecretType.GENERIC_SECRET, "t", Map.of("k", "v")),
                PASSPHRASE.clone());
    }

    private static String reencode(byte[] bytes) {
        return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] decode(String encoded) {
        return Base64.getUrlDecoder().decode(encoded.substring(PREFIX.length()));
    }

    @Test
    void rejectsMissingPrefix() {
        assertThrows(
                ValidationException.class, () -> share.open("not-a-share", PASSPHRASE.clone()));
    }

    @Test
    void rejectsInvalidBase64() {
        String encoded = PREFIX + "!!!!not-base64!!!!";
        assertThrows(ValidationException.class, () -> share.open(encoded, PASSPHRASE.clone()));
    }

    @Test
    void rejectsOversizedString() {
        StringBuilder huge = new StringBuilder(PREFIX);
        huge.append("A".repeat(2 * 1_048_576 + 8192));
        assertThrows(
                ValidationException.class, () -> share.open(huge.toString(), PASSPHRASE.clone()));
    }

    @Test
    void rejectsTruncatedHeader() {
        byte[] full = decode(freshShare());
        String truncated = reencode(Arrays.copyOf(full, 5));
        assertThrows(ValidationException.class, () -> share.open(truncated, PASSPHRASE.clone()));
    }

    @Test
    void rejectsBadMagic() {
        byte[] full = decode(freshShare());
        full[0] = (byte) 'X';
        assertThrows(
                ValidationException.class, () -> share.open(reencode(full), PASSPHRASE.clone()));
    }

    @Test
    void rejectsUnsupportedVersion() {
        byte[] full = decode(freshShare());
        full[4] = 9;
        ValidationException ex =
                assertThrows(
                        ValidationException.class,
                        () -> share.open(reencode(full), PASSPHRASE.clone()));
        assertTrue(ex.getMessage().toLowerCase().contains("version"));
    }

    @Test
    void rejectsTrailingData() {
        byte[] full = decode(freshShare());
        byte[] withTrailer = Arrays.copyOf(full, full.length + 4);
        assertThrows(
                ValidationException.class,
                () -> share.open(reencode(withTrailer), PASSPHRASE.clone()));
    }

    @Test
    void rejectsTamperedCiphertext() {
        byte[] full = decode(freshShare());
        full[full.length - 1] ^= 0x01;
        assertThrows(CryptoException.class, () -> share.open(reencode(full), PASSPHRASE.clone()));
    }

    @Test
    void rejectsTamperedHeaderAad() {
        // Offset 30 is a salt byte (magic 4 + version 1 + kdfAlg u16+20 + saltLen 1 = 28;
        // salt bytes are 28..43). Flipping it changes both the derived key and the AAD, so the
        // AEAD tag fails.
        byte[] full = decode(freshShare());
        full[30] ^= 0x01;
        assertThrows(CryptoException.class, () -> share.open(reencode(full), PASSPHRASE.clone()));
    }

    @Test
    void rejectsEmptyString() {
        assertThrows(ValidationException.class, () -> share.open("", PASSPHRASE.clone()));
    }

    @Test
    void rejectsBarePrefix() {
        assertThrows(ValidationException.class, () -> share.open(PREFIX, PASSPHRASE.clone()));
    }
}
