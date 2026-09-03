package top.focess.keystead.share;

import java.time.Clock;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.service.ValidationException;

/**
 * Mints and opens single-secret shares.
 *
 * <p>A share is a self-contained encrypted string of the form
 * {@code keystead-share:v1:<base64url>} carrying one secret's fields plus optional metadata
 * (title, sharer note, expiry). The temp passphrase supplied by the sharer is the only key;
 * no vault, vault key, or fingerprint is involved. The recipient pastes the string and
 * supplies the same passphrase to recover the payload.
 *
 * <p>This facade is the public entry point for the share format; the binary layout lives in
 * {@link ShareCodec} and is documented in {@code README.md} (Single-secret sharing).
 *
 * <p>The {@code char[]} passphrase arguments are wiped by these methods on return (including
 * on failure); callers should not reuse the array afterwards.
 */
public final class ShareService {

    private final DefaultCryptoService crypto;
    private final Clock clock;

    /**
     * Creates a share service backed by the given crypto service and clock.
     *
     * @param crypto the crypto service providing PBKDF2 key derivation and AES-256-GCM AEAD
     * @param clock  the clock used for mint/decrypt timestamps and expiry checks
     */
    public ShareService(@NonNull DefaultCryptoService crypto, @NonNull Clock clock) {
        this.crypto = Objects.requireNonNull(crypto, "crypto");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Creates a share service backed by the given crypto service and the system UTC clock.
     *
     * @param crypto the crypto service providing PBKDF2 key derivation and AES-256-GCM AEAD
     */
    public ShareService(@NonNull DefaultCryptoService crypto) {
        this(crypto, Clock.systemUTC());
    }

    /**
     * Mints a single-secret share string.
     *
     * <p>The temp passphrase is checked against the minimum-strength policy (length and
     * character-class floor) before any cryptographic work is done.
     *
     * @param draft          the secret payload and options to share
     * @param tempPassphrase the recipient's temp passphrase (wiped on return)
     * @return the {@code keystead-share:v1:...} string
     * @throws ValidationException if the draft violates size limits or the passphrase is too weak
     * @throws CryptoException     if the underlying AEAD encryption fails
     */
    public @NonNull String create(@NonNull ShareDraft draft, char @NonNull [] tempPassphrase) {
        Objects.requireNonNull(draft, "draft");
        Objects.requireNonNull(tempPassphrase, "tempPassphrase");
        try {
            SharePassphrasePolicy.requireAcceptable(tempPassphrase);
            return ShareCodec.encode(draft, tempPassphrase, crypto, clock);
        } finally {
            Wipe.wipe(tempPassphrase);
        }
    }

    /**
     * Opens (decrypts) a single-secret share string.
     *
     * <p>A wrong passphrase fails with {@link CryptoException}. Because expiry is authenticated
     * inside the encrypted payload, an expired share ({@code expiresAt} in the past) can only be
     * identified and rejected with {@link ValidationException} after successful decryption.
     *
     * @param encoded        the {@code keystead-share:v1:...} string
     * @param tempPassphrase the recipient's temp passphrase (wiped on return)
     * @return the recovered payload
     * @throws ValidationException if the string is malformed, truncated, or the share has expired
     * @throws CryptoException     if the passphrase is wrong or the ciphertext/AAD is tampered
     */
    public @NonNull ShareContents open(@NonNull String encoded, char @NonNull [] tempPassphrase) {
        Objects.requireNonNull(encoded, "encoded");
        Objects.requireNonNull(tempPassphrase, "tempPassphrase");
        try {
            return ShareCodec.decode(encoded, tempPassphrase, crypto, clock);
        } finally {
            Wipe.wipe(tempPassphrase);
        }
    }
}
