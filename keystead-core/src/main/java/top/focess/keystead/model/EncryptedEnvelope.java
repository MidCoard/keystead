package top.focess.keystead.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * An encrypted payload envelope: version, algorithm, key, nonce, AAD, ciphertext, and timestamp.
 * The byte-array components are defensively copied on construction and on access so callers cannot
 * mutate the envelope's internal state.
 *
 * @param version the envelope format version; must be positive
 * @param algorithm the authenticated encryption algorithm name
 * @param keyId the identifier of the key used to encrypt the payload
 * @param nonce the nonce used for encryption
 * @param aad the additional authenticated data bound to the ciphertext
 * @param ciphertext the encrypted payload
 * @param encryptedAt when the envelope was encrypted
 */
public record EncryptedEnvelope(
        int version,
        @NonNull String algorithm,
        @NonNull KeyId keyId,
        byte @NonNull [] nonce,
        byte @NonNull [] aad,
        byte @NonNull [] ciphertext,
        @NonNull Instant encryptedAt) {

    /** Validates and defensively copies the record components. */
    public EncryptedEnvelope {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(aad, "aad");
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(encryptedAt, "encryptedAt");
        if (version <= 0) {
            throw new IllegalArgumentException("Envelope version must be positive");
        }
        if (aad.length > SecurityLimits.MAX_ENVELOPE_AAD_BYTES) {
            throw new IllegalArgumentException("Encrypted envelope AAD exceeds the size limit");
        }
        if (ciphertext.length > SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES) {
            throw new IllegalArgumentException(
                    "Encrypted envelope ciphertext exceeds the size limit");
        }
        nonce = Arrays.copyOf(nonce, nonce.length);
        aad = Arrays.copyOf(aad, aad.length);
        ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
    }

    /** Returns a defensive copy of the nonce.
     *
     * @return a defensive copy of the nonce */
    @Override
    public byte @NonNull [] nonce() {
        return Arrays.copyOf(nonce, nonce.length);
    }

    /** Returns a defensive copy of the additional authenticated data.
     *
     * @return a defensive copy of the additional authenticated data */
    @Override
    public byte @NonNull [] aad() {
        return Arrays.copyOf(aad, aad.length);
    }

    /** Returns a defensive copy of the ciphertext.
     *
     * @return a defensive copy of the ciphertext */
    @Override
    public byte @NonNull [] ciphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }

    @Override
    public @NonNull String toString() {
        return "EncryptedEnvelope[version=%d, algorithm=%s, keyId=%s, nonce=[REDACTED %d bytes], aad=[REDACTED %d bytes], ciphertext=[REDACTED %d bytes], encryptedAt=%s]"
                .formatted(
                        version,
                        algorithm,
                        keyId,
                        nonce.length,
                        aad.length,
                        ciphertext.length,
                        encryptedAt);
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof EncryptedEnvelope other)) {
            return false;
        }
        return version == other.version
                && algorithm.equals(other.algorithm)
                && keyId.equals(other.keyId)
                && Arrays.equals(nonce, other.nonce)
                && Arrays.equals(aad, other.aad)
                && Arrays.equals(ciphertext, other.ciphertext)
                && encryptedAt.equals(other.encryptedAt);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(version, algorithm, keyId, encryptedAt);
        result = 31 * result + Arrays.hashCode(nonce);
        result = 31 * result + Arrays.hashCode(aad);
        result = 31 * result + Arrays.hashCode(ciphertext);
        return result;
    }
}
