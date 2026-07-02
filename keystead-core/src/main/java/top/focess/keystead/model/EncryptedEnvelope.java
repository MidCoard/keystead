package top.focess.keystead.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

public record EncryptedEnvelope(
    int version,
    String algorithm,
    KeyId keyId,
    byte[] nonce,
    byte[] aad,
    byte[] ciphertext,
    Instant encryptedAt
) {

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
        nonce = Arrays.copyOf(nonce, nonce.length);
        aad = Arrays.copyOf(aad, aad.length);
        ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
    }

    @Override
    public byte[] nonce() {
        return Arrays.copyOf(nonce, nonce.length);
    }

    @Override
    public byte[] aad() {
        return Arrays.copyOf(aad, aad.length);
    }

    @Override
    public byte[] ciphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }

    @Override
    public String toString() {
        return "EncryptedEnvelope[version=%d, algorithm=%s, keyId=%s, nonce=[REDACTED %d bytes], aad=[REDACTED %d bytes], ciphertext=[REDACTED %d bytes], encryptedAt=%s]"
            .formatted(version, algorithm, keyId, nonce.length, aad.length, ciphertext.length, encryptedAt);
    }

    @Override
    public boolean equals(Object object) {
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
