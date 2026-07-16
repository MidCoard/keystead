package top.focess.keystead.recovery;

import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Client-owned secret and public material created during recovery enrollment. The account
 * credential and encrypted private key are defensively copied on construction and on access, and
 * are wiped when the material is closed. Closing the material also closes the owned recovery kit.
 */
public final class RecoveryEnrollmentMaterial implements AutoCloseable {

    private static final int CREDENTIAL_BYTES = 32;
    private static final int MAX_ENCRYPTED_PRIVATE_KEY_BYTES = 1024 * 1024;

    private final RecoveryKit kit;
    private final byte[] accountCredential;
    private final RecoveryPublicKey publicKey;
    private final byte[] encryptedPrivateKey;
    private boolean closed;

    /**
     * Creates recovery enrollment material for the given kit and key material.
     *
     * @param kit the owned recovery kit; closed when this material is closed
     * @param accountCredential the 32-byte account recovery credential; defensively copied
     * @param publicKey the public wrapping key for this enrollment generation
     * @param encryptedPrivateKey the encrypted recovery private key; defensively copied
     */
    public RecoveryEnrollmentMaterial(
            @NonNull RecoveryKit kit,
            byte @NonNull [] accountCredential,
            @NonNull RecoveryPublicKey publicKey,
            byte @NonNull [] encryptedPrivateKey) {
        this(
                kit,
                accountCredential,
                publicKey,
                encryptedPrivateKey,
                value -> Arrays.copyOf(value, value.length));
    }

    RecoveryEnrollmentMaterial(
            @NonNull RecoveryKit kit,
            byte @NonNull [] accountCredential,
            @NonNull RecoveryPublicKey publicKey,
            byte @NonNull [] encryptedPrivateKey,
            @NonNull SecretArrayCopier arrayCopier) {
        Objects.requireNonNull(kit, "kit");
        Objects.requireNonNull(accountCredential, "accountCredential");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(encryptedPrivateKey, "encryptedPrivateKey");
        Objects.requireNonNull(arrayCopier, "arrayCopier");
        if (accountCredential.length != CREDENTIAL_BYTES) {
            throw new IllegalArgumentException("Account recovery credential must be 32 bytes");
        }
        if (encryptedPrivateKey.length == 0
                || encryptedPrivateKey.length > MAX_ENCRYPTED_PRIVATE_KEY_BYTES) {
            throw new IllegalArgumentException("Encrypted recovery private key is invalid");
        }
        if (!kit.enrollmentId().equals(publicKey.enrollmentId())
                || kit.generation() != publicKey.generation()) {
            throw new IllegalArgumentException("Recovery enrollment material does not match");
        }
        byte @Nullable [] credentialCopy = null;
        byte @Nullable [] privateKeyCopy = null;
        boolean completed = false;
        try {
            credentialCopy =
                    Objects.requireNonNull(
                            arrayCopier.copy(accountCredential), "account credential copy");
            privateKeyCopy =
                    Objects.requireNonNull(
                            arrayCopier.copy(encryptedPrivateKey), "encrypted private-key copy");
            this.kit = kit;
            this.publicKey = publicKey;
            this.accountCredential = credentialCopy;
            this.encryptedPrivateKey = privateKeyCopy;
            completed = true;
        } finally {
            if (!completed) {
                if (credentialCopy != null) {
                    Arrays.fill(credentialCopy, (byte) 0);
                }
                if (privateKeyCopy != null) {
                    Arrays.fill(privateKeyCopy, (byte) 0);
                }
                kit.close();
            }
        }
    }

    /** Returns the owned recovery kit.
     *
     * @return the owned recovery kit */
    public synchronized @NonNull RecoveryKit kit() {
        requireOpen();
        return kit;
    }

    /** Returns a defensive copy of the account recovery credential.
     *
     * @return a defensive copy of the account recovery credential */
    public synchronized byte @NonNull [] accountCredential() {
        requireOpen();
        return Arrays.copyOf(accountCredential, accountCredential.length);
    }

    /** Returns the public wrapping key for this enrollment generation.
     *
     * @return the public wrapping key for this enrollment generation */
    public @NonNull RecoveryPublicKey publicKey() {
        return publicKey;
    }

    /** Returns a defensive copy of the encrypted recovery private key.
     *
     * @return a defensive copy of the encrypted recovery private key */
    public synchronized byte @NonNull [] encryptedPrivateKey() {
        requireOpen();
        return Arrays.copyOf(encryptedPrivateKey, encryptedPrivateKey.length);
    }

    /** Returns whether this material has been closed and its secrets wiped.
     *
     * @return {@code true} if this material has been closed */
    public synchronized boolean isClosed() {
        return closed;
    }

    @Override
    public synchronized void close() {
        if (!closed) {
            kit.close();
            Arrays.fill(accountCredential, (byte) 0);
            Arrays.fill(encryptedPrivateKey, (byte) 0);
            closed = true;
        }
    }

    @Override
    public @NonNull String toString() {
        return "RecoveryEnrollmentMaterial(<redacted>)";
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Recovery enrollment material is closed");
        }
    }

    @FunctionalInterface
    interface SecretArrayCopier {

        byte @NonNull [] copy(byte @NonNull [] value);
    }
}
