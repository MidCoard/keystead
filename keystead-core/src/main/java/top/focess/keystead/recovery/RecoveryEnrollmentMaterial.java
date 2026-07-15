package top.focess.keystead.recovery;

import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Client-owned secret and public material created during recovery enrollment. */
public final class RecoveryEnrollmentMaterial implements AutoCloseable {

    private static final int CREDENTIAL_BYTES = 32;
    private static final int MAX_ENCRYPTED_PRIVATE_KEY_BYTES = 1024 * 1024;

    private final RecoveryKit kit;
    private final byte[] accountCredential;
    private final RecoveryPublicKey publicKey;
    private final byte[] encryptedPrivateKey;
    private boolean closed;

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

    public synchronized @NonNull RecoveryKit kit() {
        requireOpen();
        return kit;
    }

    public synchronized byte @NonNull [] accountCredential() {
        requireOpen();
        return Arrays.copyOf(accountCredential, accountCredential.length);
    }

    public @NonNull RecoveryPublicKey publicKey() {
        return publicKey;
    }

    public synchronized byte @NonNull [] encryptedPrivateKey() {
        requireOpen();
        return Arrays.copyOf(encryptedPrivateKey, encryptedPrivateKey.length);
    }

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
