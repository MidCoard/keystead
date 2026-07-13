package top.focess.keystead.recovery;

import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

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
        this.kit = Objects.requireNonNull(kit, "kit");
        Objects.requireNonNull(accountCredential, "accountCredential");
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(encryptedPrivateKey, "encryptedPrivateKey");
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
        this.accountCredential = Arrays.copyOf(accountCredential, accountCredential.length);
        this.encryptedPrivateKey = Arrays.copyOf(encryptedPrivateKey, encryptedPrivateKey.length);
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
}
