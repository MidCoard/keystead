package top.focess.keystead.generator;

import java.util.Date;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

public final class CertificatePolicy {

    public static final int DEFAULT_RSA_BITS = 3072;

    private final String commonName;
    private final Date notBefore;
    private final Date notAfter;
    private final int rsaBits;

    public CertificatePolicy(
            @NonNull String commonName, @NonNull Date notBefore, @NonNull Date notAfter) {
        this(commonName, notBefore, notAfter, DEFAULT_RSA_BITS);
    }

    public CertificatePolicy(
            @NonNull String commonName,
            @NonNull Date notBefore,
            @NonNull Date notAfter,
            int rsaBits) {
        this.commonName = requireText(commonName, "commonName");
        this.notBefore = new Date(Objects.requireNonNull(notBefore, "notBefore").getTime());
        this.notAfter = new Date(Objects.requireNonNull(notAfter, "notAfter").getTime());
        if (!this.notAfter.after(this.notBefore)) {
            throw new IllegalArgumentException("notAfter must be after notBefore");
        }
        if (rsaBits < 3072) {
            throw new IllegalArgumentException("rsaBits must be at least 3072");
        }
        this.rsaBits = rsaBits;
    }

    public @NonNull String commonName() {
        return commonName;
    }

    public @NonNull Date notBefore() {
        return new Date(notBefore.getTime());
    }

    public @NonNull Date notAfter() {
        return new Date(notAfter.getTime());
    }

    public int rsaBits() {
        return rsaBits;
    }

    private static @NonNull String requireText(@NonNull String value, @NonNull String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }
}
