package top.focess.keystead.generator;

import java.util.Date;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Parameters for generating an X.509 certificate: subject common name, validity windows, and RSA key
 * size (at least 3072 bits).
 */
public final class CertificatePolicy {

    /** Default RSA key size. */
    public static final int DEFAULT_RSA_BITS = 3072;

    private final String commonName;
    private final Date notBefore;
    private final Date notAfter;
    private final int rsaBits;

    /**
     * Creates a policy with the default RSA key size.
     *
     * @param commonName the subject common name
     * @param notBefore the validity start
     * @param notAfter the validity end
     */
    public CertificatePolicy(
            @NonNull String commonName, @NonNull Date notBefore, @NonNull Date notAfter) {
        this(commonName, notBefore, notAfter, DEFAULT_RSA_BITS);
    }

    /**
     * Creates a policy with an explicit RSA key size.
     *
     * @param commonName the subject common name
     * @param notBefore the validity start
     * @param notAfter the validity end
     * @param rsaBits the RSA key size in bits; at least 3072
     */
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

    /** Returns the subject common name.
     *
     * @return the subject common name */
    public @NonNull String commonName() {
        return commonName;
    }

    /** Returns the certificate validity start.
     *
     * @return the validity start */
    public @NonNull Date notBefore() {
        return new Date(notBefore.getTime());
    }

    /** Returns the certificate validity end.
     *
     * @return the validity end */
    public @NonNull Date notAfter() {
        return new Date(notAfter.getTime());
    }

    /** Returns the RSA key size in bits.
     *
     * @return the RSA key size */
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
