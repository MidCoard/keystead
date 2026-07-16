package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;

/**
 * Generates an X.509 certificate and private-key bundle from a {@link CertificatePolicy}.
 */
public interface CertificateGenerator {

    /**
     * Generates a certificate bundle for the given policy.
     *
     * @param policy the certificate policy
     * @return the generated certificate bundle
     */
    @NonNull CertificateBundle generate(@NonNull CertificatePolicy policy);
}
