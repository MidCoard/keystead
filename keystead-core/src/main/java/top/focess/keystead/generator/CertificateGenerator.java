package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;

public interface CertificateGenerator {
    @NonNull CertificateBundle generate(@NonNull CertificatePolicy policy);
}
