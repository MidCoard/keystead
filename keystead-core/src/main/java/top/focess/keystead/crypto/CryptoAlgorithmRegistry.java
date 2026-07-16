package top.focess.keystead.crypto;

import java.util.List;
import org.jspecify.annotations.NonNull;

/**
 * Canonical registry of approved algorithm names for AEAD, KDF, and device key packages, plus
 * membership checks. Fail-closed: unrecognized names are rejected.
 */
public final class CryptoAlgorithmRegistry {

    /** Approved AEAD algorithm name for AES-256-GCM. */
    public static final String AEAD_AES_256_GCM = "AES-256-GCM";

    /** Approved AEAD algorithm name for ChaCha20-Poly1305. */
    public static final String AEAD_CHACHA20_POLY1305 = "CHACHA20-POLY1305";

    /** Approved KDF algorithm name for PBKDF2-HMAC-SHA-256. */
    public static final String KDF_PBKDF2_HMAC_SHA256 = "PBKDF2WithHmacSHA256";

    /** Approved KDF algorithm name for PBKDF2-HMAC-SHA-512. */
    public static final String KDF_PBKDF2_HMAC_SHA512 = "PBKDF2WithHmacSHA512";

    /** Approved device key-package algorithm name for Tink ECIES P-256. */
    public static final String DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM =
            "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM";

    /** Approved device key-package algorithm name for the Tink device key package format. */
    public static final String DEVICE_TINK_DEVICE_KEY_PACKAGE = "TINK_DEVICE_KEY_PACKAGE";

    private static final List<String> APPROVED_AEAD =
            List.of(AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305);
    private static final List<String> APPROVED_KDF =
            List.of(KDF_PBKDF2_HMAC_SHA256, KDF_PBKDF2_HMAC_SHA512);
    private static final List<String> APPROVED_DEVICE_KEY_PACKAGES =
            List.of(
                    DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
                    DEVICE_TINK_DEVICE_KEY_PACKAGE);

    private CryptoAlgorithmRegistry() {}

    /** Returns whether the algorithm is an approved AEAD.
     *
     * @param algorithm the algorithm name to check
     * @return whether the algorithm is an approved AEAD */
    public static boolean isApprovedAead(@NonNull String algorithm) {
        return APPROVED_AEAD.contains(algorithm);
    }

    /** Returns whether the algorithm is an approved KDF.
     *
     * @param algorithm the algorithm name to check
     * @return whether the algorithm is an approved KDF */
    public static boolean isApprovedKdf(@NonNull String algorithm) {
        return APPROVED_KDF.contains(algorithm);
    }

    /** Returns whether the algorithm is an approved device key package.
     *
     * @param algorithm the algorithm name to check
     * @return whether the algorithm is an approved device key package */
    public static boolean isApprovedDeviceKeyPackage(@NonNull String algorithm) {
        return APPROVED_DEVICE_KEY_PACKAGES.contains(algorithm);
    }

    /** Returns the approved AEAD algorithm names.
     *
     * @return the approved AEAD algorithm names */
    public static @NonNull List<String> approvedAeadAlgorithms() {
        return APPROVED_AEAD;
    }

    /** Returns the approved KDF algorithm names.
     *
     * @return the approved KDF algorithm names */
    public static @NonNull List<String> approvedKdfAlgorithms() {
        return APPROVED_KDF;
    }

    /** Returns the approved device key-package algorithm names.
     *
     * @return the approved device key-package algorithm names */
    public static @NonNull List<String> approvedDeviceKeyPackageAlgorithms() {
        return APPROVED_DEVICE_KEY_PACKAGES;
    }
}
