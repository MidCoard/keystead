package top.focess.keystead.crypto;

import java.util.List;
import org.jspecify.annotations.NonNull;

public final class CryptoAlgorithmRegistry {

    public static final String AEAD_AES_256_GCM = "AES-256-GCM";
    public static final String AEAD_CHACHA20_POLY1305 = "CHACHA20-POLY1305";

    public static final String KDF_PBKDF2_HMAC_SHA256 = "PBKDF2WithHmacSHA256";
    public static final String KDF_PBKDF2_HMAC_SHA512 = "PBKDF2WithHmacSHA512";

    public static final String DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM =
            "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM";
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

    public static boolean isApprovedAead(@NonNull String algorithm) {
        return APPROVED_AEAD.contains(algorithm);
    }

    public static boolean isApprovedKdf(@NonNull String algorithm) {
        return APPROVED_KDF.contains(algorithm);
    }

    public static boolean isApprovedDeviceKeyPackage(@NonNull String algorithm) {
        return APPROVED_DEVICE_KEY_PACKAGES.contains(algorithm);
    }

    public static @NonNull List<String> approvedAeadAlgorithms() {
        return APPROVED_AEAD;
    }

    public static @NonNull List<String> approvedKdfAlgorithms() {
        return APPROVED_KDF;
    }

    public static @NonNull List<String> approvedDeviceKeyPackageAlgorithms() {
        return APPROVED_DEVICE_KEY_PACKAGES;
    }
}
