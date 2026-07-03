package top.focess.keystead.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

class CryptoAlgorithmRegistryTest {

    @Test
    void approvedAeadAlgorithmsIncludeMainstreamAuthenticatedEncryption() {
        assertTrue(CryptoAlgorithmRegistry.isApprovedAead("AES-256-GCM"));
        assertTrue(CryptoAlgorithmRegistry.isApprovedAead("CHACHA20-POLY1305"));
        assertFalse(CryptoAlgorithmRegistry.isApprovedAead("AES-ECB"));
    }

    @Test
    void approvedKdfAlgorithmsAreExplicit() {
        assertTrue(CryptoAlgorithmRegistry.isApprovedKdf("PBKDF2WithHmacSHA256"));
        assertTrue(CryptoAlgorithmRegistry.isApprovedKdf("PBKDF2WithHmacSHA512"));
        assertFalse(CryptoAlgorithmRegistry.isApprovedKdf("MD5"));
    }

    @Test
    void approvedDevicePackageAlgorithmsAreExplicit() {
        assertTrue(
                CryptoAlgorithmRegistry.isApprovedDeviceKeyPackage(
                        "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"));
        assertTrue(CryptoAlgorithmRegistry.isApprovedDeviceKeyPackage("TINK_DEVICE_KEY_PACKAGE"));
        assertFalse(CryptoAlgorithmRegistry.isApprovedDeviceKeyPackage("RAW_RSA"));
    }

    @Test
    void approvedAlgorithmCatalogsAreStableAndImmutable() {
        assertEquals(
                List.of("AES-256-GCM", "CHACHA20-POLY1305"),
                CryptoAlgorithmRegistry.approvedAeadAlgorithms());
        assertEquals(
                List.of("PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA512"),
                CryptoAlgorithmRegistry.approvedKdfAlgorithms());
        assertEquals(
                List.of("TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM", "TINK_DEVICE_KEY_PACKAGE"),
                CryptoAlgorithmRegistry.approvedDeviceKeyPackageAlgorithms());

        assertThrows(
                UnsupportedOperationException.class,
                () -> CryptoAlgorithmRegistry.approvedAeadAlgorithms().add("AES-CBC"));
    }
}
