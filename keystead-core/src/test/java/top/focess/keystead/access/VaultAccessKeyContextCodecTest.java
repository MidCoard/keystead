package top.focess.keystead.access;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class VaultAccessKeyContextCodecTest {

    @Test
    void contextBindsCanonicalRequestVaultFingerprintAndKeyGeneration() {
        byte[] baseline =
                VaultAccessKeyContextCodec.encode(
                        new byte[] {1, 2, 3}, "6000000000000001", "vault-key-1");

        assertFalse(
                Arrays.equals(
                        baseline,
                        VaultAccessKeyContextCodec.encode(
                                new byte[] {1, 2, 4}, "6000000000000001", "vault-key-1")));
        assertFalse(
                Arrays.equals(
                        baseline,
                        VaultAccessKeyContextCodec.encode(
                                new byte[] {1, 2, 3}, "6000000000000002", "vault-key-1")));
        assertFalse(
                Arrays.equals(
                        baseline,
                        VaultAccessKeyContextCodec.encode(
                                new byte[] {1, 2, 3}, "6000000000000001", "vault-key-2")));
    }
}
