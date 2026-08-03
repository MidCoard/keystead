package top.focess.keystead.access;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import top.focess.keystead.crypto.DefaultCryptoService;

class VaultAccessRequestCodecTest {

    @Test
    void ephemeralRequestRoundTripsWithoutPersistentDeviceIdentity() {
        VaultAccessRequest request = request(bytes(64, (byte) 2));

        byte[] encoded = VaultAccessRequestCodec.encode(request);
        VaultAccessRequest decoded = VaultAccessRequestCodec.decode(encoded);

        assertEquals("550e8400-e29b-41d4-a716-446655440000", decoded.requestId());
        assertEquals("alice", decoded.accountId());
        assertEquals("https://vault.example", decoded.serverOrigin());
        assertEquals(Instant.parse("2026-07-14T00:05:00Z"), decoded.expiresAt());
        assertEquals(DefaultCryptoService.DEVICE_KEY_ALGORITHM, decoded.keyAlgorithm());
        assertArrayEquals(bytes(64, (byte) 2), decoded.exchangePublicKey());
        assertArrayEquals(encoded, VaultAccessRequestCodec.encode(decoded));
    }

    @Test
    void comparisonFingerprintBindsTheEphemeralPublicKey() {
        VaultAccessRequest first = request(bytes(64, (byte) 2));
        VaultAccessRequest substituted = request(bytes(64, (byte) 3));

        String fingerprint = VaultAccessRequestCodec.fingerprint(first);

        assertTrue(fingerprint.matches("[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}"));
        assertNotEquals(fingerprint, VaultAccessRequestCodec.fingerprint(substituted));
    }

    @Test
    void requestDefensivelyCopiesAndRedactsTheExchangePublicKey() {
        byte[] publicKey = bytes(64, (byte) 4);
        VaultAccessRequest request = request(publicKey);

        publicKey[0] = 9;

        assertEquals(4, request.exchangePublicKey()[0]);
        assertFalse(request.toString().contains(Arrays.toString(publicKey)));
    }

    @Test
    void decoderRejectsVersionTrailingDataAndOversizedInput() {
        byte[] valid = VaultAccessRequestCodec.encode(request(bytes(64, (byte) 2)));
        byte[] unknownVersion = valid.clone();
        unknownVersion[7] = 3;
        assertThrows(
                IllegalArgumentException.class,
                () -> VaultAccessRequestCodec.decode(unknownVersion));
        byte[] trailing = Arrays.copyOf(valid, valid.length + 1);
        assertThrows(
                IllegalArgumentException.class, () -> VaultAccessRequestCodec.decode(trailing));
        assertThrows(
                IllegalArgumentException.class,
                () -> VaultAccessRequestCodec.decode(new byte[300_000]));
    }

    private static VaultAccessRequest request(byte[] publicKey) {
        return new VaultAccessRequest(
                2,
                "550e8400-e29b-41d4-a716-446655440000",
                "alice",
                "https://vault.example",
                Instant.parse("2026-07-14T00:05:00Z"),
                DefaultCryptoService.DEVICE_KEY_ALGORITHM,
                publicKey);
    }

    private static byte[] bytes(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }
}
