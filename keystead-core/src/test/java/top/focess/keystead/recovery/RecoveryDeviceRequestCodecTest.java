package top.focess.keystead.recovery;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import top.focess.keystead.crypto.DefaultCryptoService;

class RecoveryDeviceRequestCodecTest {

    @Test
    void requestRoundTripsCanonicallyWithStableFingerprint() {
        RecoveryDeviceRequest request = request();
        byte[] encoded = RecoveryDeviceRequestCodec.encode(request);
        RecoveryDeviceRequest decoded = RecoveryDeviceRequestCodec.decode(encoded);
        assertEquals(request.requestId(), decoded.requestId());
        assertEquals(request.username(), decoded.username());
        assertEquals(request.expiresAt(), decoded.expiresAt());
        assertArrayEquals(request.proofPublicKey(), decoded.proofPublicKey());
        assertArrayEquals(request.wrappingPublicKey(), decoded.wrappingPublicKey());
        assertArrayEquals(encoded, RecoveryDeviceRequestCodec.encode(decoded));
        assertEquals(
                RecoveryDeviceRequestCodec.fingerprint(request),
                RecoveryDeviceRequestCodec.fingerprint(decoded));
        assertTrue(
                RecoveryDeviceRequestCodec.fingerprint(request)
                        .matches("[0-9A-F]{4}(?:-[0-9A-F]{4}){4}"));
    }

    @Test
    void requestDefensivelyCopiesPublicKeysAndRedactsText() {
        byte[] proof = bytes(32, (byte) 3);
        byte[] wrapping = bytes(64, (byte) 4);
        RecoveryDeviceRequest request =
                new RecoveryDeviceRequest(
                        1,
                        "request-1",
                        "alice",
                        "nonce-1",
                        Instant.parse("2026-07-14T00:05:00Z"),
                        "laptop-2",
                        "ED25519",
                        proof,
                        DefaultCryptoService.DEVICE_KEY_ALGORITHM,
                        wrapping);
        proof[0] = 9;
        wrapping[0] = 9;
        assertEquals(3, request.proofPublicKey()[0]);
        assertEquals(4, request.wrappingPublicKey()[0]);
        assertFalse(request.toString().contains(Arrays.toString(proof)));
    }

    @Test
    void decoderRejectsVersionTrailingDataAndOversizedInput() {
        byte[] valid = RecoveryDeviceRequestCodec.encode(request());
        byte[] unknownVersion = valid.clone();
        unknownVersion[7] = 2;
        assertThrows(
                IllegalArgumentException.class,
                () -> RecoveryDeviceRequestCodec.decode(unknownVersion));
        byte[] trailing = Arrays.copyOf(valid, valid.length + 1);
        assertThrows(
                IllegalArgumentException.class, () -> RecoveryDeviceRequestCodec.decode(trailing));
        assertThrows(
                IllegalArgumentException.class,
                () -> RecoveryDeviceRequestCodec.decode(new byte[300_000]));
    }

    @Test
    void requestRejectsInvalidShape() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new RecoveryDeviceRequest(
                                2,
                                "request-1",
                                "alice",
                                "nonce-1",
                                Instant.parse("2026-07-14T00:05:00Z"),
                                "laptop-2",
                                "ED25519",
                                bytes(32, (byte) 1),
                                DefaultCryptoService.DEVICE_KEY_ALGORITHM,
                                bytes(64, (byte) 2)));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new RecoveryDeviceRequest(
                                1,
                                "",
                                "alice",
                                "nonce-1",
                                Instant.parse("2026-07-14T00:05:00Z"),
                                "laptop-2",
                                "ED25519",
                                bytes(32, (byte) 1),
                                DefaultCryptoService.DEVICE_KEY_ALGORITHM,
                                bytes(64, (byte) 2)));
    }

    private static RecoveryDeviceRequest request() {
        return new RecoveryDeviceRequest(
                1,
                "request-1",
                "alice",
                "nonce-1",
                Instant.parse("2026-07-14T00:05:00Z"),
                "laptop-2",
                "ED25519",
                bytes(32, (byte) 1),
                DefaultCryptoService.DEVICE_KEY_ALGORITHM,
                bytes(64, (byte) 2));
    }

    private static byte[] bytes(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }
}
