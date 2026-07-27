package top.focess.keystead.share;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.SecurityLimits;
import top.focess.keystead.service.ValidationException;

/**
 * Binary encode/decode for the single-secret share envelope (Landing 3).
 *
 * <p>Wire layout (all integers big-endian):
 * <pre>
 *   ENCODED = "keystead-share:v1:" + base64url(BYTES)   (no padding)
 *   BYTES:
 *     magic[4]              "KSTS"
 *     version[1]            1
 *     HEADER  (plaintext; = AEAD AAD, bytes [0, headerEnd))
 *       kdfAlgorithm        u16 len + UTF-8
 *       kdfSalt             u8  len + bytes
 *       kdfIterations       s32
 *       nonce               u8  len + bytes
 *     ENVELOPE
 *       envelopeVersion[1]  1
 *       algorithm           u16 len + UTF-8
 *       ciphertext          s32 len + bytes
 *     BODY  (plaintext the ciphertext decrypts to)
 *       bodyVersion[1]      1
 *       shareId             u16 len + UTF-8
 *       secretType          u16 len + UTF-8
 *       title               u16 len + UTF-8
 *       fieldCount          s32
 *       fields[fieldCount]
 *         name              u16 len + UTF-8
 *         value             u16 len + UTF-8
 *       hasNote[1]          0/1
 *       sharerNote          u16 len + UTF-8   (only if hasNote)
 *       createdAt           s64 seconds + s32 nanos
 *       hasExpiresAt[1]     0/1
 *       expiresAt           s64 seconds + s32 nanos   (only if hasExpiresAt)
 * </pre>
 *
 * <p>Fields are sorted by name at mint time for deterministic encoding. The plaintext
 * header (magic through nonce) is the AEAD additional-authenticated-data, so any tampering
 * with versioning or KDF parameters is detected at decryption time.
 *
 * <p>Package-private; {@link ShareService} is the public facade.
 */
final class ShareCodec {

    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();

    static @NonNull String encode(
            @NonNull ShareDraft draft,
            char @NonNull [] passphrase,
            @NonNull DefaultCryptoService crypto,
            @NonNull Clock clock) {
        Objects.requireNonNull(draft, "draft");
        Objects.requireNonNull(crypto, "crypto");
        Objects.requireNonNull(clock, "clock");

        int iterations = draft.kdfIterations();
        if (iterations <= 0) {
            iterations = DefaultCryptoService.DEFAULT_KDF_ITERATIONS;
        }
        if (iterations < SecurityLimits.SHARE_PBKDF2_MIN_ITERATIONS) {
            throw new ValidationException(
                    "Share KDF iterations are below the minimum ("
                            + SecurityLimits.SHARE_PBKDF2_MIN_ITERATIONS
                            + ')');
        }
        if (iterations > SecurityLimits.MAX_PBKDF2_ITERATIONS) {
            throw new ValidationException(
                    "Share KDF iterations exceed the maximum ("
                            + SecurityLimits.MAX_PBKDF2_ITERATIONS
                            + ')');
        }

        String title = draft.title();
        if (title.length() > SecurityLimits.SHARE_MAX_TITLE_CHARACTERS) {
            throw new ValidationException("Share title exceeds maximum length");
        }
        String note = draft.sharerNote();
        if (note != null && note.length() > SecurityLimits.SHARE_MAX_NOTE_CHARACTERS) {
            throw new ValidationException("Share note exceeds maximum length");
        }
        Map<String, String> fields = draft.fields();
        if (fields.size() > SecurityLimits.SHARE_MAX_FIELD_COUNT) {
            throw new ValidationException("Share has too many fields");
        }

        TreeMap<String, String> sorted = new TreeMap<>(fields);
        List<byte[]> valueBytes = new ArrayList<>(sorted.size());
        byte[] noteBytes = null;
        byte[] salt = null;
        byte[] nonce = null;
        byte[] bodyBytes = null;
        byte[] ciphertext = null;
        try {
            noteBytes = note == null ? null : utf8(note);
            if (noteBytes != null && noteBytes.length > 0xFFFF) {
                throw new ValidationException("Share note exceeds maximum encoded length");
            }
            salt = crypto.randomSalt();
            nonce = crypto.randomNonce();

            String shareId = UUID.randomUUID().toString();
            String secretTypeName = draft.secretType().name();
            Instant now = clock.instant();

            // Size the body, capturing value byte arrays for both sizing and emission.
            int bodySize = 1; // bodyVersion
            bodySize += u16StringSize(shareId);
            bodySize += u16StringSize(secretTypeName);
            bodySize += u16StringSize(title);
            bodySize += 4; // fieldCount
            for (Map.Entry<String, String> entry : sorted.entrySet()) {
                String name = entry.getKey();
                if (name.length() > SecurityLimits.SHARE_MAX_FIELD_NAME_CHARACTERS) {
                    throw new ValidationException(
                            "Share field name exceeds maximum length: " + name);
                }
                byte[] nb = utf8(name);
                if (nb.length > 0xFFFF) {
                    throw new ValidationException(
                            "Share field name exceeds maximum encoded length: " + name);
                }
                byte[] vb = utf8(entry.getValue());
                if (vb.length > SecurityLimits.SHARE_MAX_FIELD_VALUE_BYTES) {
                    Wipe.wipe(vb);
                    throw new ValidationException(
                            "Share field value exceeds maximum size: " + name);
                }
                valueBytes.add(vb);
                bodySize += 2 + nb.length + 2 + vb.length;
            }
            bodySize += 1; // hasNote
            if (noteBytes != null) {
                bodySize += 2 + noteBytes.length;
            }
            bodySize += 8 + 4; // createdAt
            bodySize += 1; // hasExpiresAt
            Instant expiresAt = draft.expiresAt();
            if (expiresAt != null) {
                bodySize += 8 + 4;
            }

            ByteBuffer body = ByteBuffer.allocate(bodySize);
            body.put((byte) ShareFormat.BODY_VERSION);
            putU16String(body, shareId);
            putU16String(body, secretTypeName);
            putU16String(body, title);
            body.putInt(sorted.size());
            int valueIndex = 0;
            for (Map.Entry<String, String> entry : sorted.entrySet()) {
                putU16String(body, entry.getKey());
                putU16Bytes(body, valueBytes.get(valueIndex++));
            }
            if (noteBytes != null) {
                body.put((byte) 1);
                putU16Bytes(body, noteBytes);
            } else {
                body.put((byte) 0);
            }
            putInstant(body, now);
            if (expiresAt != null) {
                body.put((byte) 1);
                putInstant(body, expiresAt);
            } else {
                body.put((byte) 0);
            }
            if (body.hasRemaining()) {
                throw new AssertionError("Body size miscomputed");
            }
            bodyBytes = body.array();

            // Header (magic + version + KDF params + nonce) is the AEAD AAD.
            byte[] kdfAlgorithmBytes = utf8(ShareFormat.KDF_ALGORITHM);
            int headerSize =
                    ShareFormat.MAGIC.length
                            + 1
                            + 2
                            + kdfAlgorithmBytes.length
                            + 1
                            + salt.length
                            + 4
                            + 1
                            + nonce.length;
            ByteBuffer header = ByteBuffer.allocate(headerSize);
            header.put(ShareFormat.MAGIC);
            header.put((byte) ShareFormat.VERSION);
            putU16Bytes(header, kdfAlgorithmBytes);
            putU8Bytes(header, salt);
            header.putInt(iterations);
            putU8Bytes(header, nonce);
            if (header.hasRemaining()) {
                throw new AssertionError("Header size miscomputed");
            }
            byte[] headerBytes = header.array();

            KdfParameters kdfParameters =
                    KdfParameters.pbkdf2(ShareFormat.KDF_ALGORITHM, salt, iterations);
            ciphertext =
                    crypto.sealWithPassphrase(
                            passphrase, kdfParameters, nonce, bodyBytes, headerBytes);

            byte[] algorithmBytes = utf8(ShareFormat.AEAD_ALGORITHM);
            int envelopeSize = 1 + 2 + algorithmBytes.length + 4 + ciphertext.length;
            ByteBuffer envelope = ByteBuffer.allocate(envelopeSize);
            envelope.put((byte) ShareFormat.ENVELOPE_VERSION);
            putU16Bytes(envelope, algorithmBytes);
            putS32Bytes(envelope, ciphertext);
            if (envelope.hasRemaining()) {
                throw new AssertionError("Envelope size miscomputed");
            }
            byte[] envelopeBytes = envelope.array();

            ByteBuffer full = ByteBuffer.allocate(headerBytes.length + envelopeBytes.length);
            full.put(headerBytes);
            full.put(envelopeBytes);
            return ShareFormat.PREFIX + BASE64URL.encodeToString(full.array());
        } finally {
            for (byte[] vb : valueBytes) {
                Wipe.wipe(vb);
            }
            if (noteBytes != null) {
                Wipe.wipe(noteBytes);
            }
            Wipe.wipe(bodyBytes);
            // salt and nonce are not secret; they travel in the plaintext header.
        }
    }

    static @NonNull ShareContents decode(
            @NonNull String encoded,
            char @NonNull [] passphrase,
            @NonNull DefaultCryptoService crypto,
            @NonNull Clock clock) {
        Objects.requireNonNull(encoded, "encoded");
        Objects.requireNonNull(crypto, "crypto");
        Objects.requireNonNull(clock, "clock");
        if (!encoded.startsWith(ShareFormat.PREFIX)) {
            throw new ValidationException("Not a keystead share string");
        }
        if (encoded.length() > SecurityLimits.SHARE_MAX_BODY_BYTES * 2 + 4096) {
            // Bound the input before base64 allocation to avoid a DoS via an oversized string.
            throw new ValidationException("Share string is too large");
        }
        byte[] all;
        try {
            all = BASE64URL_DECODER.decode(encoded.substring(ShareFormat.PREFIX.length()));
        } catch (IllegalArgumentException e) {
            throw new ValidationException("Share string is not valid base64url", e);
        }
        if (all.length > SecurityLimits.SHARE_MAX_BODY_BYTES + 4096) {
            throw new ValidationException("Share string is too large");
        }

        ByteBuffer buf = ByteBuffer.wrap(all);
        byte[] salt = null;
        byte[] nonce = null;
        byte[] ciphertext = null;
        byte[] bodyBytes = null;
        try {
            byte[] magic = new byte[ShareFormat.MAGIC.length];
            readFully(buf, magic);
            if (!bytesEqual(magic, ShareFormat.MAGIC)) {
                throw new ValidationException("Share magic is invalid");
            }
            int version = readByte(buf);
            if (version != ShareFormat.VERSION) {
                throw new ValidationException("Unsupported share version: " + version);
            }
            String kdfAlgorithm = readU16String(buf);
            if (!ShareFormat.KDF_ALGORITHM.equals(kdfAlgorithm)) {
                throw new ValidationException("Unsupported share KDF algorithm: " + kdfAlgorithm);
            }
            salt = readU8Bytes(buf);
            if (salt.length < 1 || salt.length > SecurityLimits.MAX_KDF_SALT_BYTES) {
                throw new ValidationException("Share KDF salt has invalid length");
            }
            int iterations = readInt(buf);
            // Decode accepts any positive count up to the absolute maximum; it deliberately does
            // NOT enforce the mint-side minimum, so raising that minimum never invalidates shares
            // minted under an older floor.
            if (iterations < 1 || iterations > SecurityLimits.MAX_PBKDF2_ITERATIONS) {
                throw new ValidationException("Share KDF iterations are out of range");
            }
            nonce = readU8Bytes(buf);
            int headerEnd = buf.position();
            byte[] aad = new byte[headerEnd];
            System.arraycopy(all, 0, aad, 0, headerEnd);

            int envelopeVersion = readByte(buf);
            if (envelopeVersion != ShareFormat.ENVELOPE_VERSION) {
                throw new ValidationException(
                        "Unsupported share envelope version: " + envelopeVersion);
            }
            String algorithm = readU16String(buf);
            if (!ShareFormat.AEAD_ALGORITHM.equals(algorithm)) {
                throw new ValidationException("Unsupported share AEAD algorithm: " + algorithm);
            }
            ciphertext = readS32Bytes(buf, SecurityLimits.SHARE_MAX_BODY_BYTES + 16);
            if (buf.hasRemaining()) {
                throw new ValidationException("Share has trailing data");
            }

            KdfParameters kdfParameters = KdfParameters.pbkdf2(kdfAlgorithm, salt, iterations);
            bodyBytes =
                    crypto.openWithPassphrase(passphrase, kdfParameters, nonce, ciphertext, aad);

            ByteBuffer body = ByteBuffer.wrap(bodyBytes);
            int bodyVersion = readByte(body);
            if (bodyVersion != ShareFormat.BODY_VERSION) {
                throw new ValidationException("Unsupported share body version: " + bodyVersion);
            }
            String shareId = readU16String(body);
            if (shareId.isBlank()) {
                throw new ValidationException("Share id is blank");
            }
            String secretTypeName = readU16String(body);
            SecretType secretType = parseSecretType(secretTypeName);
            String title = readU16String(body);
            if (title.length() > SecurityLimits.SHARE_MAX_TITLE_CHARACTERS) {
                throw new ValidationException("Share title exceeds maximum length");
            }
            int fieldCount = readInt(body);
            if (fieldCount < 0 || fieldCount > SecurityLimits.SHARE_MAX_FIELD_COUNT) {
                throw new ValidationException("Share field count is out of range");
            }
            Map<String, String> fields = new TreeMap<>();
            for (int i = 0; i < fieldCount; i++) {
                String name = readU16String(body);
                if (name.isBlank()
                        || name.length() > SecurityLimits.SHARE_MAX_FIELD_NAME_CHARACTERS) {
                    throw new ValidationException("Invalid share field name");
                }
                String value = readU16String(body);
                if (value.getBytes(StandardCharsets.UTF_8).length
                        > SecurityLimits.SHARE_MAX_FIELD_VALUE_BYTES) {
                    throw new ValidationException("Share field value exceeds maximum size");
                }
                if (fields.put(name, value) != null) {
                    throw new ValidationException("Duplicate share field name: " + name);
                }
            }
            boolean hasNote = readByte(body) != 0;
            String sharerNote = null;
            if (hasNote) {
                sharerNote = readU16String(body);
                if (sharerNote.length() > SecurityLimits.SHARE_MAX_NOTE_CHARACTERS) {
                    throw new ValidationException("Share note exceeds maximum length");
                }
            }
            Instant createdAt = readInstant(body);
            boolean hasExpiresAt = readByte(body) != 0;
            Instant expiresAt = null;
            if (hasExpiresAt) {
                expiresAt = readInstant(body);
            }
            if (body.hasRemaining()) {
                throw new ValidationException("Share body has trailing data");
            }

            if (expiresAt != null && clock.instant().isAfter(expiresAt)) {
                throw new ValidationException("Share has expired");
            }
            return new ShareContents(
                    shareId, secretType, title, fields, sharerNote, createdAt, expiresAt);
        } catch (BufferUnderflowException e) {
            throw new ValidationException("Share is truncated or malformed", e);
        } finally {
            Wipe.wipe(bodyBytes);
            Wipe.wipe(ciphertext);
            Wipe.wipe(salt);
            Wipe.wipe(nonce);
        }
    }

    private static @NonNull SecretType parseSecretType(@NonNull String name) {
        try {
            return SecretType.valueOf(name);
        } catch (IllegalArgumentException e) {
            throw new ValidationException("Unknown share secret type: " + name, e);
        }
    }

    // ---- low-level writers ----

    private static byte @NonNull [] utf8(@NonNull String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static int u16StringSize(@NonNull String s) {
        int len = utf8(s).length;
        if (len > 0xFFFF) {
            throw new ValidationException("String exceeds maximum encoded length");
        }
        return 2 + len;
    }

    private static void putU16String(@NonNull ByteBuffer buf, @NonNull String s) {
        putU16Bytes(buf, utf8(s));
    }

    private static void putU16Bytes(@NonNull ByteBuffer buf, byte @NonNull [] b) {
        if (b.length > 0xFFFF) {
            throw new ValidationException("String exceeds maximum encoded length");
        }
        buf.putShort((short) b.length);
        buf.put(b);
    }

    private static void putU8Bytes(@NonNull ByteBuffer buf, byte @NonNull [] b) {
        if (b.length > 0xFF) {
            throw new ValidationException("Byte array exceeds u8 length");
        }
        buf.put((byte) b.length);
        buf.put(b);
    }

    private static void putS32Bytes(@NonNull ByteBuffer buf, byte @NonNull [] b) {
        buf.putInt(b.length);
        buf.put(b);
    }

    private static void putInstant(@NonNull ByteBuffer buf, @NonNull Instant instant) {
        buf.putLong(instant.getEpochSecond());
        buf.putInt(instant.getNano());
    }

    // ---- low-level readers ----

    private static void readFully(@NonNull ByteBuffer buf, byte @NonNull [] dst) {
        buf.get(dst);
    }

    private static int readByte(@NonNull ByteBuffer buf) {
        return buf.get() & 0xFF;
    }

    private static int readInt(@NonNull ByteBuffer buf) {
        return buf.getInt();
    }

    private static @NonNull String readU16String(@NonNull ByteBuffer buf) {
        int len = buf.getShort() & 0xFFFF;
        byte[] b = new byte[len];
        buf.get(b);
        return new String(b, StandardCharsets.UTF_8);
    }

    private static byte @NonNull [] readU8Bytes(@NonNull ByteBuffer buf) {
        int len = buf.get() & 0xFF;
        byte[] b = new byte[len];
        buf.get(b);
        return b;
    }

    private static byte @NonNull [] readS32Bytes(@NonNull ByteBuffer buf, int max) {
        int len = buf.getInt();
        if (len < 0 || len > max) {
            throw new ValidationException("Byte array length is out of range");
        }
        byte[] b = new byte[len];
        buf.get(b);
        return b;
    }

    private static @NonNull Instant readInstant(@NonNull ByteBuffer buf) {
        long seconds = buf.getLong();
        int nanos = buf.getInt();
        if (nanos < 0 || nanos > 999_999_999) {
            throw new ValidationException("Instant nanos are out of range");
        }
        try {
            return Instant.ofEpochSecond(seconds, nanos);
        } catch (DateTimeException e) {
            throw new ValidationException("Instant is out of range", e);
        }
    }

    private static boolean bytesEqual(byte @NonNull [] a, byte @NonNull [] b) {
        if (a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    private ShareCodec() {
        throw new AssertionError("No instances");
    }
}
