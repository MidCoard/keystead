package top.focess.keystead.store;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecurityLimits;
import top.focess.keystead.model.VaultFingerprint;

/**
 * On-disk format for a v2 single-file vault.
 *
 * <p>A vault file is one opaque container: a plaintext header (magic, format version, KDF parameters,
 * wrapped vault key, timestamps) followed by a single authenticated-encryption envelope whose
 * ciphertext is the encrypted vault body and whose additional-authenticated data is the entire
 * plaintext header. The envelope tag is therefore a whole-vault MAC: any tampering with the header
 * or the ciphertext is detected on open, and a wrong passphrase fails the tag cleanly.
 *
 * <p>No vault id is stored. The vault's routing identity is the {@link VaultFingerprint}, derived at
 * unlock from the passphrase and KDF salt (see {@link DefaultCryptoService#deriveFingerprint}); it is
 * not persisted.
 *
 * <p>Layout (big-endian, all lengths unsigned):
 * <pre>
 *   HEADER (plaintext; also the container AAD)
 *     magic[6]            "KSTEAD"
 *     version[1]          2
 *     kdfAlgorithm        u16 len + UTF-8
 *     kdfSalt             u16 len + bytes
 *     kdfIterations       s32
 *     vaultKeyId          u16 len + UTF-8
 *     wrappedVaultKey     s32 len + bytes
 *     createdAt           s64 epochSeconds + s32 nanos
 *     updatedAt           s64 epochSeconds + s32 nanos
 *   ENVELOPE (ciphertext; AAD is not stored, it is recomputed from the header)
 *     envelopeVersion[1]  1
 *     algorithm           u16 len + UTF-8
 *     keyId               u16 len + UTF-8
 *     nonce               u8 len + bytes
 *     ciphertext          s32 len + bytes
 *     encryptedAt         s64 epochSeconds + s32 nanos
 * </pre>
 *
 * <p>This codec is format-only: it serializes and parses the container and performs the unlock
 * (unwrap the vault key, derive the fingerprint, decrypt the body). The structured layout of the
 * decrypted body (records, tombstones, revisions) is defined by the vault store layer.
 */
public final class VaultFileFormat {

    /** Magic bytes prefixing every v2 vault file. */
    public static final byte @NonNull [] MAGIC = "KSTEAD".getBytes(StandardCharsets.US_ASCII);

    /** Current vault file format version. */
    public static final int FORMAT_VERSION = 2;

    /** Upper bound on an envelope nonce (the on-disk length is a single byte, so this is 255). */
    private static final int MAX_NONCE_BYTES = 0xFF;

    private VaultFileFormat() {}

    /** Plaintext vault header fields. The wrapped-key bytes are defensively copied. */
    public record Header(
            int formatVersion,
            @NonNull KdfParameters kdfParameters,
            @NonNull KeyId vaultKeyId,
            byte @NonNull [] wrappedVaultKey,
            @NonNull Instant createdAt,
            @NonNull Instant updatedAt) {

        /** Validates the record components. */
        public Header {
            Objects.requireNonNull(kdfParameters, "kdfParameters");
            Objects.requireNonNull(vaultKeyId, "vaultKeyId");
            Objects.requireNonNull(wrappedVaultKey, "wrappedVaultKey");
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (formatVersion <= 0) {
                throw new IllegalArgumentException("Format version must be positive");
            }
            if (updatedAt.isBefore(createdAt)) {
                throw new IllegalArgumentException(
                        "Vault updated time must not be before created time");
            }
            if (wrappedVaultKey.length > SecurityLimits.MAX_WRAPPED_KEY_PACKAGE_BYTES) {
                throw new IllegalArgumentException("Wrapped vault key exceeds the size limit");
            }
            wrappedVaultKey = Arrays.copyOf(wrappedVaultKey, wrappedVaultKey.length);
        }

        /** Returns a defensive copy of the wrapped vault key.
         *
         * @return a defensive copy of the wrapped vault key */
        @Override
        public byte @NonNull [] wrappedVaultKey() {
            return Arrays.copyOf(wrappedVaultKey, wrappedVaultKey.length);
        }

        @Override
        public @NonNull String toString() {
            return "Header[formatVersion=%d, kdfParameters=%s, vaultKeyId=%s, wrappedVaultKey=[REDACTED %d bytes], createdAt=%s, updatedAt=%s]"
                    .formatted(
                            formatVersion,
                            kdfParameters,
                            vaultKeyId,
                            wrappedVaultKey.length,
                            createdAt,
                            updatedAt);
        }
    }

    /** Result of opening a vault file: the parsed header, unlocked vault key, fingerprint, and body. */
    public record OpenedFile(
            @NonNull Header header,
            @NonNull VaultKey vaultKey,
            @NonNull VaultFingerprint fingerprint,
            byte @NonNull [] containerBody) {

        /** Validates the record components. */
        public OpenedFile {
            Objects.requireNonNull(header, "header");
            Objects.requireNonNull(vaultKey, "vaultKey");
            Objects.requireNonNull(fingerprint, "fingerprint");
            Objects.requireNonNull(containerBody, "containerBody");
            containerBody = Arrays.copyOf(containerBody, containerBody.length);
        }

        /** Returns a defensive copy of the decrypted container body.
         *
         * @return a defensive copy of the decrypted container body */
        @Override
        public byte @NonNull [] containerBody() {
            return Arrays.copyOf(containerBody, containerBody.length);
        }
    }

    /**
     * Serializes a vault file from a header, an unlocked vault key, and the plaintext container body.
     *
     * <p>The vault key id must match the header's vault key id. The container body is encrypted under
     * the vault key, authenticated by the serialized header bytes, and appended after the header.
     *
     * @param crypto the cryptographic service
     * @param header the plaintext vault header
     * @param vaultKey the unlocked vault key protecting the body
     * @param containerBody the plaintext vault body
     * @param encryptedAt the encryption timestamp
     * @return the serialized vault file bytes
     */
    public static byte @NonNull [] write(
            @NonNull DefaultCryptoService crypto,
            @NonNull Header header,
            @NonNull VaultKey vaultKey,
            byte @NonNull [] containerBody,
            @NonNull Instant encryptedAt) {
        Objects.requireNonNull(crypto, "crypto");
        Objects.requireNonNull(header, "header");
        Objects.requireNonNull(vaultKey, "vaultKey");
        Objects.requireNonNull(containerBody, "containerBody");
        Objects.requireNonNull(encryptedAt, "encryptedAt");
        if (!vaultKey.keyId().equals(header.vaultKeyId())) {
            throw new IllegalArgumentException("Vault key id does not match header vault key id");
        }
        byte[] headerBytes = serializeHeader(header);
        EncryptedEnvelope envelope =
                crypto.encrypt(vaultKey, containerBody, headerBytes, encryptedAt);
        byte[] envelopeBytes = serializeEnvelope(envelope);
        byte[] file = new byte[headerBytes.length + envelopeBytes.length];
        System.arraycopy(headerBytes, 0, file, 0, headerBytes.length);
        System.arraycopy(envelopeBytes, 0, file, headerBytes.length, envelopeBytes.length);
        return file;
    }

    /**
     * Opens a vault file with a passphrase, returning the parsed header, unlocked vault key,
     * fingerprint, and decrypted body.
     *
     * <p>A wrong passphrase, a tampered header, or a tampered ciphertext fails the whole-vault
     * authentication tag and throws {@link CryptoException}. A truncated file or an unrecognized
     * magic/version throws {@link StoreException}.
     *
     * @param crypto the cryptographic service
     * @param file the serialized vault file bytes
     * @param masterPassword caller-owned master password
     * @return the opened vault file
     */
    public static @NonNull OpenedFile open(
            @NonNull DefaultCryptoService crypto,
            byte @NonNull [] file,
            char @NonNull [] masterPassword) {
        Objects.requireNonNull(crypto, "crypto");
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(masterPassword, "masterPassword");
        ByteBuffer buffer = ByteBuffer.wrap(file);
        try {
            int headerStart = buffer.position();
            byte[] magic = new byte[MAGIC.length];
            buffer.get(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new StoreException("Not a keystead vault file (bad magic)", null);
            }
            int version = buffer.get() & 0xFF;
            if (version != FORMAT_VERSION) {
                throw new StoreException("Unsupported vault format version: " + version, null);
            }
            String kdfAlgorithm = readShortString(buffer);
            byte[] salt = readBytes(buffer, 2, SecurityLimits.MAX_KDF_SALT_BYTES);
            int iterations = buffer.getInt();
            KdfParameters kdfParameters = KdfParameters.pbkdf2(kdfAlgorithm, salt, iterations);
            KeyId vaultKeyId = new KeyId(readShortString(buffer));
            byte[] wrappedVaultKey =
                    readBytes(buffer, 4, SecurityLimits.MAX_WRAPPED_KEY_PACKAGE_BYTES);
            Instant createdAt = readInstant(buffer);
            Instant updatedAt = readInstant(buffer);
            int headerEnd = buffer.position();
            byte[] headerBytes = Arrays.copyOfRange(file, headerStart, headerEnd);
            Header header =
                    new Header(
                            version,
                            kdfParameters,
                            vaultKeyId,
                            wrappedVaultKey,
                            createdAt,
                            updatedAt);

            int envelopeVersion = buffer.get() & 0xFF;
            if (envelopeVersion != 1) {
                throw new StoreException("Unsupported envelope version: " + envelopeVersion, null);
            }
            String algorithm = readShortString(buffer);
            KeyId envelopeKeyId = new KeyId(readShortString(buffer));
            byte[] nonce = readBytes(buffer, 1, MAX_NONCE_BYTES);
            byte[] ciphertext = readBytes(buffer, 4, SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES);
            Instant encryptedAt = readInstant(buffer);
            EncryptedEnvelope envelope =
                    new EncryptedEnvelope(
                            envelopeVersion,
                            algorithm,
                            envelopeKeyId,
                            nonce,
                            headerBytes,
                            ciphertext,
                            encryptedAt);

            // TODO(v2-landing-2): combine unwrap + fingerprint into a single password-KDF pass.
            VaultKey vaultKey =
                    crypto.unwrapVaultKey(
                            vaultKeyId, wrappedVaultKey, masterPassword, kdfParameters);
            try {
                VaultFingerprint fingerprint =
                        crypto.deriveFingerprint(masterPassword, kdfParameters);
                byte[] body = crypto.decrypt(vaultKey, envelope, headerBytes);
                return new OpenedFile(header, vaultKey, fingerprint, body);
            } catch (RuntimeException e) {
                vaultKey.close();
                throw e;
            }
        } catch (BufferUnderflowException e) {
            throw new StoreException("Vault file is truncated", e);
        }
    }

    private static byte @NonNull [] serializeHeader(@NonNull Header header) {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        try (DataOutputStream data = new DataOutputStream(byteOut)) {
            data.write(MAGIC);
            data.writeByte(header.formatVersion());
            writeShortString(data, header.kdfParameters().algorithm());
            writeBytes(data, 2, header.kdfParameters().salt());
            data.writeInt(header.kdfParameters().required(KdfParameters.ITERATIONS));
            writeShortString(data, header.vaultKeyId().value());
            writeBytes(data, 4, header.wrappedVaultKey());
            writeInstant(data, header.createdAt());
            writeInstant(data, header.updatedAt());
        } catch (IOException e) {
            throw new StoreException("Could not serialize vault header", e);
        }
        return byteOut.toByteArray();
    }

    private static byte @NonNull [] serializeEnvelope(@NonNull EncryptedEnvelope envelope) {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        try (DataOutputStream data = new DataOutputStream(byteOut)) {
            data.writeByte(envelope.version());
            writeShortString(data, envelope.algorithm());
            writeShortString(data, envelope.keyId().value());
            writeBytes(data, 1, envelope.nonce());
            writeBytes(data, 4, envelope.ciphertext());
            writeInstant(data, envelope.encryptedAt());
            // The AAD is the header bytes already present in the file; it is not stored here.
        } catch (IOException e) {
            throw new StoreException("Could not serialize vault envelope", e);
        }
        return byteOut.toByteArray();
    }

    private static void writeShortString(@NonNull DataOutputStream data, @NonNull String value)
            throws IOException {
        byte[] utf = value.getBytes(StandardCharsets.UTF_8);
        if (utf.length > 0xFFFF) {
            throw new IOException("String exceeds 65535 bytes");
        }
        data.writeShort(utf.length);
        data.write(utf);
    }

    private static void writeBytes(
            @NonNull DataOutputStream data, int lengthBytes, byte @NonNull [] bytes)
            throws IOException {
        long length = bytes.length;
        if (lengthBytes == 1) {
            if (length > 0xFF) {
                throw new IOException("Byte field exceeds 255 bytes");
            }
            data.writeByte((int) length);
        } else if (lengthBytes == 2) {
            if (length > 0xFFFF) {
                throw new IOException("Byte field exceeds 65535 bytes");
            }
            data.writeShort((int) length);
        } else if (lengthBytes == 4) {
            data.writeInt((int) length);
        } else {
            throw new AssertionError("Unsupported length size: " + lengthBytes);
        }
        data.write(bytes);
    }

    private static void writeInstant(@NonNull DataOutputStream data, @NonNull Instant instant)
            throws IOException {
        data.writeLong(instant.getEpochSecond());
        data.writeInt(instant.getNano());
    }

    private static @NonNull String readShortString(@NonNull ByteBuffer buffer) {
        int length = buffer.getShort() & 0xFFFF;
        byte[] utf = new byte[length];
        buffer.get(utf);
        return new String(utf, StandardCharsets.UTF_8);
    }

    private static byte @NonNull [] readBytes(
            @NonNull ByteBuffer buffer, int lengthBytes, int maxLength) {
        long length;
        if (lengthBytes == 1) {
            length = buffer.get() & 0xFFL;
        } else if (lengthBytes == 2) {
            length = buffer.getShort() & 0xFFFFL;
        } else if (lengthBytes == 4) {
            length = buffer.getInt() & 0xFFFFFFFFL;
        } else {
            throw new AssertionError("Unsupported length size: " + lengthBytes);
        }
        if (length > maxLength) {
            throw new StoreException("Vault field exceeds the size limit", null);
        }
        byte[] bytes = new byte[(int) length];
        buffer.get(bytes);
        return bytes;
    }

    private static @NonNull Instant readInstant(@NonNull ByteBuffer buffer) {
        long epochSecond = buffer.getLong();
        int nanos = buffer.getInt();
        return Instant.ofEpochSecond(epochSecond, nanos);
    }
}
