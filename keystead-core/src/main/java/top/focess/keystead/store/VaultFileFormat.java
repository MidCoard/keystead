package top.focess.keystead.store;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.KeySlot;
import top.focess.keystead.model.SecurityLimits;
import top.focess.keystead.model.SlotType;
import top.focess.keystead.model.VaultFingerprint;
import top.focess.keystead.model.VaultHeader;

/**
 * On-disk format for a v2 single-file vault.
 *
 * <p>A vault file is one opaque container: a plaintext multi-slot header (magic, format version,
 * fingerprint, vault key id, key slots, timestamps) followed by a single authenticated-encryption
 * envelope whose ciphertext is the encrypted vault body and whose additional-authenticated data is
 * the entire plaintext header. The envelope tag is therefore a whole-vault MAC: any tampering with
 * the header, the slots, the fingerprint, or the ciphertext is detected on open, and a wrong
 * passphrase fails the tag cleanly.
 *
 * <p><b>Multi-slot header.</b> The same data-encryption key (DEK) is wrapped under one or more
 * independent {@link KeySlot slots}: a {@link SlotType#PASSPHRASE PASSPHRASE} slot (DEK wrapped
 * under an Argon2id passphrase key), zero or more {@link SlotType#DEVICE DEVICE} slots (DEK wrapped
 * to a device public key via hybrid encryption), and zero or more {@link SlotType#RECOVERY
 * RECOVERY} slots. Any single slot unlocks the vault. A passphrase-less open (device or recovery)
 * reads the {@link VaultFingerprint fingerprint} from the header - it cannot derive it without the
 * passphrase wrapping key.
 *
 * <p>The {@link VaultFingerprint} is a <em>non-secret</em> routing identity, stored in the plaintext
 * header so that passphrase-less opens can recover it. It is integrity-protected by the container
 * AEAD tag (the header is the AAD); offline passphrase protection rests on the Argon2id-gated
 * wrapped DEK, not on fingerprint secrecy.
 *
 * <p>Layout (big-endian, all lengths unsigned):
 * <pre>
 *   HEADER (plaintext; also the container AAD)
 *     magic[6]            "KSTEAD"
 *     version[1]          2
 *     fingerprint[16]     HMAC-SHA-256(wrappingKey, label ‖ kdfSalt), low 128 bits
 *     vaultKeyId          u16 len + UTF-8
 *     slotCount           u16
 *     slots[slotCount]:
 *       slotType[1]       1=PASSPHRASE, 2=DEVICE, 3=RECOVERY
 *       slotKeyId         u16 len + UTF-8
 *       kdfAlgorithm      u16 len + UTF-8   (PASSPHRASE only; empty otherwise)
 *       kdfSalt           u16 len + bytes   (PASSPHRASE only; empty otherwise)
 *       kdfParamCount     u16
 *       kdfParams[]:      u16 len + UTF-8 name, s32 value
 *       wrappedVaultKey   s32 len + bytes
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
 * (satisfy a slot to recover the DEK, read or derive the fingerprint, decrypt the body). The
 * structured layout of the decrypted body (records, tombstones, revisions) is defined by the vault
 * store layer.
 */
public final class VaultFileFormat {

    /** Magic bytes prefixing every v2 vault file. */
    public static final byte @NonNull [] MAGIC = "KSTEAD".getBytes(StandardCharsets.US_ASCII);

    /** Current vault file format version. */
    public static final int FORMAT_VERSION = 2;

    /** Upper bound on an envelope nonce (the on-disk length is a single byte, so this is 255). */
    private static final int MAX_NONCE_BYTES = 0xFF;

    private VaultFileFormat() {}

    /** Result of opening a vault file: the parsed header, unlocked vault key, fingerprint, and body. */
    public record OpenedFile(
            @NonNull VaultHeader header,
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
            @NonNull VaultHeader header,
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
     * <p>The first {@link SlotType#PASSPHRASE} slot is satisfied: the wrapping key is derived from the
     * passphrase and the slot's KDF parameters, and the DEK is unwrapped. The wrapping key's AEAD tag
     * authenticates the passphrase, so a wrong passphrase, a tampered header, or a tampered ciphertext
     * fails the whole-vault authentication tag and throws {@link CryptoException}. The fingerprint is
     * read directly from the integrity-protected header (it is not re-derived on open). A truncated
     * file or an unrecognized magic/version throws {@link StoreException}.
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
        VaultHeader header = parseHeader(buffer);
        byte[] headerBytes = Arrays.copyOfRange(file, 0, buffer.position());
        EncryptedEnvelope envelope = parseEnvelope(buffer, headerBytes);
        KeySlot passphraseSlot =
                header.firstPassphraseSlot()
                        .orElseThrow(() -> new CryptoException("Vault has no passphrase key slot"));
        VaultKey vaultKey =
                crypto.unwrapVaultKey(
                        header.vaultKeyId(),
                        passphraseSlot.wrappedVaultKey(),
                        masterPassword,
                        passphraseSlot.kdfParameters());
        try {
            byte[] body = crypto.decrypt(vaultKey, envelope, headerBytes);
            return new OpenedFile(header, vaultKey, header.fingerprint(), body);
        } catch (RuntimeException e) {
            vaultKey.close();
            throw e;
        }
    }

    /**
     * Opens a vault file with a pre-derived vault key (DEK), for passphrase-less device or recovery
     * opens. The DEK must have been unwrapped from a {@link SlotType#DEVICE} or {@link SlotType#RECOVERY}
     * slot (or a server-stored key package) by the caller. The fingerprint is read from the header.
     *
     * @param crypto the cryptographic service
     * @param file the serialized vault file bytes
     * @param vaultKey the unlocked vault key (DEK)
     * @return the opened vault file
     */
    public static @NonNull OpenedFile openWithVaultKey(
            @NonNull DefaultCryptoService crypto,
            byte @NonNull [] file,
            @NonNull VaultKey vaultKey) {
        Objects.requireNonNull(crypto, "crypto");
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(vaultKey, "vaultKey");
        ByteBuffer buffer = ByteBuffer.wrap(file);
        VaultHeader header = parseHeader(buffer);
        if (!vaultKey.keyId().equals(header.vaultKeyId())) {
            throw new CryptoException(
                    "Vault key id "
                            + vaultKey.keyId().value()
                            + " does not match header vault key id "
                            + header.vaultKeyId().value());
        }
        byte[] headerBytes = Arrays.copyOfRange(file, 0, buffer.position());
        EncryptedEnvelope envelope = parseEnvelope(buffer, headerBytes);
        byte[] body = crypto.decrypt(vaultKey, envelope, headerBytes);
        return new OpenedFile(header, vaultKey, header.fingerprint(), body);
    }

    /**
     * Parses only the plaintext header from a vault file, without recovering the data-encryption
     * key or decrypting the body. Used by passphrase-less device and recovery opens, which must
     * inspect the slots to select a recipient before unwrapping the DEK, and then call {@link
     * #openWithVaultKey} with the recovered key.
     *
     * @param file the serialized vault file bytes
     * @return the parsed vault header
     */
    public static @NonNull VaultHeader readHeader(byte @NonNull [] file) {
        Objects.requireNonNull(file, "file");
        return parseHeader(ByteBuffer.wrap(file));
    }

    private static @NonNull VaultHeader parseHeader(@NonNull ByteBuffer buffer) {
        try {
            byte[] magic = new byte[MAGIC.length];
            buffer.get(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new StoreException("Not a keystead vault file (bad magic)", null);
            }
            int version = buffer.get() & 0xFF;
            if (version != FORMAT_VERSION) {
                throw new StoreException("Unsupported vault format version: " + version, null);
            }
            byte[] fingerprintBytes = new byte[VaultFingerprint.BYTES];
            buffer.get(fingerprintBytes);
            VaultFingerprint fingerprint = new VaultFingerprint(fingerprintBytes);
            KeyId vaultKeyId = new KeyId(readShortString(buffer));
            int slotCount = buffer.getShort() & 0xFFFF;
            if (slotCount == 0 || slotCount > VaultHeader.MAX_SLOTS) {
                throw new StoreException("Invalid vault key slot count: " + slotCount, null);
            }
            List<KeySlot> slots = new ArrayList<>(slotCount);
            for (int i = 0; i < slotCount; i++) {
                slots.add(parseSlot(buffer));
            }
            Instant createdAt = readInstant(buffer);
            Instant updatedAt = readInstant(buffer);
            return new VaultHeader(
                    version,
                    fingerprint,
                    vaultKeyId,
                    Collections.unmodifiableList(slots),
                    createdAt,
                    updatedAt);
        } catch (BufferUnderflowException e) {
            throw new StoreException("Vault file is truncated", e);
        }
    }

    private static @NonNull KeySlot parseSlot(@NonNull ByteBuffer buffer) {
        SlotType slotType;
        try {
            slotType = SlotType.fromCode(buffer.get() & 0xFF);
        } catch (IllegalArgumentException e) {
            throw new StoreException("Unknown key slot type", e);
        }
        KeyId slotKeyId = new KeyId(readShortString(buffer));
        String kdfAlgorithm = readShortString(buffer);
        KdfParameters kdfParameters = null;
        if (!kdfAlgorithm.isEmpty()) {
            byte[] salt = readBytes(buffer, 2, SecurityLimits.MAX_KDF_SALT_BYTES);
            int paramCount = buffer.getShort() & 0xFFFF;
            if (paramCount > SecurityLimits.MAX_KDF_PARAMETER_ENTRIES) {
                throw new StoreException("KDF parameter count exceeds the size limit", null);
            }
            java.util.Map<String, Integer> params = new java.util.LinkedHashMap<>(paramCount);
            for (int i = 0; i < paramCount; i++) {
                String name = readShortString(buffer);
                int value = buffer.getInt();
                params.put(name, value);
            }
            kdfParameters = new KdfParameters(kdfAlgorithm, salt, params);
        } else {
            // Non-passphrase slots carry no KDF salt; skip the empty salt and zero params.
            readBytes(buffer, 2, SecurityLimits.MAX_KDF_SALT_BYTES);
            int paramCount = buffer.getShort() & 0xFFFF;
            if (paramCount != 0) {
                throw new StoreException(
                        "Non-passphrase key slot must not carry KDF parameters", null);
            }
        }
        byte[] wrappedVaultKey = readBytes(buffer, 4, SecurityLimits.MAX_WRAPPED_KEY_PACKAGE_BYTES);
        return new KeySlot(slotType, slotKeyId, kdfParameters, wrappedVaultKey);
    }

    private static @NonNull EncryptedEnvelope parseEnvelope(
            @NonNull ByteBuffer buffer, byte @NonNull [] headerBytes) {
        try {
            int envelopeVersion = buffer.get() & 0xFF;
            if (envelopeVersion != 1) {
                throw new StoreException("Unsupported envelope version: " + envelopeVersion, null);
            }
            String algorithm = readShortString(buffer);
            KeyId envelopeKeyId = new KeyId(readShortString(buffer));
            byte[] nonce = readBytes(buffer, 1, MAX_NONCE_BYTES);
            byte[] ciphertext = readBytes(buffer, 4, SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES);
            Instant encryptedAt = readInstant(buffer);
            return new EncryptedEnvelope(
                    envelopeVersion,
                    algorithm,
                    envelopeKeyId,
                    nonce,
                    headerBytes,
                    ciphertext,
                    encryptedAt);
        } catch (BufferUnderflowException e) {
            throw new StoreException("Vault envelope is truncated", e);
        }
    }

    private static byte @NonNull [] serializeHeader(@NonNull VaultHeader header) {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        try (DataOutputStream data = new DataOutputStream(byteOut)) {
            data.write(MAGIC);
            data.writeByte(header.formatVersion());
            if (header.fingerprint().value().length != VaultFingerprint.BYTES) {
                throw new IOException("Invalid fingerprint length");
            }
            data.write(header.fingerprint().value());
            writeShortString(data, header.vaultKeyId().value());
            if (header.slots().size() > 0xFFFF) {
                throw new IOException("Too many key slots");
            }
            data.writeShort(header.slots().size());
            for (KeySlot slot : header.slots()) {
                serializeSlot(data, slot);
            }
            writeInstant(data, header.createdAt());
            writeInstant(data, header.updatedAt());
        } catch (IOException e) {
            throw new StoreException("Could not serialize vault header", e);
        }
        return byteOut.toByteArray();
    }

    private static void serializeSlot(@NonNull DataOutputStream data, @NonNull KeySlot slot)
            throws IOException {
        data.writeByte(slot.slotType().code());
        writeShortString(data, slot.slotKeyId().value());
        KdfParameters kdf = slot.kdfParameters();
        if (kdf != null) {
            writeShortString(data, kdf.algorithm());
            writeBytes(data, 2, kdf.salt());
            java.util.Map<String, Integer> params = kdf.parameters();
            if (params.size() > 0xFFFF) {
                throw new IOException("Too many KDF parameters");
            }
            data.writeShort(params.size());
            for (java.util.Map.Entry<String, Integer> entry : params.entrySet()) {
                writeShortString(data, entry.getKey());
                data.writeInt(entry.getValue());
            }
        } else {
            writeShortString(data, "");
            writeBytes(data, 2, new byte[0]);
            data.writeShort(0);
        }
        writeBytes(data, 4, slot.wrappedVaultKey());
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
