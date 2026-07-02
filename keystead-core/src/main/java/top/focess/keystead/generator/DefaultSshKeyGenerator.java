package top.focess.keystead.generator;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.EdECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;

public final class DefaultSshKeyGenerator implements SshKeyGenerator {

    private static final String OPENSSH_ED25519 = "ssh-ed25519";
    private static final int ED25519_PUBLIC_KEY_BYTES = 32;
    private static final int PEM_LINE_LENGTH = 64;

    private final SecureRandom random;

    public DefaultSshKeyGenerator() {
        this(new SecureRandom());
    }

    public DefaultSshKeyGenerator(@NonNull SecureRandom random) {
        this.random = Objects.requireNonNull(random, "random");
    }

    @Override
    public @NonNull SshKeyPair generate(@NonNull SshKeyPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        if (policy.algorithm() != SshKeyAlgorithm.ED25519) {
            throw new IllegalArgumentException(
                    "Unsupported SSH key algorithm: " + policy.algorithm());
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            generator.initialize(255, random);
            java.security.KeyPair keyPair = generator.generateKeyPair();
            return new SshKeyPair(
                    openSshPublicKey((EdECPublicKey) keyPair.getPublic(), policy.comment()),
                    pemPrivateKey(keyPair.getPrivate().getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not generate SSH key pair", e);
        }
    }

    private @NonNull String openSshPublicKey(
            @NonNull EdECPublicKey publicKey, @Nullable String comment) {
        byte[] raw = rawEd25519PublicKey(publicKey);
        byte[] wire = null;
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            writeString(output, OPENSSH_ED25519.getBytes(StandardCharsets.US_ASCII));
            writeString(output, raw);
            wire = output.toByteArray();
            String encoded = Base64.getEncoder().encodeToString(wire);
            if (comment == null) {
                return OPENSSH_ED25519 + " " + encoded;
            }
            return OPENSSH_ED25519 + " " + encoded + " " + comment;
        } finally {
            Arrays.fill(raw, (byte) 0);
            if (wire != null) {
                Arrays.fill(wire, (byte) 0);
            }
        }
    }

    private byte @NonNull [] rawEd25519PublicKey(@NonNull EdECPublicKey publicKey) {
        byte[] bigEndian = fixedWidth(publicKey.getPoint().getY(), ED25519_PUBLIC_KEY_BYTES);
        byte[] littleEndian = bigEndian.clone();
        reverse(littleEndian);
        if (publicKey.getPoint().isXOdd()) {
            littleEndian[ED25519_PUBLIC_KEY_BYTES - 1] |= (byte) 0x80;
        }
        Arrays.fill(bigEndian, (byte) 0);
        return littleEndian;
    }

    private byte @NonNull [] fixedWidth(@NonNull BigInteger value, int size) {
        byte[] source = value.toByteArray();
        byte[] output = new byte[size];
        int sourceOffset = Math.max(0, source.length - size);
        int copyLength = Math.min(source.length, size);
        System.arraycopy(source, sourceOffset, output, size - copyLength, copyLength);
        Arrays.fill(source, (byte) 0);
        return output;
    }

    private @NonNull SecretBuffer pemPrivateKey(byte @NonNull [] encodedPrivateKey) {
        byte[] base64 = null;
        char[] pem = null;
        try {
            base64 =
                    Base64.getMimeEncoder(PEM_LINE_LENGTH, new byte[] {'\n'})
                            .encode(encodedPrivateKey);
            String header = "-----BEGIN PRIVATE KEY-----\n";
            String footer = "\n-----END PRIVATE KEY-----\n";
            pem = new char[header.length() + base64.length + footer.length()];
            int offset = append(pem, 0, header);
            for (byte value : base64) {
                pem[offset++] = (char) value;
            }
            append(pem, offset, footer);
            return SecretBuffer.fromChars(pem);
        } finally {
            Arrays.fill(encodedPrivateKey, (byte) 0);
            if (base64 != null) {
                Arrays.fill(base64, (byte) 0);
            }
            if (pem != null) {
                Arrays.fill(pem, '\0');
            }
        }
    }

    private int append(char @NonNull [] target, int offset, @NonNull String value) {
        value.getChars(0, value.length(), target, offset);
        return offset + value.length();
    }

    private void writeString(@NonNull ByteArrayOutputStream output, byte @NonNull [] value) {
        output.writeBytes(
                ByteBuffer.allocate(Integer.BYTES)
                        .order(ByteOrder.BIG_ENDIAN)
                        .putInt(value.length)
                        .array());
        output.writeBytes(value);
    }

    private void reverse(byte @NonNull [] bytes) {
        for (int i = 0; i < bytes.length / 2; i++) {
            byte value = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = value;
        }
    }
}
