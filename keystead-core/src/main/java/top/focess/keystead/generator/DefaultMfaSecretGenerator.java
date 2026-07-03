package top.focess.keystead.generator;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

public final class DefaultMfaSecretGenerator implements MfaSecretGenerator {

    private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    private final SecureRandom random;

    public DefaultMfaSecretGenerator() {
        this(new SecureRandom());
    }

    public DefaultMfaSecretGenerator(@NonNull SecureRandom random) {
        this.random = Objects.requireNonNull(random, "random");
    }

    @Override
    public @NonNull MfaSecret generate(@NonNull MfaSecretPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        byte[] secret = new byte[policy.secretBytes()];
        char[] seed = null;
        char[] uri = null;
        try {
            random.nextBytes(secret);
            seed = base32(secret);
            uri = otpauthUri(policy, seed);
            return new MfaSecret(SecretBuffer.fromChars(seed), SecretBuffer.fromChars(uri));
        } finally {
            Arrays.fill(secret, (byte) 0);
            if (seed != null) {
                Arrays.fill(seed, '\0');
            }
            if (uri != null) {
                Arrays.fill(uri, '\0');
            }
        }
    }

    private char @NonNull [] base32(byte @NonNull [] secret) {
        StringBuilder builder = new StringBuilder((secret.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte value : secret) {
            buffer = (buffer << 8) | (value & 0xff);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                builder.append(BASE32[(buffer >> (bitsLeft - 5)) & 0x1f]);
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            builder.append(BASE32[(buffer << (5 - bitsLeft)) & 0x1f]);
        }
        char[] output = new char[builder.length()];
        builder.getChars(0, builder.length(), output, 0);
        return output;
    }

    private char @NonNull [] otpauthUri(@NonNull MfaSecretPolicy policy, char @NonNull [] seed) {
        String label = encode(policy.issuer() + ":" + policy.accountName());
        String issuer = encode(policy.issuer());
        String prefix = "otpauth://totp/" + label + "?secret=";
        String suffix =
                "&issuer="
                        + issuer
                        + "&algorithm=SHA1&digits="
                        + policy.digits()
                        + "&period="
                        + policy.periodSeconds();
        char[] output = new char[prefix.length() + seed.length + suffix.length()];
        int offset = append(output, 0, prefix);
        System.arraycopy(seed, 0, output, offset, seed.length);
        append(output, offset + seed.length, suffix);
        return output;
    }

    private @NonNull String encode(@NonNull String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private int append(char @NonNull [] target, int offset, @NonNull String value) {
        value.getChars(0, value.length(), target, offset);
        return offset + value.length();
    }
}
