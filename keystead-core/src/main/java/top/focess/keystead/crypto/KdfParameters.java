package top.focess.keystead.crypto;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecurityLimits;

public record KdfParameters(
        @NonNull String algorithm,
        byte @NonNull [] salt,
        @NonNull Map<String, Integer> parameters) {

    public static final String ITERATIONS = "iterations";

    public KdfParameters {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(salt, "salt");
        Objects.requireNonNull(parameters, "parameters");
        requireIdentifier(algorithm, "KDF algorithm");
        if (salt.length > SecurityLimits.MAX_KDF_SALT_BYTES) {
            throw new IllegalArgumentException("KDF salt exceeds the size limit");
        }
        if (parameters.size() > SecurityLimits.MAX_KDF_PARAMETER_ENTRIES) {
            throw new IllegalArgumentException("KDF parameter count exceeds the size limit");
        }
        TreeMap<String, Integer> sorted = new TreeMap<>();
        parameters.forEach(
                (name, value) -> {
                    Objects.requireNonNull(name, "KDF parameter name");
                    Objects.requireNonNull(value, "KDF parameter value");
                    requireIdentifier(name, "KDF parameter name");
                    if (value <= 0) {
                        throw new IllegalArgumentException("KDF parameter values must be positive");
                    }
                    sorted.put(name, value);
                });
        salt = Arrays.copyOf(salt, salt.length);
        parameters = Collections.unmodifiableMap(new LinkedHashMap<>(sorted));
    }

    public static @NonNull KdfParameters pbkdf2(
            @NonNull String algorithm, byte @NonNull [] salt, int iterations) {
        return new KdfParameters(algorithm, salt, Map.of(ITERATIONS, iterations));
    }

    public int required(@NonNull String name) {
        Objects.requireNonNull(name, "name");
        Integer value = parameters.get(name);
        if (value == null) {
            throw new IllegalArgumentException("Missing required KDF parameter: " + name);
        }
        return value;
    }

    @Override
    public byte @NonNull [] salt() {
        return Arrays.copyOf(salt, salt.length);
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof KdfParameters other)) {
            return false;
        }
        return algorithm.equals(other.algorithm)
                && Arrays.equals(salt, other.salt)
                && parameters.equals(other.parameters);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(algorithm, parameters) + Arrays.hashCode(salt);
    }

    @Override
    public @NonNull String toString() {
        return "KdfParameters[algorithm=%s, salt=[REDACTED %d bytes], parameters=%s]"
                .formatted(algorithm, salt.length, parameters);
    }

    private static void requireIdentifier(@NonNull String value, @NonNull String description) {
        if (value.isEmpty() || value.length() > SecurityLimits.MAX_KDF_PARAMETER_NAME_CHARACTERS) {
            throw new IllegalArgumentException(description + " has an invalid length");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < 0x21 || character > 0x7e) {
                throw new IllegalArgumentException(description + " must contain printable ASCII");
            }
        }
    }
}
