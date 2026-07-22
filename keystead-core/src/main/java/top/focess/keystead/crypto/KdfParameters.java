package top.focess.keystead.crypto;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecurityLimits;

/**
 * Key-derivation function parameters: the algorithm name, a salt, and positive integer parameters
 * such as an iteration count. The salt is defensively copied and {@link #toString()} redacts it.
 *
 * @param algorithm the KDF algorithm name
 * @param salt the KDF salt
 * @param parameters named positive integer parameters, sorted by name
 */
public record KdfParameters(
        @NonNull String algorithm,
        byte @NonNull [] salt,
        @NonNull Map<String, Integer> parameters) {

    /** The standard parameter name for a KDF iteration count. */
    public static final @NonNull String ITERATIONS = "iterations";

    /** Validates the components, defensively copies the salt, and sorts the parameters. */
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

    /**
     * Creates PBKDF2-style parameters with a single iteration count.
     *
     * @param algorithm the KDF algorithm name
     * @param salt the KDF salt
     * @param iterations the iteration count; must be positive
     * @return the KDF parameters
     */
    public static @NonNull KdfParameters pbkdf2(
            @NonNull String algorithm, byte @NonNull [] salt, int iterations) {
        return new KdfParameters(algorithm, salt, Map.of(ITERATIONS, iterations));
    }

    /**
     * Returns a required named parameter.
     *
     * @param name the parameter name
     * @return the parameter value
     * @throws IllegalArgumentException if the parameter is absent
     */
    public int required(@NonNull String name) {
        Objects.requireNonNull(name, "name");
        Integer value = parameters.get(name);
        if (value == null) {
            throw new IllegalArgumentException("Missing required KDF parameter: " + name);
        }
        return value;
    }

    /**
     * Returns a defensive copy of the KDF salt.
     *
     * @return a defensive copy of the KDF salt
     */
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
