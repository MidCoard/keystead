package top.focess.keystead.crypto;

import java.util.Objects;
import java.util.Set;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Strings;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.SecurityLimits;

/**
 * Argon2id {@link PasswordKeyDerivation} backed by Bouncy Castle's {@link Argon2BytesGenerator}.
 *
 * <p>Argon2id is the v2 vault passphrase KDF: it is memory-hard, raising the cost of offline
 * passphrase guessing against a stolen vault file. Parameters are the time cost (iterations), the
 * memory cost in KiB, and the parallelism (lanes).
 */
public final class Argon2idKeyDerivation implements PasswordKeyDerivation {

    /** Creates the derivation for the approved Argon2id algorithm. */
    public Argon2idKeyDerivation() {}

    @Override
    public @NonNull String algorithm() {
        return CryptoAlgorithmRegistry.KDF_ARGON2ID;
    }

    @Override
    public byte @NonNull [] derive(
            char @NonNull [] password, @NonNull KdfParameters parameters, int outputBytes) {
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(parameters, "parameters");
        if (!CryptoAlgorithmRegistry.KDF_ARGON2ID.equals(parameters.algorithm())) {
            throw new IllegalArgumentException("KDF parameters use a different algorithm");
        }
        if (!parameters
                .parameters()
                .keySet()
                .equals(
                        Set.of(
                                KdfParameters.ITERATIONS,
                                KdfParameters.MEMORY_KIB,
                                KdfParameters.PARALLELISM))) {
            throw new IllegalArgumentException("Unsupported Argon2id parameters");
        }
        int iterations = parameters.required(KdfParameters.ITERATIONS);
        int memoryKib = parameters.required(KdfParameters.MEMORY_KIB);
        int parallelism = parameters.required(KdfParameters.PARALLELISM);
        if (iterations < SecurityLimits.MIN_ARGON2ID_ITERATIONS
                || iterations > SecurityLimits.MAX_ARGON2ID_ITERATIONS) {
            throw new IllegalArgumentException("Argon2id iterations are out of range");
        }
        if (memoryKib < SecurityLimits.MIN_ARGON2ID_MEMORY_KIB
                || memoryKib > SecurityLimits.MAX_ARGON2ID_MEMORY_KIB) {
            throw new IllegalArgumentException("Argon2id memory cost is out of range");
        }
        if (parallelism < SecurityLimits.MIN_ARGON2ID_PARALLELISM
                || parallelism > SecurityLimits.MAX_ARGON2ID_PARALLELISM) {
            throw new IllegalArgumentException("Argon2id parallelism is out of range");
        }
        // Argon2 requires the memory cost to be at least 8 * parallelism KiB.
        if (memoryKib < 8L * parallelism) {
            throw new IllegalArgumentException(
                    "Argon2id memory cost must be at least 8 times the parallelism");
        }
        if (outputBytes <= 0) {
            throw new IllegalArgumentException("KDF output size must be positive");
        }

        byte @Nullable [] passwordBytes = null;
        byte @Nullable [] saltCopy = null;
        byte @Nullable [] output = null;
        try {
            passwordBytes = Strings.toUTF8ByteArray(password);
            saltCopy = parameters.salt();
            Argon2Parameters params =
                    new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                            .withSalt(saltCopy)
                            .withIterations(iterations)
                            .withMemoryAsKB(memoryKib)
                            .withParallelism(parallelism)
                            .build();
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(params);
            output = new byte[outputBytes];
            generator.generateBytes(passwordBytes, output);
            byte[] result = output;
            output = null;
            return result;
        } catch (RuntimeException e) {
            throw new CryptoException("Could not derive Argon2id key", e);
        } finally {
            if (passwordBytes != null) {
                Wipe.wipe(passwordBytes);
            }
            if (saltCopy != null) {
                Wipe.wipe(saltCopy);
            }
            if (output != null) {
                Wipe.wipe(output);
            }
        }
    }
}
