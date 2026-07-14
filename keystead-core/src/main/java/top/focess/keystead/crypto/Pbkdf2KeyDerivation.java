package top.focess.keystead.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecurityLimits;

public final class Pbkdf2KeyDerivation implements PasswordKeyDerivation {

    private final String algorithm;

    public Pbkdf2KeyDerivation(@NonNull String algorithm) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        if (!CryptoAlgorithmRegistry.isApprovedKdf(algorithm)) {
            throw new IllegalArgumentException("Unsupported PBKDF2 algorithm: " + algorithm);
        }
    }

    @Override
    public @NonNull String algorithm() {
        return algorithm;
    }

    @Override
    public byte @NonNull [] derive(
            char @NonNull [] password, @NonNull KdfParameters parameters, int outputBytes) {
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(parameters, "parameters");
        if (!algorithm.equals(parameters.algorithm())) {
            throw new IllegalArgumentException("KDF parameters use a different algorithm");
        }
        if (!parameters.parameters().keySet().equals(Set.of(KdfParameters.ITERATIONS))) {
            throw new IllegalArgumentException("Unsupported PBKDF2 parameters");
        }
        int iterations = parameters.required(KdfParameters.ITERATIONS);
        if (iterations > SecurityLimits.MAX_PBKDF2_ITERATIONS) {
            throw new IllegalArgumentException("PBKDF2 iterations exceed the size limit");
        }
        if (outputBytes <= 0 || outputBytes > Integer.MAX_VALUE / 8) {
            throw new IllegalArgumentException("KDF output size must be positive");
        }
        char[] passwordCopy = Arrays.copyOf(password, password.length);
        byte[] saltCopy = parameters.salt();
        PBEKeySpec spec = new PBEKeySpec(passwordCopy, saltCopy, iterations, outputBytes * 8);
        byte[] result = null;
        try {
            result = SecretKeyFactory.getInstance(algorithm).generateSecret(spec).getEncoded();
            if (result.length != outputBytes) {
                throw new CryptoException("Password KDF returned an invalid key size");
            }
            byte[] output = result;
            result = null;
            return output;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not derive password key", e);
        } finally {
            Arrays.fill(passwordCopy, '\0');
            Arrays.fill(saltCopy, (byte) 0);
            spec.clearPassword();
            if (result != null) {
                Arrays.fill(result, (byte) 0);
            }
        }
    }
}
