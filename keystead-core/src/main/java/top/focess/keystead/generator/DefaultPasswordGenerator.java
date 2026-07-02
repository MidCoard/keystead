package top.focess.keystead.generator;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

public final class DefaultPasswordGenerator implements PasswordGenerator {

    private static final char[] UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
    private static final char[] LOWERCASE = "abcdefghijklmnopqrstuvwxyz".toCharArray();
    private static final char[] DIGITS = "0123456789".toCharArray();
    private static final char[] SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/".toCharArray();
    private static final char[] AMBIGUOUS = "0O1Il".toCharArray();

    private final SecureRandom random;

    public DefaultPasswordGenerator() {
        this(new SecureRandom());
    }

    public DefaultPasswordGenerator(@NonNull SecureRandom random) {
        this.random = Objects.requireNonNull(random, "random");
    }

    @Override
    public @NonNull SecretBuffer generate(@NonNull PasswordPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        List<char[]> groups = enabledGroups(policy);
        if (groups.isEmpty()) {
            throw new IllegalArgumentException(
                    "At least one password character group must be enabled");
        }
        if (policy.length() < groups.size()) {
            throw new IllegalArgumentException(
                    "Password length is too short for the enabled character groups");
        }

        char[] pool = merge(groups);
        char[] password = new char[policy.length()];
        try {
            int index = 0;
            for (char[] group : groups) {
                password[index++] = pick(group);
            }
            while (index < password.length) {
                password[index++] = pick(pool);
            }
            shuffle(password);
            return SecretBuffer.fromChars(password);
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(pool, '\0');
            for (char[] group : groups) {
                Arrays.fill(group, '\0');
            }
        }
    }

    private @NonNull List<char[]> enabledGroups(@NonNull PasswordPolicy policy) {
        List<char[]> groups = new ArrayList<>();
        if (policy.uppercase()) {
            groups.add(filter(UPPERCASE, policy));
        }
        if (policy.lowercase()) {
            groups.add(filter(LOWERCASE, policy));
        }
        if (policy.digits()) {
            groups.add(filter(DIGITS, policy));
        }
        if (policy.symbols()) {
            groups.add(filter(SYMBOLS, policy));
        }
        groups.removeIf(group -> group.length == 0);
        return groups;
    }

    private char @NonNull [] filter(char @NonNull [] source, @NonNull PasswordPolicy policy) {
        StringBuilder builder = new StringBuilder(source.length);
        for (char c : source) {
            if (policy.avoidAmbiguous() && contains(AMBIGUOUS, c)) {
                continue;
            }
            if (policy.excludedCharacters().contains(c)) {
                continue;
            }
            builder.append(c);
        }
        char[] filtered = new char[builder.length()];
        builder.getChars(0, builder.length(), filtered, 0);
        return filtered;
    }

    private char @NonNull [] merge(@NonNull List<char[]> groups) {
        int length = 0;
        for (char[] group : groups) {
            length += group.length;
        }
        char[] merged = new char[length];
        int offset = 0;
        for (char[] group : groups) {
            System.arraycopy(group, 0, merged, offset, group.length);
            offset += group.length;
        }
        return merged;
    }

    private char pick(char @NonNull [] chars) {
        if (chars.length == 0) {
            throw new IllegalArgumentException(
                    "No characters are available for the requested password policy");
        }
        return chars[random.nextInt(chars.length)];
    }

    private void shuffle(char @NonNull [] chars) {
        for (int i = chars.length - 1; i > 0; i--) {
            int swapIndex = random.nextInt(i + 1);
            char value = chars[i];
            chars[i] = chars[swapIndex];
            chars[swapIndex] = value;
        }
    }

    private boolean contains(char @NonNull [] chars, char target) {
        for (char c : chars) {
            if (c == target) {
                return true;
            }
        }
        return false;
    }
}
