package top.focess.keystead.generator;

import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.SecretBuffer;

class DefaultApiTokenGeneratorTest {

    private final ApiTokenGenerator generator = new DefaultApiTokenGenerator();

    @Test
    void generatesUrlSafeTokenWithPrefix() {
        try (SecretBuffer token = generator.generate(new ApiTokenPolicy("ghp", 32))) {
            String value = copy(token);

            assertTrue(value.startsWith("ghp_"));
            assertEquals(47, value.length());
            assertTrue(value.matches("ghp_[A-Za-z0-9_-]+"));
            assertFalse(value.contains("="));
            assertFalse(value.contains("+"));
            assertFalse(value.contains("/"));
        }
    }

    @Test
    void policyRejectsInvalidTokenParameters() {
        assertThrows(IllegalArgumentException.class, () -> new ApiTokenPolicy("", 32));
        assertThrows(IllegalArgumentException.class, () -> new ApiTokenPolicy("ghp", 0));
        assertThrows(IllegalArgumentException.class, () -> new ApiTokenPolicy("bad prefix", 32));
    }

    private static String copy(SecretBuffer buffer) {
        AtomicReference<String> value = new AtomicReference<>("");
        buffer.copyChars(chars -> value.set(new String(chars)));
        return value.get();
    }
}
