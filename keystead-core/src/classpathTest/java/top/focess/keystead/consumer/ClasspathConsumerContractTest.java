package top.focess.keystead.consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.SecretMemory;
import top.focess.keystead.memory.SecretMemoryProvider;

class ClasspathConsumerContractTest {

    @Test
    void publicCoreApiIsUsableFromClasspath() {
        try (SecretMemory memory = SecretMemoryProvider.heap().protect(new byte[0])) {
            assertEquals(0, memory.length());
        }
    }

    @Test
    void coreAndConsumerShareTheUnnamedModule() {
        Module coreModule = SecretMemoryProvider.class.getModule();

        assertFalse(coreModule.isNamed());
        assertSame(ClasspathConsumerContractTest.class.getModule(), coreModule);
    }

    @Test
    void allUnnamedNativeAccessGrantIsVisibleToCore() {
        assertTrue(SecretMemoryProvider.class.getModule().isNativeAccessEnabled());
    }
}
