package top.focess.keystead.module;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.google.crypto.tink.Aead;
import java.lang.module.ModuleDescriptor;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import top.focess.keystead.crypto.AeadCipher;

class ModuleContractTest {

    private static final String CORE_MODULE_NAME = "top.focess.keystead.core";
    private static final Set<String> EXPORTED_PACKAGES =
            Set.of(
                    "top.focess.keystead.aigc",
                    "top.focess.keystead.crypto",
                    "top.focess.keystead.generator",
                    "top.focess.keystead.memory",
                    "top.focess.keystead.model",
                    "top.focess.keystead.recovery",
                    "top.focess.keystead.security",
                    "top.focess.keystead.service",
                    "top.focess.keystead.store");

    @Test
    void runsOnJava25OrLater() {
        assertTrue(Runtime.version().feature() >= 25, Runtime.version().toString());
    }

    @Test
    void coreIsTheExpectedNamedModule() {
        Module coreModule = coreModule();

        assertTrue(coreModule.isNamed());
        assertEquals(CORE_MODULE_NAME, coreModule.getName());
    }

    @Test
    void coreExportsItsCompletePublicApi() {
        ModuleDescriptor descriptor = coreModule().getDescriptor();
        assertNotNull(descriptor);

        Set<String> exports =
                descriptor.exports().stream()
                        .filter(export -> !export.isQualified())
                        .map(ModuleDescriptor.Exports::source)
                        .collect(java.util.stream.Collectors.toUnmodifiableSet());
        assertEquals(EXPORTED_PACKAGES, exports);
    }

    @Test
    void coreHasScopedNativeAccess() {
        assertTrue(nativeAccessEnabled(coreModule()));
    }

    @Test
    void tinkRetainsItsPinnedAutomaticModuleName() {
        ModuleDescriptor descriptor = Aead.class.getModule().getDescriptor();
        assertNotNull(descriptor);

        assertTrue(descriptor.isAutomatic());
        assertEquals("com.google.crypto.tink", descriptor.name());
    }

    private static boolean nativeAccessEnabled(@NonNull Module module) {
        try {
            return (boolean) Module.class.getMethod("isNativeAccessEnabled").invoke(module);
        } catch (ReflectiveOperationException exception) {
            fail("The runtime must expose Module.isNativeAccessEnabled()", exception);
            return false;
        }
    }

    private static @NonNull Module coreModule() {
        return AeadCipher.class.getModule();
    }
}
