package top.focess.keystead.memory.internal;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.NativePlatform;

/** Backend resolution and caching invariants for {@link NativeBackends}. */
class NativeBackendsTest {

    @Test
    void createCachesBackendAsProcessWideSingleton() {
        // A fresh backend must not be constructed per protect() call: each construction allocates
        // an Arena tied to the backend (the Windows kernel32 library lookup) that has no close
        // hook, so per-call construction leaks one arena per secret. The backend is stateless
        // after construction, so it must be cached as a process-wide singleton.
        NativePlatform platform =
                NativeAbi.detectPlatform(
                        System.getProperty("os.name"),
                        System.getProperty("os.arch"),
                        System.getProperty("sun.arch.data.model"),
                        System.getProperty("java.vm.name"));
        assumeTrue(platform != NativePlatform.UNSUPPORTED, "current platform must be supported");
        assumeTrue(
                NativeBackendsTest.class.getModule().isNativeAccessEnabled(),
                "native access must be enabled");

        NativeOperations first = NativeBackends.create(platform);
        NativeOperations second = NativeBackends.create(platform);

        assertTrue(first.platform() == platform, "cached backend matches the requested platform");
        assertSame(first, second, "backend must be cached as a process-wide singleton");
    }
}
