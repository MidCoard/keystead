package top.focess.keystead.security.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import top.focess.keystead.memory.NativePlatform;

/**
 * Windows contract for {@link HotSpotHardeningOperations}: the platform is not POSIX, so the
 * dumpable and core-limit reads are unavailable and the mutations fail closed. Pins the Windows
 * behavior so the real POSIX read implementation cannot regress it.
 */
@EnabledOnOs(OS.WINDOWS)
class HotSpotHardeningOperationsTest {

    @Test
    void windowsReportsUnavailablePosixReadsAndFailingPosixMutations() {
        HotSpotHardeningOperations operations = new HotSpotHardeningOperations();

        assertEquals(NativePlatform.WINDOWS_X86_64, operations.platform());
        assertNotNull(operations.nativeMemoryProbe());
        assertNull(operations.readDumpable());
        assertNull(operations.readCoreLimit());
        assertFalse(operations.setDumpableZero().successful());
        assertFalse(operations.setCoreLimitZero().successful());
    }
}
