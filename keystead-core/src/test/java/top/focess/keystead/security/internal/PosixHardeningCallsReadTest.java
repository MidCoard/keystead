package top.focess.keystead.security.internal;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

/**
 * Real POSIX read operations through {@link HotSpotHardeningOperations} on the CI matrix. These
 * tests are skipped on the Windows host; they turn red on Linux/macOS CI while the reads are stubbed
 * and green once the real {@code prctl}/{@code getrlimit} downcalls are wired.
 */
class PosixHardeningCallsReadTest {

    @Test
    @EnabledOnOs(OS.LINUX)
    void linuxReadsRealDumpableAndCoreLimit() {
        HotSpotHardeningOperations operations = new HotSpotHardeningOperations();

        Integer dumpable = operations.readDumpable();
        assertNotNull(dumpable);
        // PR_GET_DUMPABLE returns 0, 1, or 2 (suid_dumpable) on Linux.
        assertTrue(dumpable == 0 || dumpable == 1 || dumpable == 2, "unexpected dumpable value");
        assertNotNull(operations.readCoreLimit());
    }

    @Test
    @EnabledOnOs(OS.MAC)
    void macOsReadsRealCoreLimitAndHasNoDumpableRead() {
        HotSpotHardeningOperations operations = new HotSpotHardeningOperations();

        // macOS has no prctl dumpable control in this model.
        assertNull(operations.readDumpable());
        assertNotNull(operations.readCoreLimit());
    }
}
