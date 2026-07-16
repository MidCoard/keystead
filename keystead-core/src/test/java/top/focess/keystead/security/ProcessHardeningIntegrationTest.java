package top.focess.keystead.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import top.focess.keystead.memory.NativePlatform;

/** Real local Windows integration test for {@link ProcessHardening#inspect()}. */
@EnabledOnOs(OS.WINDOWS)
class ProcessHardeningIntegrationTest {

    @Test
    void realWindowsInspectReportsVerifiedPrerequisitesAndApplicationResponsibilities() {
        ProcessHardeningReport report = ProcessHardening.inspect();

        assertEquals(NativePlatform.WINDOWS_X86_64, report.platform());
        assertEquals(
                HardeningStatus.VERIFIED,
                report.result(HardeningControl.JAVA_25_OR_LATER).status());
        assertEquals(
                HardeningStatus.VERIFIED,
                report.result(HardeningControl.MODULE_NATIVE_ACCESS).status());
        assertEquals(
                HardeningStatus.VERIFIED,
                report.result(HardeningControl.NATIVE_LOCKED_MEMORY).status());
        assertEquals(
                HardeningStatus.VERIFIED,
                report.result(HardeningControl.HEAP_DUMP_ON_OOME_DISABLED).status());
        assertEquals(
                HardeningStatus.NOT_ENFORCED,
                report.result(HardeningControl.JVM_ATTACH_DISABLED).status());
        assertEquals(
                HardeningStatus.APPLICATION_REQUIRED,
                report.result(HardeningControl.OS_DEBUGGER_ISOLATION).status());
        assertEquals(
                HardeningStatus.APPLICATION_REQUIRED,
                report.result(HardeningControl.PRIVILEGED_ACCOUNT_SEPARATION).status());
        assertNull(report.result(HardeningControl.LINUX_DUMPABLE_ZERO));
        assertNull(report.result(HardeningControl.MACOS_HARDENED_RUNTIME));
    }
}
