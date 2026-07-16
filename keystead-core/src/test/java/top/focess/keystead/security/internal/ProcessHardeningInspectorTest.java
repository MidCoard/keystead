package top.focess.keystead.security.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.NativePlatform;
import top.focess.keystead.memory.NativeProtectionStatus;
import top.focess.keystead.security.HardeningControl;
import top.focess.keystead.security.HardeningStatus;
import top.focess.keystead.security.ProcessHardeningReport;

class ProcessHardeningInspectorTest {

    @Test
    void inspectReportsControlsInEnumOrderAndNeverReportsEnforced() {
        ProcessHardeningOperations operations =
                FakeHardeningOperations.windows()
                        .hotSpotOption("DisableAttachMechanism", "true")
                        .hotSpotOption("HeapDumpOnOutOfMemoryError", "false")
                        .build();

        ProcessHardeningReport report = ProcessHardeningInspector.inspect(operations);

        assertEquals(NativePlatform.WINDOWS_X86_64, report.platform());
        assertInEnumOrder(report);
        report.results().forEach(result -> assertNotEnforced(result.status()));
        assertEquals(
                HardeningStatus.VERIFIED,
                report.result(HardeningControl.JAVA_25_OR_LATER).status());
        assertEquals(
                HardeningStatus.VERIFIED,
                report.result(HardeningControl.MODULE_NATIVE_ACCESS).status());
        assertEquals(
                HardeningStatus.APPLICATION_REQUIRED,
                report.result(HardeningControl.ILLEGAL_NATIVE_ACCESS_DENY).status());
        assertEquals(
                HardeningStatus.VERIFIED,
                report.result(HardeningControl.JVM_ATTACH_DISABLED).status());
        assertEquals(
                HardeningStatus.VERIFIED,
                report.result(HardeningControl.HEAP_DUMP_ON_OOME_DISABLED).status());
        assertEquals(
                HardeningStatus.VERIFIED,
                report.result(HardeningControl.NATIVE_LOCKED_MEMORY).status());
        assertEquals(
                HardeningStatus.APPLICATION_REQUIRED,
                report.result(HardeningControl.OS_DEBUGGER_ISOLATION).status());
        assertEquals(
                HardeningStatus.APPLICATION_REQUIRED,
                report.result(HardeningControl.PRIVILEGED_ACCOUNT_SEPARATION).status());
    }

    @Test
    void inspectReportsNotEnforcedWhenTheDesiredHotSpotOptionIsInactive() {
        ProcessHardeningOperations operations =
                FakeHardeningOperations.windows()
                        .hotSpotOption("DisableAttachMechanism", "false")
                        .hotSpotOption("HeapDumpOnOutOfMemoryError", "true")
                        .build();

        ProcessHardeningReport report = ProcessHardeningInspector.inspect(operations);

        assertEquals(
                HardeningStatus.NOT_ENFORCED,
                report.result(HardeningControl.JVM_ATTACH_DISABLED).status());
        assertEquals(
                HardeningStatus.NOT_ENFORCED,
                report.result(HardeningControl.HEAP_DUMP_ON_OOME_DISABLED).status());
    }

    @Test
    void inspectReportsUnavailableWhenAHotSpotOptionCannotBeRead() {
        ProcessHardeningOperations operations = FakeHardeningOperations.windows().build();

        ProcessHardeningReport report = ProcessHardeningInspector.inspect(operations);

        assertEquals(
                HardeningStatus.UNAVAILABLE,
                report.result(HardeningControl.JVM_ATTACH_DISABLED).status());
        assertEquals(
                HardeningStatus.UNAVAILABLE,
                report.result(HardeningControl.HEAP_DUMP_ON_OOME_DISABLED).status());
    }

    @Test
    void inspectReportsJavaVersionUnavailableBelowJava25() {
        ProcessHardeningOperations operations =
                FakeHardeningOperations.windows().javaVersion(21).build();

        ProcessHardeningReport report = ProcessHardeningInspector.inspect(operations);

        assertEquals(
                HardeningStatus.UNAVAILABLE,
                report.result(HardeningControl.JAVA_25_OR_LATER).status());
    }

    @Test
    void inspectMapsNativeLockedMemoryFromTheNativeProbeAllocationStatus() {
        ProcessHardeningOperations failed =
                FakeHardeningOperations.windows()
                        .allocationStatus(NativeProtectionStatus.FAILED)
                        .build();
        assertEquals(
                HardeningStatus.FAILED,
                ProcessHardeningInspector.inspect(failed)
                        .result(HardeningControl.NATIVE_LOCKED_MEMORY)
                        .status());

        ProcessHardeningOperations notAttempted =
                FakeHardeningOperations.windows()
                        .allocationStatus(NativeProtectionStatus.NOT_ATTEMPTED)
                        .build();
        assertEquals(
                HardeningStatus.UNAVAILABLE,
                ProcessHardeningInspector.inspect(notAttempted)
                        .result(HardeningControl.NATIVE_LOCKED_MEMORY)
                        .status());
    }

    @Test
    void inspectIncludesLinuxDeploymentControlsOnLinux() {
        ProcessHardeningOperations operations =
                FakeHardeningOperations.linux()
                        .hotSpotOption("DisableAttachMechanism", "true")
                        .hotSpotOption("HeapDumpOnOutOfMemoryError", "false")
                        .build();

        ProcessHardeningReport report = ProcessHardeningInspector.inspect(operations);

        assertEquals(NativePlatform.LINUX_X86_64, report.platform());
        assertNotNull(report.result(HardeningControl.LINUX_YAMA_PTRACE_SCOPE));
        assertEquals(
                HardeningStatus.APPLICATION_REQUIRED,
                report.result(HardeningControl.LINUX_YAMA_PTRACE_SCOPE).status());
        assertEquals(
                HardeningStatus.APPLICATION_REQUIRED,
                report.result(HardeningControl.LINUX_SERVICE_SANDBOX).status());
        assertNull(report.result(HardeningControl.MACOS_HARDENED_RUNTIME));
    }

    @Test
    void inspectIncludesMacOsDeploymentControlsOnMacOs() {
        ProcessHardeningOperations operations =
                new FakeHardeningOperations.Builder(NativePlatform.MACOS_AARCH64)
                        .hotSpotOption("DisableAttachMechanism", "true")
                        .hotSpotOption("HeapDumpOnOutOfMemoryError", "false")
                        .build();

        ProcessHardeningReport report = ProcessHardeningInspector.inspect(operations);

        assertEquals(NativePlatform.MACOS_AARCH64, report.platform());
        assertEquals(
                HardeningStatus.APPLICATION_REQUIRED,
                report.result(HardeningControl.MACOS_HARDENED_RUNTIME).status());
        assertEquals(
                HardeningStatus.APPLICATION_REQUIRED,
                report.result(HardeningControl.MACOS_LIBRARY_VALIDATION).status());
        assertNull(report.result(HardeningControl.LINUX_YAMA_PTRACE_SCOPE));
    }

    private static void assertInEnumOrder(ProcessHardeningReport report) {
        int lastOrdinal = -1;
        for (var result : report.results()) {
            assertTrue(result.control().ordinal() > lastOrdinal, "controls must be in enum order");
            lastOrdinal = result.control().ordinal();
        }
    }

    private static void assertNotEnforced(HardeningStatus status) {
        assertFalse(status == HardeningStatus.ENFORCED, "inspect() must never report ENFORCED");
    }
}
