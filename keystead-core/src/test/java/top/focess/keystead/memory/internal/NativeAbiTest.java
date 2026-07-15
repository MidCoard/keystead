package top.focess.keystead.memory.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.ValueLayout;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.NativePlatform;

class NativeAbiTest {

    @Test
    void detectsExactlyTheFiveSupportedAbiTuples() {
        assertAll(
                () ->
                        assertEquals(
                                NativePlatform.WINDOWS_X86_64,
                                NativeAbi.requireSupportedPlatform(
                                        "Windows 11", "amd64", "64", "OpenJDK 64-Bit Server VM")),
                () ->
                        assertEquals(
                                NativePlatform.LINUX_X86_64,
                                NativeAbi.requireSupportedPlatform(
                                        "Linux", "x86_64", "64", "OpenJDK 64-Bit Server VM")),
                () ->
                        assertEquals(
                                NativePlatform.LINUX_AARCH64,
                                NativeAbi.requireSupportedPlatform(
                                        "Linux", "aarch64", "64", "OpenJDK 64-Bit Server VM")),
                () ->
                        assertEquals(
                                NativePlatform.MACOS_X86_64,
                                NativeAbi.requireSupportedPlatform(
                                        "Mac OS X", "x86_64", "64", "OpenJDK 64-Bit Server VM")),
                () ->
                        assertEquals(
                                NativePlatform.MACOS_AARCH64,
                                NativeAbi.requireSupportedPlatform(
                                        "Mac OS X", "arm64", "64", "OpenJDK 64-Bit Server VM")));
    }

    @Test
    void rejectsUnsupportedAbiTuplesWithoutNativeSideEffects() {
        assertEquals(
                NativePlatform.UNSUPPORTED,
                NativeAbi.detectPlatform("Linux", "x86_64", "32", "OpenJDK Server VM"));
        assertEquals(
                NativePlatform.UNSUPPORTED,
                NativeAbi.detectPlatform("Linux", "x86_64", "64", "Eclipse OpenJ9 VM"));
        assertEquals(
                NativePlatform.UNSUPPORTED,
                NativeAbi.detectPlatform("Plan 9", "x86_64", "64", "OpenJDK Server VM"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        NativeAbi.requireSupportedPlatform(
                                "Linux", "riscv64", "64", "OpenJDK Server VM"));
    }

    @Test
    void roundsLogicalLengthsToProtectedPagesWithCheckedArithmetic() {
        assertEquals(4096L, NativeAbi.roundToPage(0L, 4096L));
        assertEquals(4096L, NativeAbi.roundToPage(1L, 4096L));
        assertEquals(4096L, NativeAbi.roundToPage(4096L, 4096L));
        assertEquals(8192L, NativeAbi.roundToPage(4097L, 4096L));

        assertThrows(ArithmeticException.class, () -> NativeAbi.roundToPage(Long.MAX_VALUE, 4096L));
        assertThrows(IllegalArgumentException.class, () -> NativeAbi.roundToPage(-1L, 4096L));
        assertThrows(IllegalArgumentException.class, () -> NativeAbi.roundToPage(1L, 0L));
        assertThrows(IllegalArgumentException.class, () -> NativeAbi.roundToPage(1L, 3000L));
    }

    @Test
    void validatesCanonicalWindowsLayoutsAndSystemInfoShape() {
        Map<String, MemoryLayout> layouts = windowsLayouts();

        assertDoesNotThrow(
                () -> NativeAbi.requireCanonicalLayouts(NativePlatform.WINDOWS_X86_64, layouts));
        MemoryLayout systemInfo = NativeAbi.windowsSystemInfoLayout(layouts);

        assertEquals(48L, systemInfo.byteSize());
        assertEquals(8L, systemInfo.byteAlignment());
        assertEquals(
                4L, systemInfo.byteOffset(MemoryLayout.PathElement.groupElement("dwPageSize")));
        assertEquals(
                8L,
                systemInfo.byteOffset(
                        MemoryLayout.PathElement.groupElement("lpMinimumApplicationAddress")));
        assertEquals(
                16L,
                systemInfo.byteOffset(
                        MemoryLayout.PathElement.groupElement("lpMaximumApplicationAddress")));
        assertEquals(
                24L,
                systemInfo.byteOffset(
                        MemoryLayout.PathElement.groupElement("dwActiveProcessorMask")));
        assertEquals(
                32L,
                systemInfo.byteOffset(
                        MemoryLayout.PathElement.groupElement("dwNumberOfProcessors")));
        assertEquals(
                44L,
                systemInfo.byteOffset(MemoryLayout.PathElement.groupElement("wProcessorLevel")));
        assertEquals(
                46L,
                systemInfo.byteOffset(MemoryLayout.PathElement.groupElement("wProcessorRevision")));
    }

    @Test
    void validatesCanonicalPosixLayoutsAndRlimitShape() {
        Map<String, MemoryLayout> layouts = posixLayouts();

        assertDoesNotThrow(
                () -> NativeAbi.requireCanonicalLayouts(NativePlatform.LINUX_X86_64, layouts));
        assertDoesNotThrow(
                () -> NativeAbi.requireCanonicalLayouts(NativePlatform.LINUX_AARCH64, layouts));
        assertDoesNotThrow(
                () -> NativeAbi.requireCanonicalLayouts(NativePlatform.MACOS_X86_64, layouts));
        assertDoesNotThrow(
                () -> NativeAbi.requireCanonicalLayouts(NativePlatform.MACOS_AARCH64, layouts));

        MemoryLayout rlimit = NativeAbi.posixRlimitLayout(layouts);
        assertEquals(16L, rlimit.byteSize());
        assertEquals(8L, rlimit.byteAlignment());
        assertEquals(0L, rlimit.byteOffset(MemoryLayout.PathElement.groupElement("rlim_cur")));
        assertEquals(8L, rlimit.byteOffset(MemoryLayout.PathElement.groupElement("rlim_max")));
    }

    @Test
    void rejectsMissingOrMismatchedCanonicalLayouts() {
        Map<String, MemoryLayout> windowsLayouts = new HashMap<>(windowsLayouts());
        windowsLayouts.put("long", ValueLayout.JAVA_LONG);
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        NativeAbi.requireCanonicalLayouts(
                                NativePlatform.WINDOWS_X86_64, windowsLayouts));

        Map<String, MemoryLayout> posixLayouts = new HashMap<>(posixLayouts());
        posixLayouts.remove("int64_t");
        assertThrows(
                IllegalArgumentException.class,
                () -> NativeAbi.requireCanonicalLayouts(NativePlatform.LINUX_X86_64, posixLayouts));
        assertThrows(
                IllegalArgumentException.class,
                () -> NativeAbi.requireCanonicalLayouts(NativePlatform.UNSUPPORTED, posixLayouts));
    }

    @Test
    void requiresThePlatformCaptureStateNameToBeAvailable() {
        MemoryLayout captureStateLayout = Linker.Option.captureStateLayout();

        assertEquals("GetLastError", NativeAbi.captureStateName(NativePlatform.WINDOWS_X86_64));
        assertEquals("errno", NativeAbi.captureStateName(NativePlatform.LINUX_X86_64));
        assertDoesNotThrow(
                () -> NativeAbi.requireCaptureStateName(captureStateLayout, "GetLastError"));
        assertDoesNotThrow(() -> NativeAbi.requireCaptureStateName(captureStateLayout, "errno"));
        assertThrows(
                IllegalArgumentException.class,
                () -> NativeAbi.requireCaptureStateName(captureStateLayout, "missing_state"));
        assertThrows(
                IllegalArgumentException.class,
                () -> NativeAbi.captureStateName(NativePlatform.UNSUPPORTED));
    }

    @Test
    void validatesTheCurrentLinkerCanonicalLayouts() {
        NativePlatform current =
                NativeAbi.requireSupportedPlatform(
                        System.getProperty("os.name"),
                        System.getProperty("os.arch"),
                        System.getProperty("sun.arch.data.model"),
                        System.getProperty("java.vm.name"));

        assertDoesNotThrow(
                () ->
                        NativeAbi.requireCanonicalLayouts(
                                current, Linker.nativeLinker().canonicalLayouts()));
    }

    @Test
    void treatsWindowsNullAsAllocationFailureWithUnsignedLastError() {
        NativeOperations operations = FakeNativeOperations.windows(0L, 0xFFFF_FFFE, 1L, 0);

        NativeOperationResult result = operations.allocate(4096L);

        assertFalse(result.successful());
        assertEquals(NativeOperationResult.DETAIL_OPERATION_FAILED, result.detail());
        assertEquals(4_294_967_294L, result.osErrorCode());
    }

    @Test
    void treatsOnlyPosixMapFailedAsNativeAllocationFailure() {
        FakeNativeOperations operations = FakeNativeOperations.posix(-1L, 12, 0L, 0);

        NativeOperationResult result = operations.allocate(4096L);

        assertFalse(result.successful());
        assertEquals(NativeOperationResult.DETAIL_OPERATION_FAILED, result.detail());
        assertEquals(12L, result.osErrorCode());
        assertTrue(operations.releaseCalls().isEmpty());
    }

    @Test
    void acceptsAHighBitPosixAddressAndIgnoresStaleErrno() {
        FakeNativeOperations operations = FakeNativeOperations.posix(Long.MIN_VALUE, 12, 0L, 0);

        NativeOperationResult result = operations.allocate(4096L);

        assertTrue(result.successful());
        assertEquals(Long.MIN_VALUE, result.value());
        assertNull(result.osErrorCode());
    }

    @Test
    void rejectsSuccessfulPosixAddressZeroAfterMandatoryUnmap() {
        FakeNativeOperations operations = FakeNativeOperations.posix(0L, 99, -1L, 5);

        NativeOperationResult result = operations.allocate(8192L);

        assertFalse(result.successful());
        assertEquals(NativeOperationResult.DETAIL_ZERO_ADDRESS_REJECTED, result.detail());
        assertNull(result.osErrorCode());
        assertEquals(1, operations.releaseCalls().size());
        assertEquals(
                new FakeNativeOperations.ReleaseCall(0L, 8192L),
                operations.releaseCalls().getFirst());
    }

    private static Map<String, MemoryLayout> posixLayouts() {
        return Map.of(
                "int", ValueLayout.JAVA_INT,
                "long", ValueLayout.JAVA_LONG,
                "short", ValueLayout.JAVA_SHORT,
                "size_t", ValueLayout.JAVA_LONG,
                "void*", ValueLayout.ADDRESS,
                "int64_t", ValueLayout.JAVA_LONG);
    }

    private static Map<String, MemoryLayout> windowsLayouts() {
        return Map.of(
                "int", ValueLayout.JAVA_INT,
                "long", ValueLayout.JAVA_INT,
                "short", ValueLayout.JAVA_SHORT,
                "size_t", ValueLayout.JAVA_LONG,
                "void*", ValueLayout.ADDRESS);
    }
}
