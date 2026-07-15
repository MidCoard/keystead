package top.focess.keystead.memory;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

class NativeMemoryReportTest {

    private static final List<@NonNull String> SENSITIVE_FRAGMENTS =
            List.of(
                    "[115, 101, 99, 114, 101, 116]",
                    "0x7ffdecaf",
                    "alice-admin",
                    "vault-01234567",
                    "key-89abcdef",
                    "--enable-native-access=ALL-UNNAMED",
                    "C:\\sensitive\\native.dll",
                    "C:\\vaults\\customer-a");

    @Test
    void publicEnumsHaveStableOrder() {
        assertArrayEquals(
                new NativePlatform[] {
                    NativePlatform.WINDOWS_X86_64,
                    NativePlatform.LINUX_X86_64,
                    NativePlatform.LINUX_AARCH64,
                    NativePlatform.MACOS_X86_64,
                    NativePlatform.MACOS_AARCH64,
                    NativePlatform.UNSUPPORTED
                },
                NativePlatform.values());
        assertArrayEquals(
                new NativeProtectionControl[] {
                    NativeProtectionControl.PLATFORM,
                    NativeProtectionControl.NATIVE_ACCESS,
                    NativeProtectionControl.ABI_LAYOUTS,
                    NativeProtectionControl.SYMBOLS,
                    NativeProtectionControl.ALLOCATION,
                    NativeProtectionControl.PAGE_LOCK,
                    NativeProtectionControl.DUMP_EXCLUSION,
                    NativeProtectionControl.WIPE,
                    NativeProtectionControl.PAGE_UNLOCK,
                    NativeProtectionControl.RELEASE
                },
                NativeProtectionControl.values());
        assertArrayEquals(
                new NativeProtectionStatus[] {
                    NativeProtectionStatus.VERIFIED,
                    NativeProtectionStatus.UNAVAILABLE,
                    NativeProtectionStatus.FAILED,
                    NativeProtectionStatus.NOT_APPLICABLE,
                    NativeProtectionStatus.NOT_ATTEMPTED
                },
                NativeProtectionStatus.values());
        assertArrayEquals(
                new NativeMemoryOperation[] {
                    NativeMemoryOperation.PLATFORM,
                    NativeMemoryOperation.NATIVE_ACCESS,
                    NativeMemoryOperation.ABI_LAYOUTS,
                    NativeMemoryOperation.SYMBOLS,
                    NativeMemoryOperation.ALLOCATION,
                    NativeMemoryOperation.PAGE_LOCK,
                    NativeMemoryOperation.DUMP_EXCLUSION,
                    NativeMemoryOperation.COPY,
                    NativeMemoryOperation.WIPE,
                    NativeMemoryOperation.PAGE_UNLOCK,
                    NativeMemoryOperation.RELEASE
                },
                NativeMemoryOperation.values());
    }

    @Test
    void reportDefensivelyCopiesResultsAndReturnsAnImmutableList() {
        List<@NonNull NativeProtectionResult> source = new ArrayList<>(verifiedResults());
        NativeMemoryProtectionReport report =
                new NativeMemoryProtectionReport(NativePlatform.LINUX_X86_64, source);
        List<@NonNull NativeProtectionResult> expected = List.copyOf(source);

        source.set(0, unavailable(NativeProtectionControl.PLATFORM));

        assertEquals(expected, report.results());
        assertThrows(
                UnsupportedOperationException.class,
                () -> report.results().set(0, unavailable(NativeProtectionControl.PLATFORM)));
    }

    @Test
    void reportRequiresExactlyOneResultPerControlInEnumOrder() {
        List<@NonNull NativeProtectionResult> missing =
                new ArrayList<>(
                        verifiedResults().subList(0, NativeProtectionControl.values().length - 1));
        List<@NonNull NativeProtectionResult> outOfOrder = new ArrayList<>(verifiedResults());
        NativeProtectionResult first = outOfOrder.get(0);
        outOfOrder.set(0, outOfOrder.get(1));
        outOfOrder.set(1, first);

        assertThrows(
                IllegalArgumentException.class,
                () -> new NativeMemoryProtectionReport(NativePlatform.LINUX_X86_64, missing));
        assertThrows(
                IllegalArgumentException.class,
                () -> new NativeMemoryProtectionReport(NativePlatform.LINUX_X86_64, outOfOrder));
    }

    @Test
    void lookupIsExplicitlyNullableEvenThoughCurrentReportsAreExhaustive() throws Exception {
        NativeMemoryProtectionReport report =
                new NativeMemoryProtectionReport(NativePlatform.LINUX_X86_64, verifiedResults());

        assertEquals(
                NativeProtectionControl.PAGE_LOCK,
                report.result(NativeProtectionControl.PAGE_LOCK).control());
        Method lookup =
                NativeMemoryProtectionReport.class.getMethod(
                        "result", NativeProtectionControl.class);
        assertTrue(lookup.getAnnotatedReturnType().isAnnotationPresent(Nullable.class));
        assertTrue(lookup.getAnnotatedParameterTypes()[0].isAnnotationPresent(NonNull.class));
    }

    @Test
    void reportsAndResultsUseValueEquality() {
        NativeProtectionResult leftResult =
                new NativeProtectionResult(
                        NativeProtectionControl.PAGE_LOCK,
                        NativeProtectionStatus.FAILED,
                        NativeProtectionResult.DETAIL_OPERATION_FAILED,
                        12L);
        NativeProtectionResult rightResult =
                new NativeProtectionResult(
                        NativeProtectionControl.PAGE_LOCK,
                        NativeProtectionStatus.FAILED,
                        NativeProtectionResult.DETAIL_OPERATION_FAILED,
                        12L);
        NativeMemoryProtectionReport left =
                new NativeMemoryProtectionReport(NativePlatform.LINUX_X86_64, verifiedResults());
        NativeMemoryProtectionReport right =
                new NativeMemoryProtectionReport(
                        NativePlatform.LINUX_X86_64, new ArrayList<>(verifiedResults()));

        assertEquals(leftResult, rightResult);
        assertEquals(leftResult.hashCode(), rightResult.hashCode());
        assertEquals(left, right);
        assertEquals(left.hashCode(), right.hashCode());
        assertNotEquals(
                left,
                new NativeMemoryProtectionReport(NativePlatform.LINUX_AARCH64, verifiedResults()));
    }

    @Test
    void windowsErrorCodesAreConvertedToUnsignedLongs() {
        NativeProtectionResult result =
                NativeProtectionResult.withWindowsError(
                        NativeProtectionControl.PAGE_LOCK,
                        NativeProtectionStatus.FAILED,
                        NativeProtectionResult.DETAIL_OPERATION_FAILED,
                        -1);
        NativeMemoryUnavailableException failure =
                NativeMemoryUnavailableException.fromWindowsError(
                        NativePlatform.WINDOWS_X86_64, NativeMemoryOperation.PAGE_LOCK, -1);

        assertEquals(4_294_967_295L, result.osErrorCode());
        assertEquals(4_294_967_295L, failure.osErrorCode());
        assertTrue(failure.getMessage().contains("4294967295"));
        assertFalse(failure.getMessage().contains("-1"));
    }

    @Test
    void arbitraryDetailTextIsRejectedWithoutBeingEchoed() {
        String unsafeDetail = "ALICE_ADMIN_VAULT_01234567";

        IllegalArgumentException failure =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                new NativeProtectionResult(
                                        NativeProtectionControl.PAGE_LOCK,
                                        NativeProtectionStatus.FAILED,
                                        unsafeDetail,
                                        null));

        assertEquals("Unsupported native protection detail code", failure.getMessage());
        assertFalse(failure.toString().contains(unsafeDetail));
    }

    @Test
    void causeCannotBeInitializedButRedactedSuppressionRemainsAvailable() {
        NativeMemoryUnavailableException failure =
                new NativeMemoryUnavailableException(
                        NativePlatform.LINUX_X86_64, NativeMemoryOperation.PAGE_LOCK, 12L);
        RuntimeException unsafeCause =
                new RuntimeException(String.join(" | ", SENSITIVE_FRAGMENTS));
        NativeMemoryUnavailableException cleanupFailure =
                new NativeMemoryUnavailableException(
                        NativePlatform.LINUX_X86_64, NativeMemoryOperation.RELEASE);

        assertThrows(IllegalStateException.class, () -> failure.initCause(unsafeCause));
        failure.addSuppressed(cleanupFailure);

        assertNull(failure.getCause());
        assertEquals(1, failure.getSuppressed().length);
        assertEquals(cleanupFailure, failure.getSuppressed()[0]);
    }

    @Test
    void messagesTextAndThrowableGraphsRemainRedactionSafe() {
        NativeMemoryProtectionReport report =
                new NativeMemoryProtectionReport(NativePlatform.LINUX_X86_64, verifiedResults());
        NativeMemoryUnavailableException failure =
                new NativeMemoryUnavailableException(
                        NativePlatform.LINUX_X86_64, NativeMemoryOperation.PAGE_LOCK, 12L);
        NativeMemoryUnavailableException cleanupFailure =
                new NativeMemoryUnavailableException(
                        NativePlatform.LINUX_X86_64, NativeMemoryOperation.RELEASE);
        failure.addSuppressed(cleanupFailure);

        assertEquals(
                "NativeProtectionResult[control=PAGE_LOCK, status=FAILED, "
                        + "detail=OPERATION_FAILED, osErrorCode=12]",
                new NativeProtectionResult(
                                NativeProtectionControl.PAGE_LOCK,
                                NativeProtectionStatus.FAILED,
                                NativeProtectionResult.DETAIL_OPERATION_FAILED,
                                12L)
                        .toString());
        assertNull(failure.getCause());
        assertEquals(1, failure.getSuppressed().length);
        assertNull(failure.getSuppressed()[0].getCause());
        assertNoSensitiveFragments(report.toString());
        assertThrowableGraphIsSafe(failure);
        assertTrue(
                Arrays.stream(NativeMemoryUnavailableException.class.getConstructors())
                        .map(Constructor::getParameterTypes)
                        .flatMap(Arrays::stream)
                        .noneMatch(Throwable.class::isAssignableFrom));
    }

    private static void assertThrowableGraphIsSafe(@NonNull Throwable failure) {
        assertNoSensitiveFragments(failure.getMessage());
        assertNoSensitiveFragments(failure.toString());
        assertNull(failure.getCause());
        for (Throwable suppressed : failure.getSuppressed()) {
            assertTrue(suppressed instanceof NativeMemoryUnavailableException);
            assertThrowableGraphIsSafe(suppressed);
        }
    }

    private static void assertNoSensitiveFragments(@Nullable String value) {
        if (value == null) {
            return;
        }
        for (String fragment : SENSITIVE_FRAGMENTS) {
            assertFalse(value.contains(fragment), () -> "Leaked sensitive fragment: " + fragment);
        }
    }

    private static @NonNull NativeProtectionResult unavailable(
            @NonNull NativeProtectionControl control) {
        return new NativeProtectionResult(
                control,
                NativeProtectionStatus.UNAVAILABLE,
                NativeProtectionResult.DETAIL_NOT_ATTEMPTED,
                null);
    }

    private static @NonNull List<@NonNull NativeProtectionResult> verifiedResults() {
        List<@NonNull NativeProtectionResult> results = new ArrayList<>();
        for (NativeProtectionControl control : NativeProtectionControl.values()) {
            String detail =
                    switch (control) {
                        case PLATFORM -> NativeProtectionResult.DETAIL_PLATFORM_SUPPORTED;
                        case NATIVE_ACCESS -> NativeProtectionResult.DETAIL_NATIVE_ACCESS_ENABLED;
                        case ABI_LAYOUTS -> NativeProtectionResult.DETAIL_ABI_LAYOUTS_VERIFIED;
                        case SYMBOLS -> NativeProtectionResult.DETAIL_SYMBOLS_RESOLVED;
                        default -> NativeProtectionResult.DETAIL_OPERATION_VERIFIED;
                    };
            results.add(
                    new NativeProtectionResult(
                            control, NativeProtectionStatus.VERIFIED, detail, null));
        }
        return results;
    }
}
