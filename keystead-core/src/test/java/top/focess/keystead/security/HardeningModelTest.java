package top.focess.keystead.security;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.NativePlatform;

class HardeningModelTest {

    @Test
    void hardeningResultRejectsUnknownDetailAndNegativeErrorCode() {
        assertThrows(
                NullPointerException.class,
                () ->
                        new HardeningResult(
                                null,
                                HardeningStatus.VERIFIED,
                                HardeningResult.DETAIL_VERIFIED,
                                null));
        assertThrows(
                NullPointerException.class,
                () ->
                        new HardeningResult(
                                HardeningControl.JAVA_25_OR_LATER,
                                null,
                                HardeningResult.DETAIL_VERIFIED,
                                null));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new HardeningResult(
                                HardeningControl.JAVA_25_OR_LATER,
                                HardeningStatus.VERIFIED,
                                "BOGUS_DETAIL",
                                null));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new HardeningResult(
                                HardeningControl.JAVA_25_OR_LATER,
                                HardeningStatus.FAILED,
                                HardeningResult.DETAIL_FAILED,
                                -1L));
    }

    @Test
    void hardeningResultIsValueEqualAndRedactsInToString() {
        HardeningResult a =
                new HardeningResult(
                        HardeningControl.JVM_ATTACH_DISABLED,
                        HardeningStatus.VERIFIED,
                        HardeningResult.DETAIL_VERIFIED,
                        null);
        HardeningResult b =
                new HardeningResult(
                        HardeningControl.JVM_ATTACH_DISABLED,
                        HardeningStatus.VERIFIED,
                        HardeningResult.DETAIL_VERIFIED,
                        null);
        HardeningResult c =
                new HardeningResult(
                        HardeningControl.JVM_ATTACH_DISABLED,
                        HardeningStatus.NOT_ENFORCED,
                        HardeningResult.DETAIL_NOT_ENFORCED,
                        5L);

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
        assertNotEquals(a, "other");

        String rendered = c.toString();
        assertTrue(rendered.contains("JVM_ATTACH_DISABLED"));
        assertTrue(rendered.contains("NOT_ENFORCED"));
        assertTrue(rendered.contains("5"));
    }

    @Test
    void processHardeningReportDefensivelyCopiesAndPreservesEnumOrder() {
        List<HardeningResult> input = new ArrayList<>();
        input.add(
                new HardeningResult(
                        HardeningControl.JAVA_25_OR_LATER,
                        HardeningStatus.VERIFIED,
                        HardeningResult.DETAIL_VERIFIED,
                        null));
        input.add(
                new HardeningResult(
                        HardeningControl.MODULE_NATIVE_ACCESS,
                        HardeningStatus.VERIFIED,
                        HardeningResult.DETAIL_VERIFIED,
                        null));

        ProcessHardeningReport report =
                new ProcessHardeningReport(NativePlatform.LINUX_X86_64, input);
        input.clear();

        assertEquals(NativePlatform.LINUX_X86_64, report.platform());
        assertEquals(2, report.results().size());
        assertEquals(HardeningControl.JAVA_25_OR_LATER, report.results().get(0).control());
        assertEquals(HardeningControl.MODULE_NATIVE_ACCESS, report.results().get(1).control());
    }

    @Test
    void processHardeningReportRejectsOutOfOrderOrDuplicateControls() {
        List<HardeningResult> reversed = new ArrayList<>();
        reversed.add(
                new HardeningResult(
                        HardeningControl.MODULE_NATIVE_ACCESS,
                        HardeningStatus.VERIFIED,
                        HardeningResult.DETAIL_VERIFIED,
                        null));
        reversed.add(
                new HardeningResult(
                        HardeningControl.JAVA_25_OR_LATER,
                        HardeningStatus.VERIFIED,
                        HardeningResult.DETAIL_VERIFIED,
                        null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new ProcessHardeningReport(NativePlatform.LINUX_X86_64, reversed));

        List<HardeningResult> duplicated = new ArrayList<>();
        duplicated.add(
                new HardeningResult(
                        HardeningControl.JAVA_25_OR_LATER,
                        HardeningStatus.VERIFIED,
                        HardeningResult.DETAIL_VERIFIED,
                        null));
        duplicated.add(
                new HardeningResult(
                        HardeningControl.JAVA_25_OR_LATER,
                        HardeningStatus.VERIFIED,
                        HardeningResult.DETAIL_VERIFIED,
                        null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new ProcessHardeningReport(NativePlatform.LINUX_X86_64, duplicated));
    }

    @Test
    void processHardeningReportResultLookupReturnsNullForAbsentControls() {
        ProcessHardeningReport report =
                new ProcessHardeningReport(
                        NativePlatform.WINDOWS_X86_64,
                        List.of(
                                new HardeningResult(
                                        HardeningControl.JAVA_25_OR_LATER,
                                        HardeningStatus.VERIFIED,
                                        HardeningResult.DETAIL_VERIFIED,
                                        null)));
        assertEquals(
                HardeningControl.JAVA_25_OR_LATER,
                report.result(HardeningControl.JAVA_25_OR_LATER).control());
        assertNull(report.result(HardeningControl.LINUX_DUMPABLE_ZERO));
        assertThrows(NullPointerException.class, () -> report.result(null));
    }

    @Test
    void processHardeningExceptionCarriesReportAndStaysRedacted() {
        ProcessHardeningReport report =
                new ProcessHardeningReport(
                        NativePlatform.LINUX_X86_64,
                        List.of(
                                new HardeningResult(
                                        HardeningControl.LINUX_DUMPABLE_ZERO,
                                        HardeningStatus.FAILED,
                                        HardeningResult.DETAIL_FAILED,
                                        13L)));
        ProcessHardeningException exception = new ProcessHardeningException(report);

        assertEquals(report, exception.report());
        assertNull(exception.getCause());
        String rendered = exception.getMessage() + " " + exception.toString();
        assertTrue(rendered.contains("LINUX_X86_64"));
        assertTrue(rendered.contains("controls=1"));
        // No raw causes, command lines, paths, or usernames are attached.
        assertDoesNotThrow(() -> exception.getMessage());
    }
}
