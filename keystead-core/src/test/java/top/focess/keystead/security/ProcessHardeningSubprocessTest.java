package top.focess.keystead.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

/**
 * Proves {@link ProcessHardening} behavior in expendable child JVMs launched with controlled
 * native-access and HotSpot flags. Process-global mutations ({@code setrlimit}, {@code prctl}) and
 * launcher-flag combinations never run in the Gradle worker.
 *
 * <p>Child JVMs are launched on the module path with {@code --enable-native-access} (or
 * {@code --illegal-native-access=deny} for the no-access case) and run {@link HardeningProbeMain},
 * whose {@code key=value} output is parsed here. POSIX mutation children run only on the Linux/macOS
 * CI matrix; the Windows inspect child and the no-access child run locally.
 */
@Timeout(90)
class ProcessHardeningSubprocessTest {

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void windowsInspectChildReportsVerifiedPrerequisitesAndApplicationResponsibilities()
            throws Exception {
        ChildResult result = runChild("inspect", true, false);

        assertEquals(0, result.exitCode(), result.output());
        assertNull(result.values().get("thrown"), result.output());
        assertEquals("WINDOWS_X86_64", result.values().get("platform"), result.output());
        assertEquals("VERIFIED", result.values().get("NATIVE_LOCKED_MEMORY"), result.output());
        assertEquals("VERIFIED", result.values().get("MODULE_NATIVE_ACCESS"), result.output());
        assertEquals("VERIFIED", result.values().get("JAVA_25_OR_LATER"), result.output());
        assertEquals(
                "APPLICATION_REQUIRED",
                result.values().get("OS_DEBUGGER_ISOLATION"),
                result.output());
        assertNull(result.values().get("LINUX_DUMPABLE_ZERO"), result.output());
    }

    @Test
    void noNativeAccessChildReportsUnavailableWithoutThrowing() throws Exception {
        ChildResult result = runChild("inspect", false, false);

        assertEquals(0, result.exitCode(), result.output());
        assertNull(result.values().get("thrown"), result.output());
        assertEquals("UNAVAILABLE", result.values().get("MODULE_NATIVE_ACCESS"), result.output());
        assertEquals("UNAVAILABLE", result.values().get("NATIVE_LOCKED_MEMORY"), result.output());
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    void linuxMutationChildEnforcesDumpableAndCoreLimit() throws Exception {
        ChildResult probe = runChild("inspect", true, false);
        assumeTrue(
                "VERIFIED".equals(probe.values().get("NATIVE_LOCKED_MEMORY")),
                "NATIVE_LOCKED_MEMORY not verified on this runner: " + probe.output());

        ChildResult result = runChild("applyStrict", true, true);

        assertEquals(0, result.exitCode(), result.output());
        assertNull(result.values().get("thrown"), result.output());
        assertEffective(result.values().get("LINUX_DUMPABLE_ZERO"), result.output());
        assertEffective(result.values().get("POSIX_CORE_RLIMIT_ZERO"), result.output());
    }

    @Test
    @EnabledOnOs(OS.MAC)
    void macOsMutationChildEnforcesCoreLimit() throws Exception {
        ChildResult probe = runChild("inspect", true, false);
        assumeTrue(
                "VERIFIED".equals(probe.values().get("NATIVE_LOCKED_MEMORY")),
                "NATIVE_LOCKED_MEMORY not verified on this runner: " + probe.output());

        ChildResult result = runChild("applyStrict", true, true);

        assertEquals(0, result.exitCode(), result.output());
        assertNull(result.values().get("thrown"), result.output());
        assertEffective(result.values().get("POSIX_CORE_RLIMIT_ZERO"), result.output());
        assertNull(result.values().get("LINUX_DUMPABLE_ZERO"), result.output());
    }

    private static void assertEffective(String status, String output) {
        assertTrue(
                "ENFORCED".equals(status) || "VERIFIED".equals(status),
                "expected ENFORCED or VERIFIED but was " + status + "; output:\n" + output);
    }

    private static ChildResult runChild(
            String mode, boolean enableNativeAccess, boolean disableAttach) throws Exception {
        Process process = moduleChild(mode, enableNativeAccess, disableAttach).start();
        StringBuilder output = new StringBuilder();
        Thread reader =
                new Thread(
                        () -> {
                            try (var input = process.getInputStream()) {
                                output.append(
                                        new String(input.readAllBytes(), StandardCharsets.UTF_8));
                            } catch (IOException e) {
                                output.append("READ_ERROR=").append(e.getMessage());
                            }
                        });
        reader.setDaemon(true);
        reader.start();
        boolean exited = process.waitFor(60, TimeUnit.SECONDS);
        reader.join(5000);
        if (!exited) {
            process.destroyForcibly().waitFor();
            fail("child did not exit within 60s; output:\n" + output);
        }
        String out = output.toString();
        return new ChildResult(process.exitValue(), parse(out), out);
    }

    private static ProcessBuilder moduleChild(
            String mode, boolean enableNativeAccess, boolean disableAttach) {
        String exe =
                System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")
                        ? "java.exe"
                        : "java";
        Path java = Path.of(System.getProperty("java.home"), "bin", exe);
        String modulePath = System.getProperty("keystead.modulePath");
        String testClassesDir = System.getProperty("keystead.testClassesDir");
        String coreModule = System.getProperty("keystead.coreModule");
        List<String> cmd = new ArrayList<>();
        cmd.add(java.toString());
        cmd.add("--module-path");
        cmd.add(modulePath);
        cmd.add("--add-modules");
        cmd.add(coreModule + ",ALL-MODULE-PATH");
        cmd.add("--patch-module");
        cmd.add(coreModule + "=" + testClassesDir);
        cmd.add("--add-reads=" + coreModule + "=ALL-UNNAMED");
        if (enableNativeAccess) {
            cmd.add("--enable-native-access=" + coreModule);
        } else {
            cmd.add("--illegal-native-access=deny");
        }
        if (disableAttach) {
            cmd.add("-XX:+DisableAttachMechanism");
        }
        cmd.add("-m");
        cmd.add(coreModule + "/top.focess.keystead.security.HardeningProbeMain");
        cmd.add(mode);
        return new ProcessBuilder(cmd).redirectErrorStream(true);
    }

    private static Map<String, String> parse(String output) {
        Map<String, String> values = new HashMap<>();
        for (String line : output.split("\\R")) {
            int eq = line.indexOf('=');
            if (eq > 0) {
                values.put(line.substring(0, eq), line.substring(eq + 1));
            }
        }
        return values;
    }

    private record ChildResult(int exitCode, Map<String, String> values, String output) {}
}
