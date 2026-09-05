package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CrossPlatformSyncIdentityTest {
    @TempDir Path temp;

    @Test
    void importingAndReexportingAcrossLfAndCrLfPreservesContentIdentity() throws Exception {
        Path mac = temp.resolve("mac.vault"), windows = temp.resolve("windows.vault");
        try (var vault =
                new DefaultVaultService(
                                new top.focess.keystead.crypto.DefaultCryptoService(),
                                java.time.Clock.fixed(
                                        java.time.Instant.parse("2026-09-05T01:02:03.123456789Z"),
                                        java.time.ZoneOffset.UTC))
                        .createVault(mac, "cross-platform-fixture".toCharArray())) {}
        Files.copy(mac, windows);
        Path macRow = temp.resolve("mac.row"),
                windowsRow = temp.resolve("windows.row"),
                roundTrip = temp.resolve("roundtrip.row");
        run("\n", "save", mac, macRow, macRow);
        assertTrue(run("\r\n", "import", windows, macRow, windowsRow).contains("imported=1"));
        run("\n", "import", mac, windowsRow, roundTrip);
        var original = CrossPlatformSyncProbeMain.read(macRow);
        var imported = CrossPlatformSyncProbeMain.read(windowsRow);
        var returned = CrossPlatformSyncProbeMain.read(roundTrip);
        assertEquals(original.revision(), imported.revision());
        assertEquals(original.secretId(), imported.secretId());
        assertAll(
                () ->
                        assertEquals(
                                original.contentKey(),
                                imported.contentKey(),
                                "CRLF import/reexport changed unchanged content identity"),
                () ->
                        assertEquals(
                                SyncRecordEventId.of(original),
                                SyncRecordEventId.of(imported),
                                "CRLF reexport generated new event identity"),
                () ->
                        assertEquals(
                                imported.contentKey(),
                                returned.contentKey(),
                                "LF return trip changed unchanged content identity"));
    }

    private String run(String separator, String mode, Path vault, Path input, Path output)
            throws Exception {
        String exe =
                System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")
                        ? "java.exe"
                        : "java";
        String module = System.getProperty("keystead.coreModule");
        var command =
                new ArrayList<>(
                        List.of(
                                Path.of(System.getProperty("java.home"), "bin", exe).toString(),
                                "-Dline.separator=" + separator,
                                "--module-path",
                                System.getProperty("keystead.modulePath"),
                                "--add-modules",
                                module + ",ALL-MODULE-PATH",
                                "--patch-module",
                                module + "=" + System.getProperty("keystead.testClassesDir"),
                                "--enable-native-access=" + module,
                                "--sun-misc-unsafe-memory-access=allow",
                                "-m",
                                module + "/top.focess.keystead.service.CrossPlatformSyncProbeMain",
                                mode,
                                vault.toString(),
                                input.toString(),
                                output.toString()));
        Path log = temp.resolve(UUID.randomUUID() + ".log");
        Process process =
                new ProcessBuilder(command)
                        .redirectErrorStream(true)
                        .redirectOutput(log.toFile())
                        .start();
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Cross-platform child timed out");
            String result = Files.readString(log, StandardCharsets.UTF_8);
            assertEquals(0, process.exitValue(), result);
            return result;
        } finally {
            if (process.isAlive()) process.destroyForcibly();
        }
    }
}
