package top.focess.keystead.service;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.model.SecretType;

/** Isolated JVM fixture exercising the real platform-dependent serializer and sync APIs. */
public final class CrossPlatformSyncProbeMain {
    private CrossPlatformSyncProbeMain() {}

    public static void main(String[] args) throws Exception {
        var clock = Clock.fixed(Instant.parse("2026-09-05T01:02:03.123456789Z"), ZoneOffset.UTC);
        var service = new DefaultVaultService(new DefaultCryptoService(), clock);
        Path vaultPath = Path.of(args[1]);
        try (var vault = service.openVault(vaultPath, "cross-platform-fixture".toCharArray())) {
            if (args[0].equals("save")) {
                try (var value =
                        SecretBuffer.fromChars(
                                "fixture-only-value".toCharArray(), SecretMemoryProvider.heap())) {
                    vault.saveSecret(
                            SecretType.GENERIC_SECRET,
                            d ->
                                    d.title("Cross-platform 测试")
                                            .field("value", value)
                                            .tag("work")
                                            .attribute("expiry", "2030-01-01"));
                }
            } else {
                var report = vault.importRecordsWithReport(List.of(read(Path.of(args[2]))));
                if (!report.rejected().isEmpty())
                    throw new IllegalStateException("Import rejected valid fixture");
                System.out.print("imported=" + report.imported() + ";skipped=" + report.skipped());
            }
            write(Path.of(args[3]), vault.exportRecordsSince(0).getFirst());
        }
    }

    static void write(Path path, EncryptedSyncRecord row) throws Exception {
        try (var out = new DataOutputStream(Files.newOutputStream(path))) {
            out.writeUTF(row.fingerprint());
            out.writeUTF(row.secretId());
            out.writeLong(row.revision());
            out.writeUTF(row.secretType());
            out.writeUTF(row.encryptedProfile());
            out.writeUTF(row.envelope());
            out.writeBoolean(row.deleted());
            out.writeUTF(row.contentKey());
        }
    }

    static EncryptedSyncRecord read(Path path) throws Exception {
        try (var in = new DataInputStream(Files.newInputStream(path))) {
            return new EncryptedSyncRecord(
                    in.readUTF(),
                    in.readUTF(),
                    in.readLong(),
                    in.readUTF(),
                    in.readUTF(),
                    in.readUTF(),
                    in.readBoolean(),
                    in.readUTF());
        }
    }
}
