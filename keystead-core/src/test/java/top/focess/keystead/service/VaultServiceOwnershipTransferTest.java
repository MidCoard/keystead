package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.testing.RecordingSecretMemoryProvider;

class VaultServiceOwnershipTransferTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-15T00:00:00Z"), ZoneOffset.UTC);

    @TempDir Path tempDir;

    @Test
    void createClosesGeneratedKeyWhenHandleFactoryThrowsAssertionError() {
        Fixture fixture = fixture("create");

        assertThrows(
                AssertionError.class,
                () ->
                        fixture.throwingService.createVault(
                                fixture.vaultFile, "password".toCharArray()));

        assertTrue(fixture.memory.lastOwner().isClosed());
    }

    @Test
    void openClosesUnwrappedKeyWhenHandleFactoryThrowsAssertionError() {
        Fixture fixture = initializedFixture("open");
        int previousOwners = fixture.memory.ownerCount();

        assertThrows(
                AssertionError.class,
                () ->
                        fixture.throwingService.openVault(
                                fixture.vaultFile, "password".toCharArray()));

        assertTrue(fixture.memory.owner(previousOwners).isClosed());
    }

    @Test
    void rotateClosesGeneratedKeyWhenHandleFactoryThrowsAssertionError() {
        Fixture fixture = initializedFixture("rotate");

        assertThrows(
                AssertionError.class,
                () ->
                        fixture.throwingService.rotateVaultKey(
                                fixture.vaultFile, "password".toCharArray()));

        assertTrue(fixture.memory.lastOwner().isClosed());
    }

    @Test
    void deviceOpenClosesUnwrappedKeyWhenHandleFactoryThrowsAssertionError() {
        Fixture fixture = initializedFixture("device-open");
        byte[] context = {4, 5, 6};
        Path provisionedFile = tempDir.resolve("device-open-provisioned.kv");
        try (DeviceKeyPair device = fixture.crypto.generateDeviceKeyPair();
                VaultHandle passwordVault =
                        fixture.normalService.openVault(
                                fixture.vaultFile, "password".toCharArray())) {
            DeviceVaultKeyPackage keyPackage =
                    passwordVault.wrapVaultKeyPackageForDevice(device.publicKey(), context);
            device.copyPrivateKey(
                    privateKey -> {
                        try (VaultHandle ignored =
                                fixture.normalService.provisionVault(
                                        provisionedFile, keyPackage, privateKey, context)) {
                            // The provisioned handle transfers and then closes its own key.
                        }
                        int previousOwners = fixture.memory.ownerCount();
                        assertThrows(
                                AssertionError.class,
                                () ->
                                        fixture.throwingService.openVaultWithDeviceKey(
                                                provisionedFile, privateKey, context));
                        assertTrue(fixture.memory.owner(previousOwners).isClosed());
                    });
        }
    }

    private Fixture initializedFixture(String directory) {
        Fixture fixture = fixture(directory);
        try (VaultHandle ignored =
                fixture.normalService.createVault(fixture.vaultFile, "password".toCharArray())) {
            return fixture;
        }
    }

    private Fixture fixture(String directory) {
        RecordingSecretMemoryProvider memory = new RecordingSecretMemoryProvider();
        DefaultCryptoService crypto =
                new DefaultCryptoService(
                        new SecureRandom(),
                        new top.focess.keystead.crypto.TinkAesGcmCipher(),
                        memory);
        Path vaultFile = tempDir.resolve(directory + ".kv");
        DefaultVaultService normalService = new DefaultVaultService(crypto, CLOCK);
        DefaultVaultService throwingService =
                new DefaultVaultService(
                        crypto,
                        CLOCK,
                        store -> {
                            throw new AssertionError("injected handle construction failure");
                        });
        return new Fixture(vaultFile, crypto, memory, normalService, throwingService);
    }

    private record Fixture(
            Path vaultFile,
            DefaultCryptoService crypto,
            RecordingSecretMemoryProvider memory,
            DefaultVaultService normalService,
            DefaultVaultService throwingService) {}
}
