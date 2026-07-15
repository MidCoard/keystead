package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.FileVaultStore;
import top.focess.keystead.testing.RecordingSecretMemoryProvider;

class VaultServiceOwnershipTransferTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-15T00:00:00Z"), ZoneOffset.UTC);

    @TempDir java.nio.file.Path tempDir;

    @Test
    void createClosesGeneratedKeyWhenHandleFactoryThrowsAssertionError() {
        Fixture fixture = fixture("create");

        assertThrows(
                AssertionError.class,
                () ->
                        fixture.throwingService.createVault(
                                new CreateVaultRequest(fixture.vaultId), "password".toCharArray()));

        assertTrue(fixture.memory.lastOwner().isClosed());
    }

    @Test
    void openClosesUnwrappedKeyWhenHandleFactoryThrowsAssertionError() {
        Fixture fixture = initializedFixture("open");
        int previousOwners = fixture.memory.ownerCount();

        assertThrows(
                AssertionError.class,
                () -> fixture.throwingService.openVault(fixture.vaultId, "password".toCharArray()));

        assertTrue(fixture.memory.owner(previousOwners).isClosed());
    }

    @Test
    void rotateClosesGeneratedKeyWhenHandleFactoryThrowsAssertionError() {
        Fixture fixture = initializedFixture("rotate");

        assertThrows(
                AssertionError.class,
                () ->
                        fixture.throwingService.rotateVaultKey(
                                fixture.vaultId, "password".toCharArray()));

        assertTrue(fixture.memory.lastOwner().isClosed());
    }

    @Test
    void deviceOpenClosesUnwrappedKeyWhenHandleFactoryThrowsAssertionError() {
        Fixture fixture = initializedFixture("device-open");
        byte[] context = {4, 5, 6};
        try (DeviceKeyPair device = fixture.crypto.generateDeviceKeyPair();
                VaultHandle passwordVault =
                        fixture.normalService.openVault(
                                fixture.vaultId, "password".toCharArray())) {
            DeviceVaultKeyPackage keyPackage =
                    passwordVault.wrapVaultKeyPackageForDevice(device.publicKey(), context);
            device.copyPrivateKey(
                    privateKey -> {
                        try (VaultHandle ignored =
                                fixture.normalService.provisionVault(
                                        fixture.vaultId, keyPackage, privateKey, context)) {
                            // The provisioned handle transfers and then closes its own key.
                        }
                        int previousOwners = fixture.memory.ownerCount();
                        assertThrows(
                                AssertionError.class,
                                () ->
                                        fixture.throwingService.openVaultWithDeviceKey(
                                                fixture.vaultId, privateKey, context));
                        assertTrue(fixture.memory.owner(previousOwners).isClosed());
                    });
        }
    }

    private Fixture initializedFixture(String directory) {
        Fixture fixture = fixture(directory);
        try (VaultHandle ignored =
                fixture.normalService.createVault(
                        new CreateVaultRequest(fixture.vaultId), "password".toCharArray())) {
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
        FileVaultStore store = new FileVaultStore(tempDir.resolve(directory));
        VaultId vaultId = new VaultId(UUID.randomUUID());
        DefaultVaultService normalService = new DefaultVaultService(store, crypto, CLOCK);
        DefaultVaultService throwingService =
                new DefaultVaultService(
                        store,
                        crypto,
                        CLOCK,
                        (id, key, targetStore, targetCrypto, clock) -> {
                            throw new AssertionError("injected handle construction failure");
                        });
        return new Fixture(vaultId, crypto, memory, normalService, throwingService);
    }

    private record Fixture(
            VaultId vaultId,
            DefaultCryptoService crypto,
            RecordingSecretMemoryProvider memory,
            DefaultVaultService normalService,
            DefaultVaultService throwingService) {}
}
