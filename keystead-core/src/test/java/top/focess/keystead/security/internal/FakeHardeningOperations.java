package top.focess.keystead.security.internal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativeMemoryProtectionReport;
import top.focess.keystead.memory.NativePlatform;
import top.focess.keystead.memory.NativeProtectionControl;
import top.focess.keystead.memory.NativeProtectionResult;
import top.focess.keystead.memory.NativeProtectionStatus;

/** Deterministic fake {@link ProcessHardeningOperations} for control tests. */
final class FakeHardeningOperations implements ProcessHardeningOperations {

    private final @NonNull NativePlatform platform;
    private final int javaMajorVersion;
    private final boolean nativeAccessEnabled;
    private final @NonNull Map<@NonNull String, @NonNull String> hotSpotOptions;
    private final @NonNull NativeMemoryProtectionReport probe;

    private FakeHardeningOperations(
            @NonNull NativePlatform platform,
            int javaMajorVersion,
            boolean nativeAccessEnabled,
            @NonNull Map<@NonNull String, @NonNull String> hotSpotOptions,
            @NonNull NativeMemoryProtectionReport probe) {
        this.platform = platform;
        this.javaMajorVersion = javaMajorVersion;
        this.nativeAccessEnabled = nativeAccessEnabled;
        this.hotSpotOptions = hotSpotOptions;
        this.probe = probe;
    }

    static @NonNull Builder windows() {
        return new Builder(NativePlatform.WINDOWS_X86_64);
    }

    static @NonNull Builder linux() {
        return new Builder(NativePlatform.LINUX_X86_64);
    }

    @Override
    public @NonNull NativePlatform platform() {
        return platform;
    }

    @Override
    public int javaMajorVersion() {
        return javaMajorVersion;
    }

    @Override
    public boolean nativeAccessEnabled() {
        return nativeAccessEnabled;
    }

    @Override
    public @Nullable String hotSpotOption(@NonNull String name) {
        return hotSpotOptions.get(name);
    }

    @Override
    public @NonNull NativeMemoryProtectionReport nativeMemoryProbe() {
        return probe;
    }

    static final class Builder {
        private final @NonNull NativePlatform platform;
        private int javaMajorVersion = 25;
        private boolean nativeAccessEnabled = true;
        private final @NonNull Map<@NonNull String, @NonNull String> hotSpotOptions =
                new HashMap<>();
        private @NonNull NativeProtectionStatus allocationStatus = NativeProtectionStatus.VERIFIED;

        Builder(@NonNull NativePlatform platform) {
            this.platform = platform;
        }

        @NonNull Builder javaVersion(int version) {
            this.javaMajorVersion = version;
            return this;
        }

        @NonNull Builder nativeAccess(boolean enabled) {
            this.nativeAccessEnabled = enabled;
            return this;
        }

        @NonNull Builder hotSpotOption(@NonNull String name, @NonNull String value) {
            hotSpotOptions.put(name, value);
            return this;
        }

        @NonNull Builder allocationStatus(@NonNull NativeProtectionStatus status) {
            this.allocationStatus = status;
            return this;
        }

        @NonNull FakeHardeningOperations build() {
            return new FakeHardeningOperations(
                    platform, javaMajorVersion, nativeAccessEnabled, hotSpotOptions, probeReport());
        }

        private @NonNull NativeMemoryProtectionReport probeReport() {
            List<NativeProtectionResult> results = new ArrayList<>();
            for (NativeProtectionControl control : NativeProtectionControl.values()) {
                NativeProtectionStatus status =
                        control == NativeProtectionControl.ALLOCATION
                                ? allocationStatus
                                : NativeProtectionStatus.VERIFIED;
                String detail =
                        status == NativeProtectionStatus.VERIFIED
                                ? NativeProtectionResult.DETAIL_OPERATION_VERIFIED
                                : status == NativeProtectionStatus.FAILED
                                        ? NativeProtectionResult.DETAIL_OPERATION_FAILED
                                        : NativeProtectionResult.DETAIL_NOT_ATTEMPTED;
                results.add(new NativeProtectionResult(control, status, detail, null));
            }
            return new NativeMemoryProtectionReport(platform, results);
        }
    }
}
