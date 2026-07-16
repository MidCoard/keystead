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

/**
 * Deterministic, stateful fake {@link ProcessHardeningOperations} for control tests. Mutation
 * operations update the readable state so {@code applyStrict()} read-backs observe the change.
 */
final class FakeHardeningOperations implements ProcessHardeningOperations {

    private final @NonNull NativePlatform platform;
    private final int javaMajorVersion;
    private final boolean nativeAccessEnabled;
    private final @NonNull Map<@NonNull String, @NonNull String> hotSpotOptions;
    private final @NonNull NativeMemoryProtectionReport probe;

    private @Nullable Integer dumpable;
    private @Nullable CoreLimit coreLimit;
    private boolean dumpableMutationSucceeds = true;
    private boolean coreLimitMutationSucceeds = true;
    private long dumpableMutationErrorCode;
    private long coreLimitMutationErrorCode;

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

    @Override
    public @Nullable Integer readDumpable() {
        return dumpable;
    }

    @Override
    public @Nullable CoreLimit readCoreLimit() {
        return coreLimit;
    }

    @Override
    public @NonNull MutationResult setDumpableZero() {
        if (dumpableMutationSucceeds) {
            dumpable = 0;
            return MutationResult.success();
        }
        return MutationResult.failure(dumpableMutationErrorCode);
    }

    @Override
    public @NonNull MutationResult setCoreLimitZero() {
        if (coreLimitMutationSucceeds) {
            coreLimit = new CoreLimit(0L, 0L);
            return MutationResult.success();
        }
        return MutationResult.failure(coreLimitMutationErrorCode);
    }

    static final class Builder {
        private final @NonNull NativePlatform platform;
        private int javaMajorVersion = 25;
        private boolean nativeAccessEnabled = true;
        private final @NonNull Map<@NonNull String, @NonNull String> hotSpotOptions =
                new HashMap<>();
        private @NonNull NativeProtectionStatus allocationStatus = NativeProtectionStatus.VERIFIED;
        private @Nullable Integer dumpable;
        private @Nullable CoreLimit coreLimit;
        private boolean dumpableMutationSucceeds = true;
        private long dumpableMutationErrorCode;
        private boolean coreLimitMutationSucceeds = true;
        private long coreLimitMutationErrorCode;

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

        @NonNull Builder dumpable(int value) {
            this.dumpable = value;
            return this;
        }

        @NonNull Builder coreLimit(long soft, long hard) {
            this.coreLimit = new CoreLimit(soft, hard);
            return this;
        }

        @NonNull Builder dumpableMutationFails(long errorCode) {
            this.dumpableMutationSucceeds = false;
            this.dumpableMutationErrorCode = errorCode;
            return this;
        }

        @NonNull Builder coreLimitMutationFails(long errorCode) {
            this.coreLimitMutationSucceeds = false;
            this.coreLimitMutationErrorCode = errorCode;
            return this;
        }

        @NonNull FakeHardeningOperations build() {
            FakeHardeningOperations operations =
                    new FakeHardeningOperations(
                            platform,
                            javaMajorVersion,
                            nativeAccessEnabled,
                            hotSpotOptions,
                            probeReport());
            operations.dumpable = dumpable;
            operations.coreLimit = coreLimit;
            operations.dumpableMutationSucceeds = dumpableMutationSucceeds;
            operations.dumpableMutationErrorCode = dumpableMutationErrorCode;
            operations.coreLimitMutationSucceeds = coreLimitMutationSucceeds;
            operations.coreLimitMutationErrorCode = coreLimitMutationErrorCode;
            return operations;
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
