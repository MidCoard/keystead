package top.focess.keystead.security.internal;

import com.sun.management.HotSpotDiagnosticMXBean;
import java.lang.management.ManagementFactory;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativeMemoryProtection;
import top.focess.keystead.memory.NativeMemoryProtectionReport;
import top.focess.keystead.memory.NativePlatform;

/** Real {@link ProcessHardeningOperations} backed by HotSpot diagnostics and the native probe. */
public final class HotSpotHardeningOperations implements ProcessHardeningOperations {

    private final @Nullable HotSpotDiagnosticMXBean mxBean;
    private @Nullable NativeMemoryProtectionReport cachedProbe;
    private @Nullable PosixHardeningCalls posixCalls;

    public HotSpotHardeningOperations() {
        this.mxBean = ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class);
    }

    @Override
    public @NonNull NativePlatform platform() {
        return nativeMemoryProbe().platform();
    }

    @Override
    public int javaMajorVersion() {
        return Runtime.version().feature();
    }

    @Override
    public boolean nativeAccessEnabled() {
        return HotSpotHardeningOperations.class.getModule().isNativeAccessEnabled();
    }

    @Override
    public @Nullable String hotSpotOption(@NonNull String name) {
        if (mxBean == null) {
            return null;
        }
        try {
            return mxBean.getVMOption(name).getValue();
        } catch (IllegalArgumentException optionAbsent) {
            return null;
        }
    }

    @Override
    public @NonNull NativeMemoryProtectionReport nativeMemoryProbe() {
        NativeMemoryProtectionReport report = cachedProbe;
        if (report == null) {
            report = NativeMemoryProtection.inspect();
            cachedProbe = report;
        }
        return report;
    }

    @Override
    public @Nullable Integer readDumpable() {
        return canReadPosixState() ? posixCalls().readDumpable() : null;
    }

    @Override
    public @Nullable CoreLimit readCoreLimit() {
        return canReadPosixState() ? posixCalls().readCoreLimit() : null;
    }

    @Override
    public @NonNull MutationResult setDumpableZero() {
        // prctl(PR_SET_DUMPABLE, 0) is wired with its subprocess mutation evidence in a later task.
        return MutationResult.failure(0L);
    }

    @Override
    public @NonNull MutationResult setCoreLimitZero() {
        // setrlimit(RLIMIT_CORE, 0, 0) is wired with its subprocess mutation evidence in a later
        // task.
        return MutationResult.failure(0L);
    }

    private boolean isPosixPlatform() {
        NativePlatform platform = platform();
        return platform == NativePlatform.LINUX_X86_64
                || platform == NativePlatform.LINUX_AARCH64
                || platform == NativePlatform.MACOS_X86_64
                || platform == NativePlatform.MACOS_AARCH64;
    }

    /**
     * POSIX reads require both a POSIX platform and enabled module native access; without native
     * access the restricted {@code downcallHandle} would throw {@code IllegalCallerException}, so
     * the reads degrade to {@code null} (reported {@code UNAVAILABLE}) instead of throwing.
     */
    private boolean canReadPosixState() {
        return isPosixPlatform() && nativeAccessEnabled();
    }

    private @NonNull PosixHardeningCalls posixCalls() {
        PosixHardeningCalls existing = posixCalls;
        if (existing == null) {
            existing = new PosixHardeningCalls(platform());
            posixCalls = existing;
        }
        return existing;
    }
}
