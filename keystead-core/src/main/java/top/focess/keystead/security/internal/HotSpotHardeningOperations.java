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
}
