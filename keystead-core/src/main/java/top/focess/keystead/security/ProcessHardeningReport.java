package top.focess.keystead.security;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativePlatform;

/**
 * Immutable snapshot of process-hardening controls for the detected platform.
 *
 * <p>Contains only the controls applicable to the detected {@link NativePlatform}, in
 * {@link HardeningControl} enum order, exactly one entry per applicable control. Reports are
 * snapshots, not durable attestations. {@link HardeningControl}s absent from the list are not
 * applicable to the platform rather than assigned a misleading status.
 */
public record ProcessHardeningReport(
        @NonNull NativePlatform platform, @NonNull List<@NonNull HardeningResult> results) {

    public ProcessHardeningReport {
        Objects.requireNonNull(platform, "platform");
        results = List.copyOf(Objects.requireNonNull(results, "results"));
        requireApplicableEnumOrder(results);
    }

    public @NonNull NativePlatform platform() {
        return platform;
    }

    public @NonNull List<@NonNull HardeningResult> results() {
        return results;
    }

    public @Nullable HardeningResult result(@NonNull HardeningControl control) {
        Objects.requireNonNull(control, "control");
        for (HardeningResult current : results) {
            if (current.control() == control) {
                return current;
            }
        }
        return null;
    }

    @Override
    public @NonNull String toString() {
        return "ProcessHardeningReport[platform=" + platform + ", results=" + results + "]";
    }

    private static void requireApplicableEnumOrder(
            @NonNull List<@NonNull HardeningResult> results) {
        int lastOrdinal = -1;
        for (HardeningResult current : results) {
            int ordinal = current.control().ordinal();
            if (ordinal <= lastOrdinal) {
                throw new IllegalArgumentException(
                        "Hardening results must be in control enum order without duplicates");
            }
            lastOrdinal = ordinal;
        }
    }
}
