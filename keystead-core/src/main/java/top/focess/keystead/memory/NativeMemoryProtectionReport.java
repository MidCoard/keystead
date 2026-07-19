package top.focess.keystead.memory;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Immutable snapshot of native-memory protection capabilities.
 *
 * @param platform the detected native platform
 * @param results one result per {@link NativeProtectionControl}, in enum order
 */
public record NativeMemoryProtectionReport(
        @NonNull NativePlatform platform, @NonNull List<@NonNull NativeProtectionResult> results) {

    /** Validates the components and requires one result per control in enum order. */
    public NativeMemoryProtectionReport {
        Objects.requireNonNull(platform, "platform");
        results = List.copyOf(Objects.requireNonNull(results, "results"));
        requireCompleteEnumOrder(results);
    }

    /**
     * Returns the detected native platform.
     *
     * @return the detected native platform
     */
    @Override
    public @NonNull NativePlatform platform() {
        return platform;
    }

    /**
     * Returns the per-control results in {@link NativeProtectionControl} enum order.
     *
     * @return the per-control results in enum order
     */
    @Override
    public @NonNull List<@NonNull NativeProtectionResult> results() {
        return results;
    }

    /**
     * Returns the result for one control.
     *
     * @param control the control to look up
     * @return the result for {@code control}
     */
    public @Nullable NativeProtectionResult result(@NonNull NativeProtectionControl control) {
        Objects.requireNonNull(control, "control");
        return results.get(control.ordinal());
    }

    @Override
    public @NonNull String toString() {
        return "NativeMemoryProtectionReport[platform=" + platform + ", results=" + results + "]";
    }

    private static void requireCompleteEnumOrder(
            @NonNull List<@NonNull NativeProtectionResult> results) {
        NativeProtectionControl[] controls = NativeProtectionControl.values();
        if (results.size() != controls.length) {
            throw new IllegalArgumentException(
                    "Native protection report must contain every control exactly once");
        }
        for (int index = 0; index < controls.length; index++) {
            if (results.get(index).control() != controls[index]) {
                throw new IllegalArgumentException(
                        "Native protection report controls must be in enum order");
            }
        }
    }
}
