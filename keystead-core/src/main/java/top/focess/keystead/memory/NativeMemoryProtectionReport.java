package top.focess.keystead.memory;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Immutable snapshot of native-memory protection capabilities. */
public record NativeMemoryProtectionReport(
        @NonNull NativePlatform platform, @NonNull List<@NonNull NativeProtectionResult> results) {

    public NativeMemoryProtectionReport {
        Objects.requireNonNull(platform, "platform");
        results = List.copyOf(Objects.requireNonNull(results, "results"));
        requireCompleteEnumOrder(results);
    }

    @Override
    public @NonNull NativePlatform platform() {
        return platform;
    }

    @Override
    public @NonNull List<@NonNull NativeProtectionResult> results() {
        return results;
    }

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
