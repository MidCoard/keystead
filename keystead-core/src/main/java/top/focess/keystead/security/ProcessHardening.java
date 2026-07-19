package top.focess.keystead.security;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.security.internal.HotSpotHardeningOperations;
import top.focess.keystead.security.internal.ProcessHardeningInspector;

/**
 * Process-wide hardening inspection and strict application for the current platform.
 *
 * <p>{@link #inspect()} returns a redacted {@link ProcessHardeningReport} snapshot of the
 * applicable controls without mutating, so it never reports {@link HardeningStatus#ENFORCED}.
 * Deployment responsibilities Core cannot safely enforce are reported as
 * {@link HardeningStatus#APPLICATION_REQUIRED}.
 */
public final class ProcessHardening {

    private ProcessHardening() {}

    /**
     * Inspects the applicable process-hardening controls without mutating the process.
     *
     * @return a redacted snapshot report; never reports {@link HardeningStatus#ENFORCED}
     */
    public static @NonNull ProcessHardeningReport inspect() {
        return ProcessHardeningInspector.inspect(new HotSpotHardeningOperations());
    }

    /**
     * Applies strict process hardening for the current platform.
     *
     * <p>Serialized, monotonic, idempotent, and non-transactional. Completes every immutable
     * prerequisite preflight before mutating; on Linux sets and verifies dumpability and the core
     * limit, on macOS sets and verifies the core limit. Throws {@link ProcessHardeningException}
     * with a complete redacted report if a prerequisite is unmet or a mutation fails.
     *
     * <p>The hard {@code RLIMIT_CORE} limit is lowered irreversibly for an unprivileged process, so
     * {@code applyStrict()} is intended to run in an expendable child JVM rather than a long-lived
     * host process; {@link ProcessHardening#inspect()} is the non-mutating entry point.
     *
     * @return a redacted report of the resulting control states
     * @throws ProcessHardeningException if a prerequisite is unmet or a mutation fails; carries the
     *     complete redacted report
     */
    public static @NonNull ProcessHardeningReport applyStrict() {
        return ProcessHardeningInspector.applyStrict(new HotSpotHardeningOperations());
    }
}
