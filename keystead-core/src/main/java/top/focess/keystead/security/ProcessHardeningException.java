package top.focess.keystead.security;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Redacted unchecked failure raised when strict process hardening cannot be fully established.
 *
 * <p>Carries a complete {@link ProcessHardeningReport}. The message, {@link #toString()}, and
 * suppressed graph never contain secret bytes, command lines, library paths, usernames, or
 * filesystem paths.
 */
public final class ProcessHardeningException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** The redacted report describing the unmet prerequisites or failed mutations. */
    private final @NonNull ProcessHardeningReport report;

    /**
     * Creates the exception carrying the complete hardening report.
     *
     * @param report the redacted report describing the unmet prerequisites or failed mutations
     */
    public ProcessHardeningException(@NonNull ProcessHardeningReport report) {
        super(message(report), null);
        this.report = Objects.requireNonNull(report, "report");
    }

    /**
     * Returns the complete hardening report captured at failure time.
     *
     * @return the complete hardening report captured at failure time
     */
    public @NonNull ProcessHardeningReport report() {
        return report;
    }

    @Override
    public @NonNull String toString() {
        return "ProcessHardeningException[platform="
                + report.platform()
                + ", controls="
                + report.results().size()
                + "]";
    }

    private static @NonNull String message(@NonNull ProcessHardeningReport report) {
        return "Process hardening could not be fully established [platform="
                + report.platform()
                + ", controls="
                + report.results().size()
                + "]";
    }
}
