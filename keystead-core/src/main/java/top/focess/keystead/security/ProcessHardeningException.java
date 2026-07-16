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

    private final @NonNull ProcessHardeningReport report;

    public ProcessHardeningException(@NonNull ProcessHardeningReport report) {
        super(message(report), null);
        this.report = Objects.requireNonNull(report, "report");
    }

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
