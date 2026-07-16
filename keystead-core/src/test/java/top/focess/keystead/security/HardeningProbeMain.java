package top.focess.keystead.security;

/**
 * Child-JVM probe launched by {@link ProcessHardeningSubprocessTest} to exercise {@link
 * ProcessHardening} with launcher flags (native access, attach disabling, deny mode) that cannot be
 * applied to the Gradle test worker.
 *
 * <p>Args: {@code inspect} (default) or {@code applyStrict}. Prints one {@code key=value} line per
 * report field to standard output: {@code platform=<NativePlatform>}, then {@code
 * <HardeningControl>=<HardeningStatus>} for each applicable control. Exits {@code 0} on a returned
 * report, {@code 1} if {@code applyStrict} raises {@link ProcessHardeningException} (the report is
 * still printed with {@code thrown=true}), or {@code 2} on any other throwable. Output is redacted:
 * only control names, statuses, and the platform enum appear.
 */
public final class HardeningProbeMain {

    private HardeningProbeMain() {}

    public static void main(String[] args) {
        String mode = args.length == 0 ? "inspect" : args[0];
        try {
            ProcessHardeningReport report =
                    "applyStrict".equals(mode)
                            ? ProcessHardening.applyStrict()
                            : ProcessHardening.inspect();
            print(report, false);
        } catch (ProcessHardeningException e) {
            print(e.report(), true);
            System.exit(1);
        } catch (Throwable t) {
            // Print only the exception type; messages may carry library paths or other fragments.
            System.out.println("unexpected=" + t.getClass().getName());
            System.exit(2);
        }
    }

    private static void print(ProcessHardeningReport report, boolean thrown) {
        System.out.println("platform=" + report.platform().name());
        if (thrown) {
            System.out.println("thrown=true");
        }
        for (HardeningResult result : report.results()) {
            System.out.println(result.control().name() + "=" + result.status().name());
        }
    }
}
