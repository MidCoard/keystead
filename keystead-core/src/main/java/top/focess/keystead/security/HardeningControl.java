package top.focess.keystead.security;

/**
 * Stable process-hardening control identifiers. Consumers must ignore future controls they do not
 * understand rather than assume an exhaustive set. Controls not applicable to the detected platform
 * are absent from a {@link ProcessHardeningReport} rather than assigned a misleading status.
 */
public enum HardeningControl {
    /** The runtime is Java 25 or later, as required by the native-memory default. */
    JAVA_25_OR_LATER,
    /** The Keystead Core module has native access enabled. */
    MODULE_NATIVE_ACCESS,
    /** The JVM runs with {@code --illegal-native-access=deny}. */
    ILLEGAL_NATIVE_ACCESS_DENY,
    /** The JVM attach mechanism is disabled ({@code -XX:+DisableAttachMechanism}). */
    JVM_ATTACH_DISABLED,
    /** Heap dumps on {@code OutOfMemoryError} are disabled. */
    HEAP_DUMP_ON_OOME_DISABLED,
    /** Fail-closed native locked memory is available for secret storage. */
    NATIVE_LOCKED_MEMORY,
    /** JVM diagnostic dump output is isolated from secret-bearing memory. */
    JVM_DIAGNOSTIC_DUMP_ISOLATION,
    /** The operating system crash-dump policy excludes this process's memory. */
    OS_CRASH_DUMP_POLICY,
    /** The process is isolated from unrelated debuggers. */
    OS_DEBUGGER_ISOLATION,
    /** The process runs under a dedicated, non-shared account identity. */
    DEDICATED_PROCESS_IDENTITY,
    /** Linux {@code PR_GET_DUMPABLE} reports the process is not dumpable. */
    LINUX_DUMPABLE_ZERO,
    /** The POSIX {@code RLIMIT_CORE} soft and hard limits are zero. */
    POSIX_CORE_RLIMIT_ZERO,
    /** The system Yama {@code ptrace_scope} restricts cross-process tracing. */
    LINUX_YAMA_PTRACE_SCOPE,
    /** The service manager sandboxes the process (application deployment requirement). */
    LINUX_SERVICE_SANDBOX,
    /** The application is signed with the macOS Hardened Runtime. */
    MACOS_HARDENED_RUNTIME,
    /** The application is notarized by Apple. */
    MACOS_NOTARIZATION,
    /** The {@code get-task-allow} entitlement is absent from the signature. */
    MACOS_GET_TASK_ALLOW_ABSENT,
    /** macOS library validation restricts dynamic library loading. */
    MACOS_LIBRARY_VALIDATION,
    /** The process does not run as a privileged (root or administrator) account. */
    PRIVILEGED_ACCOUNT_SEPARATION
}
