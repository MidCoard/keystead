package top.focess.keystead.security;

/**
 * Stable process-hardening control identifiers. Consumers must ignore future controls they do not
 * understand rather than assume an exhaustive set. Controls not applicable to the detected platform
 * are absent from a {@link ProcessHardeningReport} rather than assigned a misleading status.
 */
public enum HardeningControl {
    JAVA_25_OR_LATER,
    MODULE_NATIVE_ACCESS,
    ILLEGAL_NATIVE_ACCESS_DENY,
    JVM_ATTACH_DISABLED,
    HEAP_DUMP_ON_OOME_DISABLED,
    NATIVE_LOCKED_MEMORY,
    JVM_DIAGNOSTIC_DUMP_ISOLATION,
    OS_CRASH_DUMP_POLICY,
    OS_DEBUGGER_ISOLATION,
    DEDICATED_PROCESS_IDENTITY,
    LINUX_DUMPABLE_ZERO,
    POSIX_CORE_RLIMIT_ZERO,
    LINUX_YAMA_PTRACE_SCOPE,
    LINUX_SERVICE_SANDBOX,
    MACOS_HARDENED_RUNTIME,
    MACOS_NOTARIZATION,
    MACOS_GET_TASK_ALLOW_ABSENT,
    MACOS_LIBRARY_VALIDATION,
    PRIVILEGED_ACCOUNT_SEPARATION
}
