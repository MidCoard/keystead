package top.focess.keystead.security;

/**
 * Stable status of one process-hardening control at report-return time.
 *
 * @see ProcessHardeningReport
 */
public enum HardeningStatus {
    /** This call changed the control and then read it back as effective. */
    ENFORCED,
    /** The control was already effective and was read back by this call. */
    VERIFIED,
    /** The control is supported and observable but is currently ineffective. */
    NOT_ENFORCED,
    /** Core cannot safely enforce or authoritatively verify this deployment responsibility. */
    APPLICATION_REQUIRED,
    /** This runtime cannot inspect or apply a control that should be supported. */
    UNAVAILABLE,
    /** An attempted process mutation or its read-back verification failed. */
    FAILED,
    /** A prior failure prevented this later mutation in the fixed order. */
    NOT_ATTEMPTED
}
