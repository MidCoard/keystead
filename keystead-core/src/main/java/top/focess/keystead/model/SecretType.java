package top.focess.keystead.model;

/**
 * The canonical vocabulary of secret types. {@code LOGIN_PASSWORD} and {@code SECURE_NOTE} use
 * dedicated payload formats; the remaining types share the structured payload format.
 */
public enum SecretType {
    /** A reusable login credential pair (username and password). */
    LOGIN_PASSWORD,
    /** A free-form encrypted note. */
    SECURE_NOTE,
    /** An SSH key pair with an optional passphrase. */
    SSH_KEY,
    /** A long-lived API token. */
    API_TOKEN,
    /** A GPG key pair with an optional passphrase. */
    GPG_KEY,
    /** A multi-factor authentication secret and recovery codes. */
    MFA_SECRET,
    /** An X.509 certificate with its private key. */
    CERTIFICATE,
    /** A generic secret with arbitrary custom fields. */
    GENERIC_SECRET
}
