package top.focess.keystead.model;

/**
 * The canonical vocabulary of secret types. {@code LOGIN_PASSWORD} and {@code SECURE_NOTE} use
 * dedicated payload formats; the remaining types share the structured payload format.
 */
public enum SecretType {
    LOGIN_PASSWORD,
    SECURE_NOTE,
    SSH_KEY,
    API_TOKEN,
    GPG_KEY,
    MFA_SECRET,
    CERTIFICATE,
    GENERIC_SECRET
}
