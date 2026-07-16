package top.focess.keystead.model;

/**
 * Classifies the sensitivity and storage treatment of a secret field.
 */
public enum SecretFieldType {
    /** A non-secret, publicly displayable text value. */
    TEXT,
    /** A sensitive value that is encrypted at rest and revealed on demand. */
    SECRET,
    /** A binary blob value. */
    BINARY
}
