package top.focess.keystead.service;

/** Why an encrypted server row was ignored before it could mutate the local vault. */
public enum SyncImportRejectionReason {
    /** The row advertises a different vault fingerprint. */
    WRONG_VAULT,

    /** The row is malformed or cannot be authenticated with the open vault key. */
    UNVERIFIABLE
}
