package top.focess.keystead.service;

/** Why an encrypted server row was ignored before it could mutate the local vault. */
public enum SyncImportRejectionReason {
    WRONG_VAULT,
    UNVERIFIABLE
}
