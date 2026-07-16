package top.focess.keystead.model;

import java.util.Locale;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Catalog of canonical taxonomy constants and factory methods for building secret classifications.
 */
public final class SecretTaxonomy {

    /** Category for development-oriented secrets. */
    public static final String CATEGORY_DEVELOPMENT = "development";

    /** Category for communication-oriented secrets. */
    public static final String CATEGORY_COMMUNICATION = "communication";

    /** Provider value for generic API tokens. */
    public static final String PROVIDER_API = "api";

    /** Provider value for GitHub. */
    public static final String PROVIDER_GITHUB = "github";

    /** Provider value for Google. */
    public static final String PROVIDER_GOOGLE = "google";

    /** Provider value for GPG. */
    public static final String PROVIDER_GPG = "gpg";

    /** Provider value for SSH. */
    public static final String PROVIDER_SSH = "ssh";

    /** Provider value for WeChat. */
    public static final String PROVIDER_WECHAT = "wechat";

    /** Provider value for X.509 certificates. */
    public static final String PROVIDER_X509 = "x509";

    /** Software value for GitHub. */
    public static final String SOFTWARE_GITHUB = "github.com";

    /** Software value for Google. */
    public static final String SOFTWARE_GOOGLE = "google";

    /** Software value for Google Authenticator. */
    public static final String SOFTWARE_GOOGLE_AUTHENTICATOR = "google-authenticator";

    /** Software value for GPG. */
    public static final String SOFTWARE_GPG = "gpg";

    /** Software value for OpenSSH. */
    public static final String SOFTWARE_OPENSSH = "openssh";

    /** Software value for WeChat. */
    public static final String SOFTWARE_WECHAT = "wechat";

    /** Software value for X.509 tooling. */
    public static final String SOFTWARE_X509 = "x509";

    private SecretTaxonomy() {}

    /** Creates a development-category classification.
     *
     * @param provider the optional provider
     * @param software the optional software
     * @param account the optional account identifier
     * @return a development classification */
    public static @NonNull SecretClassification development(
            @Nullable String provider, @Nullable String software, @Nullable String account) {
        return new SecretClassification(CATEGORY_DEVELOPMENT, provider, software, account);
    }

    /** Creates a communication-category classification.
     *
     * @param provider the optional provider
     * @param software the optional software
     * @param account the optional account identifier
     * @return a communication classification */
    public static @NonNull SecretClassification communication(
            @Nullable String provider, @Nullable String software, @Nullable String account) {
        return new SecretClassification(CATEGORY_COMMUNICATION, provider, software, account);
    }

    /** Creates a GitHub development classification.
     *
     * @param account the optional account identifier
     * @return a GitHub development classification */
    public static @NonNull SecretClassification githubDevelopment(@Nullable String account) {
        return development(PROVIDER_GITHUB, SOFTWARE_GITHUB, account);
    }

    /** Creates an SSH development classification.
     *
     * @param account the optional account identifier
     * @return an SSH development classification */
    public static @NonNull SecretClassification sshDevelopment(@Nullable String account) {
        return development(PROVIDER_SSH, SOFTWARE_OPENSSH, account);
    }

    /** Creates a GPG development classification.
     *
     * @param account the optional account identifier
     * @return a GPG development classification */
    public static @NonNull SecretClassification gpgDevelopment(@Nullable String account) {
        return development(PROVIDER_GPG, SOFTWARE_GPG, account);
    }

    /** Creates a Google communication classification.
     *
     * @param account the optional account identifier
     * @return a Google communication classification */
    public static @NonNull SecretClassification googleCommunication(@Nullable String account) {
        return communication(PROVIDER_GOOGLE, SOFTWARE_GOOGLE, account);
    }

    /** Creates a WeChat communication classification.
     *
     * @param account the optional account identifier
     * @return a WeChat communication classification */
    public static @NonNull SecretClassification wechatCommunication(@Nullable String account) {
        return communication(PROVIDER_WECHAT, SOFTWARE_WECHAT, account);
    }

    /** Suggests a classification based on the secret type and title heuristics.
     *
     * @param type the secret type
     * @param title the optional title used for heuristic matching
     * @param account the optional account identifier
     * @return the suggested classification, possibly with all fields empty */
    public static @NonNull SecretClassification suggest(
            @NonNull SecretType type, @Nullable String title, @Nullable String account) {
        Objects.requireNonNull(type, "type");
        if (contains(title, PROVIDER_GITHUB)) {
            return githubDevelopment(account);
        }
        if (contains(title, PROVIDER_WECHAT)) {
            return wechatCommunication(account);
        }
        return switch (type) {
            case SSH_KEY -> sshDevelopment(account);
            case GPG_KEY -> gpgDevelopment(account);
            case API_TOKEN -> development(PROVIDER_API, null, account);
            case MFA_SECRET -> {
                if (contains(title, PROVIDER_GOOGLE)) {
                    yield communication(PROVIDER_GOOGLE, SOFTWARE_GOOGLE_AUTHENTICATOR, account);
                }
                yield communication(null, null, account);
            }
            case CERTIFICATE -> development(PROVIDER_X509, SOFTWARE_X509, account);
            case LOGIN_PASSWORD, SECURE_NOTE, GENERIC_SECRET -> SecretClassification.none();
        };
    }

    private static boolean contains(@Nullable String value, @NonNull String needle) {
        return value != null && value.toLowerCase(Locale.ROOT).contains(needle);
    }
}
