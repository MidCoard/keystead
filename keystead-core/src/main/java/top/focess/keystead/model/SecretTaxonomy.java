package top.focess.keystead.model;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public final class SecretTaxonomy {

    public static final String CATEGORY_DEVELOPMENT = "development";
    public static final String CATEGORY_COMMUNICATION = "communication";

    public static final String PROVIDER_API = "api";
    public static final String PROVIDER_GITHUB = "github";
    public static final String PROVIDER_GOOGLE = "google";
    public static final String PROVIDER_GPG = "gpg";
    public static final String PROVIDER_SSH = "ssh";
    public static final String PROVIDER_WECHAT = "wechat";
    public static final String PROVIDER_X509 = "x509";

    public static final String SOFTWARE_GITHUB = "github.com";
    public static final String SOFTWARE_GOOGLE = "google";
    public static final String SOFTWARE_GOOGLE_AUTHENTICATOR = "google-authenticator";
    public static final String SOFTWARE_GPG = "gpg";
    public static final String SOFTWARE_OPENSSH = "openssh";
    public static final String SOFTWARE_WECHAT = "wechat";
    public static final String SOFTWARE_X509 = "x509";

    private SecretTaxonomy() {}

    public static @NonNull SecretClassification development(
            @Nullable String provider, @Nullable String software, @Nullable String account) {
        return new SecretClassification(CATEGORY_DEVELOPMENT, provider, software, account);
    }

    public static @NonNull SecretClassification communication(
            @Nullable String provider, @Nullable String software, @Nullable String account) {
        return new SecretClassification(CATEGORY_COMMUNICATION, provider, software, account);
    }

    public static @NonNull SecretClassification githubDevelopment(@Nullable String account) {
        return development(PROVIDER_GITHUB, SOFTWARE_GITHUB, account);
    }

    public static @NonNull SecretClassification sshDevelopment(@Nullable String account) {
        return development(PROVIDER_SSH, SOFTWARE_OPENSSH, account);
    }

    public static @NonNull SecretClassification gpgDevelopment(@Nullable String account) {
        return development(PROVIDER_GPG, SOFTWARE_GPG, account);
    }

    public static @NonNull SecretClassification googleCommunication(@Nullable String account) {
        return communication(PROVIDER_GOOGLE, SOFTWARE_GOOGLE, account);
    }

    public static @NonNull SecretClassification wechatCommunication(@Nullable String account) {
        return communication(PROVIDER_WECHAT, SOFTWARE_WECHAT, account);
    }
}
