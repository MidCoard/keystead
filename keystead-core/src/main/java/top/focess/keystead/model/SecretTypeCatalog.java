package top.focess.keystead.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

public final class SecretTypeCatalog {

    private static final Map<SecretType, SecretTypeCatalogEntry> DEFAULTS = buildDefaults();
    private static final List<SecretTypeCatalogEntry> DEFAULT_LIST = List.copyOf(DEFAULTS.values());

    private SecretTypeCatalog() {}

    public static @NonNull SecretTypeCatalogEntry forType(@NonNull SecretType type) {
        Objects.requireNonNull(type, "type");
        return DEFAULTS.get(type);
    }

    public static @NonNull List<SecretTypeCatalogEntry> defaults() {
        return DEFAULT_LIST;
    }

    private static @NonNull Map<SecretType, SecretTypeCatalogEntry> buildDefaults() {
        Map<SecretType, SecretTypeCatalogEntry> map = new LinkedHashMap<>();
        put(
                map,
                new SecretTypeCatalogEntry(
                        SecretTypeSchema.forType(SecretType.LOGIN_PASSWORD),
                        SecretTaxonomy.CATEGORY_COMMUNICATION,
                        null,
                        null,
                        null));
        put(
                map,
                new SecretTypeCatalogEntry(
                        SecretTypeSchema.forType(SecretType.SECURE_NOTE), null, null, null, null));
        put(
                map,
                new SecretTypeCatalogEntry(
                        SecretTypeSchema.forType(SecretType.SSH_KEY),
                        SecretTaxonomy.CATEGORY_DEVELOPMENT,
                        SecretTaxonomy.PROVIDER_SSH,
                        SecretTaxonomy.SOFTWARE_OPENSSH,
                        null));
        put(
                map,
                new SecretTypeCatalogEntry(
                        SecretTypeSchema.forType(SecretType.API_TOKEN),
                        SecretTaxonomy.CATEGORY_DEVELOPMENT,
                        SecretTaxonomy.PROVIDER_API,
                        null,
                        null));
        put(
                map,
                new SecretTypeCatalogEntry(
                        SecretTypeSchema.forType(SecretType.GPG_KEY),
                        SecretTaxonomy.CATEGORY_DEVELOPMENT,
                        SecretTaxonomy.PROVIDER_GPG,
                        SecretTaxonomy.SOFTWARE_GPG,
                        null));
        put(
                map,
                new SecretTypeCatalogEntry(
                        SecretTypeSchema.forType(SecretType.MFA_SECRET),
                        SecretTaxonomy.CATEGORY_COMMUNICATION,
                        null,
                        null,
                        null));
        put(
                map,
                new SecretTypeCatalogEntry(
                        SecretTypeSchema.forType(SecretType.CERTIFICATE),
                        SecretTaxonomy.CATEGORY_DEVELOPMENT,
                        SecretTaxonomy.PROVIDER_X509,
                        SecretTaxonomy.SOFTWARE_X509,
                        null));
        put(
                map,
                new SecretTypeCatalogEntry(
                        SecretTypeSchema.forType(SecretType.GENERIC_SECRET),
                        null,
                        null,
                        null,
                        SecretFieldType.SECRET));
        return Collections.unmodifiableMap(map);
    }

    private static void put(
            @NonNull Map<SecretType, SecretTypeCatalogEntry> map,
            @NonNull SecretTypeCatalogEntry entry) {
        SecretTypeCatalogEntry previous = map.put(entry.type(), entry);
        if (previous != null) {
            throw new IllegalStateException("Duplicate secret type catalog entry: " + entry.type());
        }
    }
}
