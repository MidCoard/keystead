package top.focess.keystead.generator;

/** Canonical character sets used by the default password generator. */
public final class PasswordCharacterSets {

    /** ASCII uppercase letters. */
    public static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /** ASCII lowercase letters. */
    public static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";

    /** ASCII decimal digits. */
    public static final String DIGITS = "0123456789";

    /** Symbols supported by the default generator, in canonical order. */
    public static final String SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";

    /** Characters omitted when a policy requests ambiguous-character exclusion. */
    public static final String AMBIGUOUS = "0O1Il";

    private PasswordCharacterSets() {}
}
