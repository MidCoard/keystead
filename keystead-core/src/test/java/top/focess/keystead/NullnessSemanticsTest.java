package top.focess.keystead;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import org.junit.jupiter.api.Test;

class NullnessSemanticsTest {

    private static final Set<String> PRIMITIVES =
            Set.of("boolean", "byte", "char", "double", "float", "int", "long", "short");
    private static final Set<String> NON_DECLARATION_PREFIXES =
            Set.of(
                    "assert", "catch", "do", "for", "if", "new", "return", "super", "switch",
                    "throw", "try", "while");

    @Test
    void productionCodeDoesNotUsePackageLevelNullDefaults() throws IOException {
        Path sourceRoot = Path.of("src/main/java/top/focess/keystead");

        try (var files = Files.walk(sourceRoot)) {
            List<Path> packageInfoFiles =
                    files.filter(path -> path.getFileName().toString().equals("package-info.java"))
                            .toList();

            assertTrue(
                    packageInfoFiles.isEmpty(),
                    "Do not use package-info.java for nullness defaults");
        }
    }

    @Test
    void productionMethodsDeclareExplicitNullness() throws IOException {
        Path sourceRoot = Path.of("src/main/java/top/focess/keystead");
        List<String> violations = new ArrayList<>();

        try (var files = Files.walk(sourceRoot)) {
            for (Path file : files.filter(path -> path.toString().endsWith(".java")).toList()) {
                String source = Files.readString(file);
                assertTrue(!source.contains("NullMarked"), file + " must not use @NullMarked");
                checkDeclarations(file, source, violations);
            }
        }

        assertTrue(violations.isEmpty(), String.join(System.lineSeparator(), violations));
    }

    private static void checkDeclarations(Path file, String source, List<String> violations) {
        String[] lines = source.split("\\R");
        Set<String> typeNames = typeNames(source);
        for (int index = 0; index < lines.length; index++) {
            String firstLine = lines[index].strip();
            if (!isDeclarationStart(firstLine, typeNames)) {
                continue;
            }

            StringBuilder signature = new StringBuilder(firstLine);
            int end = index;
            while (!endsDeclaration(signature.toString()) && end + 1 < lines.length) {
                end++;
                signature.append(' ').append(lines[end].strip());
            }

            checkReturnAnnotation(file, index + 1, signature.toString(), typeNames, violations);
            checkParameterAnnotations(file, index + 1, signature.toString(), violations);
            index = end;
        }
    }

    private static Set<String> typeNames(String source) {
        Set<String> names = new HashSet<>();
        Matcher matcher =
                java.util.regex.Pattern.compile("\\b(?:class|enum|interface|record)\\s+(\\w+)")
                        .matcher(source);
        while (matcher.find()) {
            names.add(matcher.group(1));
        }
        return names;
    }

    private static boolean isDeclarationStart(String line, Set<String> typeNames) {
        if (!line.contains("(")) {
            return false;
        }
        if (line.startsWith("}")) {
            return false;
        }
        String beforeParenthesis = line.substring(0, line.indexOf('(')).strip();
        if (beforeParenthesis.isBlank()
                || beforeParenthesis.contains("=")
                || beforeParenthesis.contains("->")
                || beforeParenthesis.contains(".")) {
            return false;
        }
        String firstToken = beforeParenthesis.split("\\s+")[0];
        if (!Character.isJavaIdentifierStart(firstToken.charAt(0)) && firstToken.charAt(0) != '@') {
            return false;
        }
        if (NON_DECLARATION_PREFIXES.contains(firstToken)) {
            return false;
        }

        String declaration = stripLeadingAnnotationsAndModifiers(beforeParenthesis);
        String[] tokens = declaration.split("\\s+");
        if (tokens.length == 1) {
            return typeNames.contains(tokens[0]);
        }
        return tokens.length >= 2;
    }

    private static boolean endsDeclaration(String signature) {
        return signature.endsWith("{") || signature.endsWith(";");
    }

    private static void checkReturnAnnotation(
            Path file,
            int lineNumber,
            String signature,
            Set<String> typeNames,
            List<String> violations) {
        String beforeParenthesis = signature.substring(0, signature.indexOf('(')).strip();
        String declaration = stripLeadingAnnotationsAndModifiers(beforeParenthesis);
        String[] tokens = declaration.split("\\s+");
        String methodName = tokens[tokens.length - 1];
        if (typeNames.contains(methodName)) {
            return;
        }
        if (beforeParenthesis.contains("@NonNull") || beforeParenthesis.contains("@Nullable")) {
            return;
        }

        String returnType = declaration.substring(0, declaration.lastIndexOf(methodName)).strip();
        if (returnType.isBlank() || returnType.equals("void") || isPrimitiveType(returnType)) {
            return;
        }
        if (!returnType.contains("@NonNull") && !returnType.contains("@Nullable")) {
            violations.add(
                    file + ":" + lineNumber + " method return type needs @NonNull or @Nullable");
        }
    }

    private static void checkParameterAnnotations(
            Path file, int lineNumber, String signature, List<String> violations) {
        String parameters =
                signature.substring(signature.indexOf('(') + 1, signature.lastIndexOf(')'));
        if (parameters.isBlank()) {
            return;
        }
        for (String parameter : splitParameters(parameters)) {
            String trimmed = parameter.strip();
            if (trimmed.isBlank()
                    || trimmed.contains("@NonNull")
                    || trimmed.contains("@Nullable")) {
                continue;
            }
            if (requiresNullnessAnnotation(trimmed)) {
                violations.add(
                        file
                                + ":"
                                + lineNumber
                                + " parameter needs @NonNull or @Nullable: "
                                + trimmed);
            }
        }
    }

    private static List<String> splitParameters(String parameters) {
        List<String> split = new ArrayList<>();
        int genericDepth = 0;
        int start = 0;
        for (int index = 0; index < parameters.length(); index++) {
            char value = parameters.charAt(index);
            if (value == '<') {
                genericDepth++;
            } else if (value == '>') {
                genericDepth--;
            } else if (value == ',' && genericDepth == 0) {
                split.add(parameters.substring(start, index));
                start = index + 1;
            }
        }
        split.add(parameters.substring(start));
        return split;
    }

    private static boolean requiresNullnessAnnotation(String parameter) {
        String withoutFinal = parameter.replaceFirst("^final\\s+", "").strip();
        String[] tokens = withoutFinal.split("\\s+");
        if (tokens.length < 2) {
            return false;
        }
        String type =
                withoutFinal
                        .substring(0, withoutFinal.lastIndexOf(tokens[tokens.length - 1]))
                        .strip();
        return !isPrimitiveType(type);
    }

    private static String stripLeadingAnnotationsAndModifiers(String value) {
        String stripped = value.strip();
        boolean changed;
        do {
            changed = false;
            String updated =
                    stripped.replaceFirst(
                            "^(?:@[A-Za-z0-9_.]+|public|protected|private|static|final|abstract|default|synchronized)\\s+",
                            "");
            if (!updated.equals(stripped)) {
                stripped = updated;
                changed = true;
            }
        } while (changed);
        return stripped;
    }

    private static boolean isPrimitiveType(String type) {
        String normalized =
                type.replace("@NonNull", "").replace("@Nullable", "").replace("...", "[]").strip();
        return PRIMITIVES.contains(normalized);
    }
}
