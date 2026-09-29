import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

public class PasswordStrengthDetector {

    private static final Set<String> KEYBOARD_WALKS = Set.of(
    "qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "2wsx",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "poiuyt", "lkjhg"
    );

    private static final String SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("=========================================");
        System.out.println("  Password Strength Detector + HIBP");
        System.out.println("=========================================");
        System.out.print("Enter a password to test: ");

        String password = scanner.nextLine();
        System.out.println("\n--- Results ---");
        System.out.println(analyze(password));

        scanner.close();
    }

    // Analyzes passwords
    public static String analyze(String password) {
        List<String> feedback = new ArrayList<>();
        int score = 0;

        // length check
        int length = password.length();
        if (length >= 16) score += 45;
        else if (length >= 12) score += 35;
        else if (length >= 10) score += 25;
        else if (length >= 8) score += 15;
        else if (length >= 6) score += 8;
        else feedback.add("Password is too short. Use at least 12 characters.");

        // Different characters check
        boolean hasLower = false;
        boolean hasUpper = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        for (char c : password.toCharArray()) {
            if (SPECIAL_CHARS.indexOf(c) >= 0) hasSpecial = true;
            if (Character.isLowerCase(c)) hasLower = true;
            if (Character.isUpperCase(c)) hasUpper = true;
            if (Character.isDigit(c)) hasDigit = true;
        }

        if (hasLower) score += 15; else feedback.add("Add lowercase letters.");
        if (hasUpper) score += 15; else feedback.add("Add uppercase letters.");
        if (hasDigit) score += 15; else feedback.add("Add numbers.");
        if (hasSpecial) score += 15; else feedback.add("Add special characters.");

        // Penalties
        if (KEYBOARD_WALKS.contains(password.toLowerCase())) {
            score -= 15;
            feedback.add("This contains a keyboard walk. Avoid it");
        }
        if (hasSequentialChars(password)) {
            score -= 15;
            feedback.add("Avoid sequential characters.");
        }
        if (hasRepeatedChars(password)) {
            score -= 10;
            feedback.add("Avoid repeated characters.");
        }

        score = Math.max(0, Math.min(100, score));

        // HIBP Check
        boolean breached = false;
        int breachCount = 0;
        try {
            breachCount = HibpChecker.checkPassword(password);
            breached = breachCount > 0;
            if (breached) {
                score = 0;
                feedback.add("This password has appeared in data breaches. Never use it for anything important.");
            }
        } catch (Exception e) {
            feedback.add("Didnt do breach check");
        }

        // Strength level
        String label;
        if (breached) label = "COMPROMISED";
        else if (score >= 80) label = "Very Strong";
        else if (score >= 60) label = "Strong";
        else if (score >= 40) label = "Fair";
        else label = "Weak";

        // Report
        String result = "Score: " + score + "/100 (" + label + ")\n";

        if (breached) {
            result += "BREACHED: Found in " + breachCount + " known data breaches!\n";
        } else {
            result += "Not found in known breaches.\n";
        }  

        if (!feedback.isEmpty()) {
            result += "Feedback:\n";
            for (String f : feedback) {
                result += "  - " + f + "\n";
            }
        }
        return result;  
    }

    private static boolean hasSequentialChars(String password) {
        String lower = password.toLowerCase();
        for (int i = 0; i < lower.length() - 2; i++) {
            char a = lower.charAt(i);
            char b = lower.charAt(i + 1);
            char c = lower.charAt(i + 2);
            if (b - a == 1 && c - b == 1) return true;
            if (a - b == 1 && b - c == 1) return true;
        }
        return false;
    }

    private static boolean hasRepeatedChars(String password) {
        for (int i = 0; i < password.length() - 2; i++) {
            if (password.charAt(i) == password.charAt(i + 1)
                    && password.charAt(i + 1) == password.charAt(i + 2)) {
                return true;
            }
        }
        return false;
    }
}