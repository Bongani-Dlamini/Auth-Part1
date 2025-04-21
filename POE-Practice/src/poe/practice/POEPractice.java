package poe.practice;

import javax.swing.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class POEPractice {

    // Class-level variables
    static Map<String, String> userCredentials = new HashMap<>(); // Store username and hashed password
    static Map<String, String> userDetails = new HashMap<>();     // Store other user details
    static Set<String> existingUsernames = new HashSet<>();
    static int failedAttempts = 0;
    static String loggedInUsername = null; // To track logged-in user

    // --- Configuration ---
    static final int MIN_PASSWORD_LENGTH = 8;
    static final String USERNAME_REGEX = "^[a-zA-Z0-9_]{1,5}$"; // Allows alphanumeric and underscore, max 5 chars
    static final int MAX_LOGIN_ATTEMPTS = 3;
    static final long LOCKOUT_DURATION = 30 * 1000; // 30 seconds lockout (for demonstration)
    static Map<String, Long> failedLoginTimestamps = new HashMap<>();

    // --- Password Hashing (Simplified Placeholder - USE A LIBRARY LIKE JBCRYPT IN REALITY) ---
    public static String hashPassword(String password) {
        // In a real application, use a strong hashing algorithm with salt.
        // This is a VERY insecure placeholder.
        return "hashed_" + password;
    }

    public static boolean checkPassword(String plainPassword, String hashedPassword) {
        return hashPassword(plainPassword).equals(hashedPassword);
    }

    // --- Input Validation ---
    public static boolean isUsernameValid(String username) {
        return username.matches(USERNAME_REGEX) && !existingUsernames.contains(username);
    }

    public static boolean isPasswordValid(String password) {
        if (password.length() < MIN_PASSWORD_LENGTH) return false;
        boolean hasCapital = false, hasNumber = false, hasSpecial = false;
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) hasCapital = true;
            if (Character.isDigit(c)) hasNumber = true;
            if (!Character.isLetterOrDigit(c)) hasSpecial = true;
        }
        return hasCapital && hasNumber && hasSpecial;
    }

    public static boolean isPhoneNumberValid(String phone) {
        return phone.matches("^\\+\\d{10,12}$");
    }

    public static boolean isEmailValid(String email) {
        // A more comprehensive regex might be needed for production
        return email.matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$");
    }

    // --- Simulated CAPTCHA ---
    public static boolean validateCaptcha() {
        String answer = JOptionPane.showInputDialog("Captcha: What is 3 + 4?");
        return answer != null && answer.trim().equals("7");
    }

    // --- Simulate 2FA ---
    public static boolean performTwoFactorAuth() {
        int code = new Random().nextInt(9000) + 1000;
        String entered = JOptionPane.showInputDialog("Enter 2FA code: " + code);
        return String.valueOf(code).equals(entered);
    }

    // --- Account Recovery (Basic Security Questions) ---
    static Map<String, Map<String, String>> securityQuestions = new HashMap<>();

    public static String registerUser(String username, String password, String confirmPassword,
                                     String phoneNumber, String firstName, String lastName, String email,
                                     String securityQuestion1, String securityAnswer1,
                                     String securityQuestion2, String securityAnswer2) {
        if (!isUsernameValid(username)) {
            return "Invalid username. Must be 1-5 alphanumeric chars with _, and not taken.";
        }
        if (!isPasswordValid(password)) {
            return "Invalid password. Must be " + MIN_PASSWORD_LENGTH + "+ chars with uppercase, number & special char.";
        }
        if (!password.equals(confirmPassword)) {
            return "Passwords do not match.";
        }
        if (!isPhoneNumberValid(phoneNumber)) {
            return "Phone number must be in international format (e.g., +27831234567).";
        }
        if (email != null && !email.isEmpty() && !isEmailValid(email)) {
            return "Invalid email format.";
        }
        if (!validateCaptcha()) {
            return "Captcha failed.";
        }

        String hashedPassword = hashPassword(password);
        userCredentials.put(username, hashedPassword);
        userDetails.put(username, firstName + "," + lastName + "," + phoneNumber + "," + (email == null ? "" : email));
        existingUsernames.add(username);

        Map<String, String> questionsAndAnswers = new HashMap<>();
        questionsAndAnswers.put(securityQuestion1, securityAnswer1);
        questionsAndAnswers.put(securityQuestion2, securityAnswer2);
        securityQuestions.put(username, questionsAndAnswers);

        return "Registration complete!";
    }

    public static boolean checkLogin(String username, String password) {
        if (userCredentials.containsKey(username)) {
            return checkPassword(password, userCredentials.get(username));
        }
        return false;
    }

    public static String getLoginMessage(boolean success, String username) {
        if (success && userDetails.containsKey(username)) {
            String[] details = userDetails.get(username).split(",");
            return "Welcome back, " + details[0] + " " + details[1] + "!";
        } else {
            return "Login failed. Username or password incorrect.";
        }
    }

    public static void register() {
        JOptionPane.showMessageDialog(null, "--- Registration ---");

        String username = JOptionPane.showInputDialog("Username:");
        String password = JOptionPane.showInputDialog("Password:");
        String confirmPassword = JOptionPane.showInputDialog("Confirm Password:");
        String phone = JOptionPane.showInputDialog("Phone number (+27...):");
        String firstName = JOptionPane.showInputDialog("First name:");
        String lastName = JOptionPane.showInputDialog("Last name:");
        String email = JOptionPane.showInputDialog("Email (optional):");
        String securityQuestion1 = JOptionPane.showInputDialog("Security Question 1:");
        String securityAnswer1 = JOptionPane.showInputDialog("Answer to Question 1:");
        String securityQuestion2 = JOptionPane.showInputDialog("Security Question 2:");
        String securityAnswer2 = JOptionPane.showInputDialog("Answer to Question 2:");

        String result = registerUser(username, password, confirmPassword, phone, firstName, lastName, email,
                                     securityQuestion1, securityAnswer1, securityQuestion2, securityAnswer2);
        JOptionPane.showMessageDialog(null, result);

        if (result.contains("complete")) {
            JOptionPane.showMessageDialog(null, "Registration successful!");
            login();
        } else {
            register(); // Re-prompt on failure
        }
    }

    public static void login() {
        JOptionPane.showMessageDialog(null, "--- Login ---");

        String username = JOptionPane.showInputDialog("Username:");
        String password = JOptionPane.showInputDialog("Password:");

        if (failedLoginTimestamps.containsKey(username) &&
            System.currentTimeMillis() < failedLoginTimestamps.get(username) + LOCKOUT_DURATION) {
            JOptionPane.showMessageDialog(null, "Account temporarily locked. Please try again later.");
            return;
        }

        boolean success = checkLogin(username, password);

        if (success) {
            failedAttempts = 0; // Reset failed attempts on successful login
            loggedInUsername = username;
            if (performTwoFactorAuth()) {
                JOptionPane.showMessageDialog(null, getLoginMessage(true, username));
                showUserProfile(username);
                offerPasswordChange(username);
                offerLogout();
            } else {
                JOptionPane.showMessageDialog(null, "2FA failed.");
                login();
            }
        } else {
            failedAttempts++;
            failedLoginTimestamps.put(username, System.currentTimeMillis());
            if (failedAttempts >= MAX_LOGIN_ATTEMPTS) {
                JOptionPane.showMessageDialog(null, "Account locked due to too many failed attempts.");
                failedLoginTimestamps.remove(username); // Keep lockout active
                System.exit(0);
            } else {
                JOptionPane.showMessageDialog(null, getLoginMessage(false, username));
                login();
            }
        }
    }

    public static void showUserProfile(String username) {
        if (userDetails.containsKey(username)) {
            String[] details = userDetails.get(username).split(",");
            JOptionPane.showMessageDialog(null,
                    "----- Profile -----\n" +
                            "Name: " + details[0] + " " + details[1] + "\n" +
                            "Phone: " + details[2] + "\n" +
                            "Email: " + details[3] + "\n" +
                            "Username: " + username
            );
        } else {
            JOptionPane.showMessageDialog(null, "User profile not found.");
        }
    }

    public static void offerPasswordChange(String username) {
        int change = JOptionPane.showConfirmDialog(null, "Would you like to change your password?");
        if (change == 0) {
            String newPass = JOptionPane.showInputDialog("Enter new password:");
            if (isPasswordValid(newPass)) {
                userCredentials.put(username, hashPassword(newPass));
                JOptionPane.showMessageDialog(null, "Password updated successfully.");
            } else {
                JOptionPane.showMessageDialog(null, "New password is invalid.");
            }
        }
    }

    public static void forgotPassword() {
        String username = JOptionPane.showInputDialog("Enter your username:");
        if (securityQuestions.containsKey(username)) {
            Map<String, String> qa = securityQuestions.get(username);
            String question1 = (String) qa.keySet().toArray()[0];
            String answer1 = JOptionPane.showInputDialog("Answer to: " + question1);
            String question2 = (String) qa.keySet().toArray()[1];
            String answer2 = JOptionPane.showInputDialog("Answer to: " + question2);

            if (answer1 != null && answer1.equals(qa.get(question1)) &&
                answer2 != null && answer2.equals(qa.get(question2))) {
                String newPassword = JOptionPane.showInputDialog("Enter your new password:");
                String confirmNewPassword = JOptionPane.showInputDialog("Confirm new password:");
                if (newPassword != null && newPassword.equals(confirmNewPassword) && isPasswordValid(newPassword)) {
                    userCredentials.put(username, hashPassword(newPassword));
                    JOptionPane.showMessageDialog(null, "Password reset successfully!");
                } else {
                    JOptionPane.showMessageDialog(null, "New passwords do not match or are invalid.");
                }
            } else {
                JOptionPane.showMessageDialog(null, "Answers to security questions do not match.");
            }
        } else {
            JOptionPane.showMessageDialog(null, "Username not found.");
        }
    }

    public static void offerLogout() {
        int logout = JOptionPane.showConfirmDialog(null, "Would you like to logout?");
        if (logout == 0) {
            loggedInUsername = null;
            JOptionPane.showMessageDialog(null, "Logged out successfully.");
            execute(); // Go back to the main menu
        }
    }

    public static void execute() {
        String[] options = {"Register", "Login", "Forgot Password", "Exit"};
        int choice = JOptionPane.showOptionDialog(null,
                "Choose an option:",
                "Login System",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                null,
                options,
                options[0]);

        switch (choice) {
            case 0 -> register();
            case 1 -> login();
            case 2 -> forgotPassword();
            default -> JOptionPane.showMessageDialog(null, "Goodbye!");
        }
    }

    public static void main(String[] args) {
        execute();
    }
}



  
