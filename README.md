# Password Strength Analyzer

A command-line password strength analyzer built in Java that scores
passwords 0–100 and checks them against the Have I Been Pwned breach
database using k-anonymity.

## Features
- Length-based scoring (0–40 points)
- Character diversity checks: lowercase, uppercase, digits, special (0–60 points)
- Pattern penalties: keyboard walks, sequences, repeats
- Breach detection via HIBP Pwned Passwords API (k-anonymity)

## How It Works

Password scoring combines three signals:
1. **Length** — longer passwords score higher
2. **Character diversity** — four classes: lower, upper, digit, special
3. **Pattern penalties** — deducts points for weak patterns

Breach checking uses k-anonymity:
- Password is SHA-1 hashed locally
- Only the first 5 characters of the hash are sent to HIBP
- The remaining 35 characters are matched locally
- The server never sees the password or the full hash

## Example Output

<img width="648" height="616" alt="image" src="https://github.com/user-attachments/assets/beddaa4b-34c5-4234-bc30-fa33e6c304da" />


## Build & Run

    javac -d out HibpChecker.java PasswordStrengthDetector.java
    java -cp out PasswordStrengthDetector
