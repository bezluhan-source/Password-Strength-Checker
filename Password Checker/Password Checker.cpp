// =====================================================================
//  PasswordChecker - an educational password strength checker in C++
//
//  FOR EDUCATIONAL USE. Only ever test passwords that are YOUR OWN.
//
//  Everything runs locally on your machine. The password you type is
//  never saved to disk and never sent over the network. That is an
//  important property for a security tool, and worth saying out loud.
//
//  What it measures:
//    1. Length                - how many characters
//    2. Character variety     - lower / UPPER / digits / symbols
//    3. Predictability        - common passwords, simple patterns
//    4. Entropy (in bits)     - a single number combining the above,
//                               used to estimate how long a brute-force
//                               attack would take
//
//  Build (Visual Studio): plain Console App, C++17, no extra libraries.
//  Build (g++):  g++ -std=c++17 PasswordChecker.cpp -o passwordchecker
// =====================================================================

#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>
#include <cctype>
#include <cmath>
#include <algorithm>

// ---------------------------------------------------------------------
//  A small built-in list of very common / leaked passwords.
//  Real tools (like "Have I Been Pwned") compare against hundreds of
//  millions of leaked passwords. We keep a short list so the idea is
//  clear without shipping a huge file. Everything here is compared in
//  lowercase.
// ---------------------------------------------------------------------
static const std::unordered_set<std::string> kCommonPasswords = {
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "password1", "111111", "123123", "admin",
    "letmein", "welcome", "monkey", "dragon", "football", "iloveyou",
    "sunshine", "princess", "qwerty123", "1q2w3e4r", "000000", "passw0rd",
    "zaq12wsx", "login", "starwars", "whatever", "trustno1", "superman",
    "michael", "shadow", "master", "hello", "freedom", "ninja", "azerty",
    "qazwsx", "password123", "root", "toor", "changeme", "secret"
};

// Common keyboard / sequence runs that attackers try first.
static const std::vector<std::string> kKeyboardRuns = {
    "qwerty", "qwertyuiop", "asdf", "asdfgh", "zxcvbn", "qazwsx",
    "1qaz2wsx", "1q2w3e", "abcdef", "123456", "654321", "qweasd"
};

// ---------------------------------------------------------------------
//  Holds everything we learn about one password.
// ---------------------------------------------------------------------
struct Analysis {
    std::size_t length = 0;
    bool hasLower = false;
    bool hasUpper = false;
    bool hasDigit = false;
    bool hasSymbol = false;

    int    poolSize = 0;   // how many distinct symbols an attacker must try per position
    double entropyBits = 0.0; // raw strength: length * log2(poolSize)
    double effectiveBits = 0.0; // raw strength AFTER docking points for predictable patterns

    bool isCommon = false;  // exact match in the common list
    bool containsCommon = false;  // a common word sits inside it (e.g. "password123")
    bool hasKeyboardRun = false;  // "qwerty", "asdf", ...
    bool hasSequence = false;  // "abcd", "1234", "wxyz" (4+ in a row)
    bool hasRepeat = false;  // same char 3+ times in a row, or all one char
};

// Lowercase a copy of a string (used for case-insensitive comparisons).
static std::string toLower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Does the password contain 4+ characters in a straight ASCII run,
// ascending ("1234", "abcd") or descending ("4321", "dcba")?
static bool hasSequentialRun(const std::string& s) {
    if (s.size() < 4) return false;
    int ascending = 1, descending = 1;
    for (std::size_t i = 1; i < s.size(); ++i) {
        int diff = static_cast<int>(s[i]) - static_cast<int>(s[i - 1]);
        ascending = (diff == 1) ? ascending + 1 : 1;
        descending = (diff == -1) ? descending + 1 : 1;
        if (ascending >= 4 || descending >= 4) return true;
    }
    return false;
}

// Does the same character repeat 3+ times in a row? ("aaa", "111")
static bool hasRepeatedRun(const std::string& s) {
    int run = 1;
    for (std::size_t i = 1; i < s.size(); ++i) {
        run = (s[i] == s[i - 1]) ? run + 1 : 1;
        if (run >= 3) return true;
    }
    return false;
}

// ---------------------------------------------------------------------
//  The core analysis: inspect every character, then derive the numbers.
// ---------------------------------------------------------------------
static Analysis analyze(const std::string& password) {
    Analysis a;
    a.length = password.size();

    // Walk through each character and note which "families" appear.
    for (unsigned char c : password) {
        if (std::islower(c))      a.hasLower = true;
        else if (std::isupper(c)) a.hasUpper = true;
        else if (std::isdigit(c)) a.hasDigit = true;
        else if (std::isgraph(c)) a.hasSymbol = true;  // printable, not a letter/digit/space
        else                      a.hasSymbol = true;  // spaces / anything else -> treat as symbol
    }

    // The "pool size" is how many possible characters an attacker must
    // consider for each position, based on the families you actually used.
    if (a.hasLower)  a.poolSize += 26;
    if (a.hasUpper)  a.poolSize += 26;
    if (a.hasDigit)  a.poolSize += 10;
    if (a.hasSymbol) a.poolSize += 33;  // rough count of ASCII symbols + space

    // Entropy in bits = length * log2(poolSize).
    // Each position multiplies the number of guesses by poolSize, and
    // log2 turns that multiplication into a number of bits we can add up.
    if (a.poolSize > 0 && a.length > 0)
        a.entropyBits = static_cast<double>(a.length) * std::log2(static_cast<double>(a.poolSize));

    // Predictability checks (all case-insensitive).
    const std::string lower = toLower(password);

    a.isCommon = (kCommonPasswords.find(lower) != kCommonPasswords.end());

    for (const auto& common : kCommonPasswords) {
        if (common.size() >= 4 && lower.find(common) != std::string::npos) {
            a.containsCommon = true;
            break;
        }
    }
    for (const auto& run : kKeyboardRuns) {
        if (lower.find(run) != std::string::npos) {
            a.hasKeyboardRun = true;
            break;
        }
    }
    a.hasSequence = hasSequentialRun(lower);
    a.hasRepeat = hasRepeatedRun(password);

    // "Effective" entropy: start from the raw figure, then dock points for
    // anything that makes the password easier to guess than its length and
    // character mix suggest. This single number drives both the rating and
    // the crack-time estimate, so they always agree.
    a.effectiveBits = a.entropyBits;
    if (a.isCommon)                           a.effectiveBits = 1.0;  // known password: basically no protection
    if (a.containsCommon || a.hasKeyboardRun) a.effectiveBits -= 15.0;
    if (a.hasSequence || a.hasRepeat)         a.effectiveBits -= 10.0;
    if (a.effectiveBits < 0.0)                a.effectiveBits = 0.0;

    return a;
}

// ---------------------------------------------------------------------
//  Turn entropy (bits) into a human rating.
//  These thresholds are a common rule of thumb, not an exact science.
// ---------------------------------------------------------------------
static std::string rating(const Analysis& a) {
    if (a.isCommon) return "Very Weak (this is a known common password)";

    const double bits = a.effectiveBits;
    if (bits < 40)  return "Very Weak";   // cracked in seconds to minutes
    if (bits < 55)  return "Weak";        // cracked in hours to weeks
    if (bits < 70)  return "Reasonable";  // months to years
    if (bits < 90)  return "Strong";      // centuries+
    return "Very Strong";                 // effectively uncrackable by brute force
}

// ---------------------------------------------------------------------
//  Estimate how long a brute-force attack would take, as plain English.
//
//  We assume an OFFLINE attacker with a fast GPU trying 10 billion
//  guesses per second against a weak/fast hash. On average they find
//  the password after trying half of the possibilities (2^entropy / 2).
//  This is an estimate to build intuition, not a guarantee.
// ---------------------------------------------------------------------
static std::string crackTime(const Analysis& a) {
    const double guessesPerSecond = 1e10;             // 10,000,000,000 / sec
    const double totalGuesses = std::pow(2.0, a.effectiveBits);
    const double seconds = (totalGuesses / 2.0) / guessesPerSecond;

    if (seconds < 1.0)            return "less than a second";
    if (seconds < 60.0)           return std::to_string((long long)seconds) + " seconds";
    if (seconds < 3600.0)         return std::to_string((long long)(seconds / 60.0)) + " minutes";
    if (seconds < 86400.0)        return std::to_string((long long)(seconds / 3600.0)) + " hours";
    if (seconds < 31557600.0)     return std::to_string((long long)(seconds / 86400.0)) + " days";

    double years = seconds / 31557600.0;
    if (years < 1000.0)           return std::to_string((long long)years) + " years";
    if (years < 1e6)              return std::to_string((long long)(years / 1000.0)) + " thousand years";
    if (years < 1e9)              return std::to_string((long long)(years / 1e6)) + " million years";
    return "effectively forever (billions of years+)";
}

// ---------------------------------------------------------------------
//  Print a friendly report explaining WHY the password scored as it did.
// ---------------------------------------------------------------------
static void report(const std::string& password, const Analysis& a) {
    std::cout << "\n--------------------------------------------------\n";
    std::cout << "  Length:        " << a.length << " characters\n";

    std::cout << "  Character mix: ";
    std::cout << (a.hasLower ? "[lowercase] " : "");
    std::cout << (a.hasUpper ? "[UPPERCASE] " : "");
    std::cout << (a.hasDigit ? "[digits] " : "");
    std::cout << (a.hasSymbol ? "[symbols] " : "");
    if (!a.hasLower && !a.hasUpper && !a.hasDigit && !a.hasSymbol)
        std::cout << "(none)";
    std::cout << "\n";

    std::cout << "  Entropy:       ~" << (long long)a.entropyBits << " bits";
    if (a.effectiveBits < a.entropyBits - 0.5)   // patterns dragged the real strength down
        std::cout << "  (but only ~" << (long long)a.effectiveBits
        << " bits once predictable patterns are accounted for)";
    std::cout << "\n";
    std::cout << "  Est. crack time (offline fast attack): " << crackTime(a) << "\n";
    std::cout << "  RATING:        " << rating(a) << "\n";

    // Collect concrete reasons / advice.
    std::vector<std::string> reasons;
    if (a.isCommon)
        reasons.push_back("It is one of the most common passwords in the world and sits at the top of every attacker's list.");
    if (a.containsCommon && !a.isCommon)
        reasons.push_back("It contains a well-known word (like 'password' or 'admin'); adding digits on the end barely helps.");
    if (a.hasKeyboardRun)
        reasons.push_back("It contains a keyboard pattern (like 'qwerty' or 'asdf'), which attackers try very early.");
    if (a.hasSequence)
        reasons.push_back("It contains a run of sequential characters (like '1234' or 'abcd').");
    if (a.hasRepeat)
        reasons.push_back("It repeats the same character several times in a row.");
    if (a.length < 12)
        reasons.push_back("It is short. Length is the single biggest factor - aim for at least 12-16 characters.");
    int families = (int)a.hasLower + a.hasUpper + a.hasDigit + a.hasSymbol;
    if (families < 3)
        reasons.push_back("It uses few character types. Mixing lower, UPPER, digits and symbols widens the search space.");

    if (reasons.empty()) {
        std::cout << "\n  Looks good! This password is long and varied with no obvious\n";
        std::cout << "  patterns. Use a unique one per site and store it in a password manager.\n";
    }
    else {
        std::cout << "\n  Why it could be stronger:\n";
        for (const auto& r : reasons)
            std::cout << "   - " << r << "\n";
    }
    std::cout << "--------------------------------------------------\n";
}

int main() {
    std::cout << "==================================================\n";
    std::cout << "  Password Strength Checker (educational)\n";
    std::cout << "  Test ONLY your own passwords. Nothing is saved\n";
    std::cout << "  or sent anywhere - this runs entirely offline.\n";
    std::cout << "==================================================\n";

    std::string password;
    while (true) {
        std::cout << "\nEnter a password to check (or just press Enter to quit): ";
        std::getline(std::cin, password);

        if (password.empty()) {
            std::cout << "Goodbye - stay safe out there.\n";
            break;
        }

        Analysis a = analyze(password);
        report(password, a);
    }

    return 0;
}
