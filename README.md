# Password Strength Checker

A small, self-contained command-line tool in C++ that analyses a password and
explains — in plain English — how strong it is and *why*. Built as an
educational security project.

It runs **entirely offline**. The password you type is never written to disk
and never sent over the network.

## What it checks

| Factor | What it means |
| --- | --- |
| **Length** | The single biggest factor. Each extra character multiplies the number of possible guesses. |
| **Character variety** | Whether you use lowercase, UPPERCASE, digits and symbols. More variety = a bigger search space per character. |
| **Predictability** | Common/leaked passwords, dictionary words, keyboard runs (`qwerty`), sequences (`1234`), and repeated characters (`aaa`). |
| **Entropy (bits)** | A single number combining length and variety that estimates how much guessing effort a password demands. |

From the entropy it also estimates how long an **offline** attacker with a fast
GPU (assumed ~10 billion guesses/second against a weak hash) would need to crack
it, and gives an overall rating from **Very Weak** to **Very Strong**.

## How entropy is calculated

```
entropy (bits) = length × log2(pool size)
```

The *pool size* is how many different characters an attacker must consider per
position, based on the character families you actually used:

* lowercase → 26
* uppercase → 26
* digits → 10
* symbols → ~33

If the password contains predictable patterns (a dictionary word, a keyboard
run, a sequence, or repeats), the tool lowers this to an **effective** entropy,
because those patterns make it far easier to guess than the raw number suggests.
The rating and crack-time estimate both use that effective number, so they
always agree.

> These figures are **estimates to build intuition**, not guarantees. Real
> strength also depends on how the defender stores the password (a slow, salted
> hash like bcrypt/Argon2 slows attackers down enormously).

## Build

No external libraries are required — just the C++ standard library (C++17).

### Visual Studio (Windows)
1. Create a new **Console App** project.
2. Replace the contents of the main `.cpp` file with `PasswordChecker.cpp`.
3. Make sure the language standard is **ISO C++17** (Project → Properties →
   C/C++ → Language → C++ Language Standard).
4. Press the green ▶ to build and run.

### g++ (Linux / macOS)
```bash
g++ -std=c++17 PasswordChecker.cpp -o passwordchecker
./passwordchecker
```

## Usage

Run the program and type a password to check. Press **Enter** on an empty line
to quit. You can check as many passwords as you like in one session.

```
Enter a password to check (or just press Enter to quit): qwerty123456
--------------------------------------------------
  Length:        12 characters
  Character mix: [lowercase] [digits]
  Entropy:       ~62 bits  (but only ~37 bits once predictable patterns are accounted for)
  Est. crack time (offline fast attack): 7 seconds
  RATING:        Very Weak

  Why it could be stronger:
   - It contains a well-known word (like 'password' or 'admin'); adding digits on the end barely helps.
   - It contains a keyboard pattern (like 'qwerty' or 'asdf'), which attackers try very early.
   - It contains a run of sequential characters (like '1234' or 'abcd').
   - It uses few character types. Mixing lower, UPPER, digits and symbols widens the search space.
--------------------------------------------------
```

*(Add your own screenshot here as `screenshot.png`.)*

## The takeaway

A long passphrase of ordinary words beats a short string of random symbols.
Length wins. And a password that looks complicated (`P@ssw0rd!`) can still be
weak if it is built from a predictable word — attackers' wordlists already
include those substitutions.

**Best practice:** use a password manager, a unique password per site, and
enable multi-factor authentication wherever you can.

## Ethics

This tool is for **learning** and for checking **your own** passwords. Do not
use it, or any technique it demonstrates, against accounts or systems you do not
own or have explicit written permission to test.

## License

All rights rserved
