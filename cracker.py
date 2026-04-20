import hashlib
import time
import itertools
import string
import sys


# I learned about hashlib from the python docs
# hashlib lets you hash strings with different algorithms (md5, sha256, etc.)

def hash_password(password, algorithm):
    # encode the string first because hashlib needs bytes not a string
    encoded = password.encode("utf-8")

    if algorithm == "md5":
        return hashlib.md5(encoded).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(encoded).hexdigest()
    elif algorithm == "bcrypt":
        # bcrypt needs to be installed separately (pip install bcrypt)
        # i put it here so the rest of the script still works without it
        try:
            import bcrypt
            hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())
            return hashed.decode("utf-8")
        except ImportError:
            print("bcrypt is not installed, run: pip install bcrypt")
            sys.exit(1)
    else:
        print(f"unknown algorithm: {algorithm}")
        sys.exit(1)


def check_if_match(candidate, target_hash, algorithm):
    # bcrypt hashes are different every time (because of the salt)
    # so you can't just compare them with == like md5/sha256
    if algorithm == "bcrypt":
        import bcrypt
        return bcrypt.checkpw(candidate.encode("utf-8"), target_hash.encode("utf-8"))

    # for md5 and sha256 we just hash the candidate and compare
    return hash_password(candidate, algorithm) == target_hash


# ---- dictionary attack ----
# tries every word from a wordlist file against the hash
# this is how most real attacks work apparently

def dictionary_attack(target_hash, wordlist_file, algorithm):
    attempts = 0
    start = time.time()  # TODO: maybe use perf_counter instead? looked it up and its more precise

    try:
        f = open(wordlist_file, "r", encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        print(f"wordlist file not found: {wordlist_file}")
        return None

    for line in f:
        word = line.strip()

        # skip empty lines
        if word == "":
            continue

        attempts += 1

        if check_if_match(word, target_hash, algorithm):
            elapsed = time.time() - start
            f.close()
            return {
                "found": True,
                "password": word,
                "attempts": attempts,
                "time": elapsed
            }

    f.close()
    elapsed = time.time() - start
    return {
        "found": False,
        "password": None,
        "attempts": attempts,
        "time": elapsed
    }


# ---- brute force attack ----
# generates every possible combination of characters up to max_length
# WARNING: gets very slow very fast if you increase max_length
# 4 chars = ~1.7 million combinations with digits+lowercase

def brute_force_attack(target_hash, algorithm, max_length=3):
    # only using digits and lowercase for now, adding uppercase would make it way too slow
    charset = string.digits + string.ascii_lowercase

    attempts = 0
    start = time.time()

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1

            if check_if_match(candidate, target_hash, algorithm):
                elapsed = time.time() - start
                return {
                    "found": True,
                    "password": candidate,
                    "attempts": attempts,
                    "time": elapsed
                }

    elapsed = time.time() - start
    return {
        "found": False,
        "password": None,
        "attempts": attempts,
        "time": elapsed
    }


def print_result(result, mode, algorithm):
    print(f"\n  [{mode.upper()} - {algorithm.upper()}]")
    print(f"  attempts : {result['attempts']}")
    print(f"  time     : {result['time']:.4f}s")
    if result["found"]:
        print(f"  result   : FOUND -> {result['password']}")
    else:
        print(f"  result   : not found")


# ---- bcrypt demo ----
# this is separate because bcrypt needs to be installed
# the point is to show how much slower it is compared to md5

def bcrypt_demo():
    try:
        import bcrypt
    except ImportError:
        print("install bcrypt first: pip install bcrypt")
        return

    password = "hunter2"
    print(f"\n--- bcrypt vs md5 timing (password: '{password}') ---\n")

    # time md5 - do it 100 times and average it so the result is more stable
    start = time.time()
    for i in range(100):
        hashlib.md5(password.encode()).hexdigest()
    md5_avg = (time.time() - start) / 100

    # time bcrypt - only once because it already takes a while
    start = time.time()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    bcrypt_time = time.time() - start

    print(f"  md5 average (x100) : {md5_avg * 1000:.4f} ms")
    print(f"  bcrypt (x1)        : {bcrypt_time * 1000:.1f} ms")
    print(f"\n  bcrypt is roughly {int(bcrypt_time / md5_avg)}x slower")
    print("  this is on purpose - slow hashing = harder to brute force\n")


def main():
    target = "abc"
    wordlist = "wordlist.txt"

    print("\n=== password cracker demo ===")
    print(f"target password: '{target}'")
    print("(in a real scenario you'd only have the hash, not the actual password)\n")

    # hash the target with both algorithms
    md5_hash = hash_password(target, "md5")
    sha256_hash = hash_password(target, "sha256")

    print(f"md5 hash    : {md5_hash}")
    print(f"sha256 hash : {sha256_hash}")

    # --- dictionary attack ---
    print("\n--- dictionary attack ---")
    result = dictionary_attack(md5_hash, wordlist, "md5")
    print_result(result, "dictionary", "md5")

    result = dictionary_attack(sha256_hash, wordlist, "sha256")
    print_result(result, "dictionary", "sha256")

    # --- brute force ---
    print("\n--- brute force attack (max 3 chars) ---")
    print("this might take a second...\n")

    result = brute_force_attack(md5_hash, "md5", max_length=3)
    print_result(result, "brute force", "md5")

    result = brute_force_attack(sha256_hash, "sha256", max_length=3)
    print_result(result, "brute force", "sha256")

    print("\n--- note on bcrypt ---")
    print("bcrypt is different - it's designed to be slow on purpose")
    print("run with --bcrypt flag to see the timing comparison")
    print("example: python cracker.py --bcrypt\n")


if __name__ == "__main__":
    if "--bcrypt" in sys.argv:
        bcrypt_demo()
    else:
        main()