import argparse
import hashlib
import time
import itertools
import string
import sys
from pathlib import Path


# I learned about hashlib from the python docs
# hashlib lets you hash strings with different algorithms (md5, sha256, etc.)

def hash_password(password: str, algorithm: str) -> str:
    # encode the string first because hashlib needs bytes not a string
    encoded = password.encode("utf-8")

    if algorithm == "md5":
        return hashlib.md5(encoded).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(encoded).hexdigest()
    elif algorithm == "bcrypt":
        # bcrypt needs to be installed separately (pip install bcrypt)
        # i put it here so the rest of the script still works without it
        bcrypt = load_bcrypt()
        if len(encoded) > 72:
            raise ValueError("bcrypt passwords must not exceed 72 UTF-8 bytes")
        return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode("utf-8")
    raise ValueError(f"unknown algorithm: {algorithm}")


def load_bcrypt():
    try:
        import bcrypt
    except ImportError as exc:
        raise RuntimeError("bcrypt is unavailable; run: pip install -r requirements.txt") from exc
    return bcrypt


def check_if_match(candidate: str, target_hash: str, algorithm: str) -> bool:
    # bcrypt hashes are different every time (because of the salt)
    # so you can't just compare them with == like md5/sha256
    if algorithm == "bcrypt":
        bcrypt = load_bcrypt()
        encoded = candidate.encode("utf-8")
        if len(encoded) > 72:
            raise ValueError("bcrypt passwords must not exceed 72 UTF-8 bytes")
        return bcrypt.checkpw(encoded, target_hash.encode("utf-8"))

    # for md5 and sha256 we just hash the candidate and compare
    return hash_password(candidate, algorithm) == target_hash


# ---- dictionary attack ----
# tries every word from a wordlist file against the hash
# This demonstration uses only bundled sample data.

def dictionary_attack(target_hash: str, wordlist_file: Path, algorithm: str) -> dict:
    attempts = 0
    start = time.perf_counter()

    with open(wordlist_file, "r", encoding="utf-8") as f:
        for line in f:
            word = line.rstrip("\r\n")
            if word == "":
                continue
            attempts += 1
            if check_if_match(word, target_hash, algorithm):
                return {
                    "found": True,
                    "password": word,
                    "attempts": attempts,
                    "time": time.perf_counter() - start,
                }

    elapsed = time.perf_counter() - start
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

def brute_force_attack(target_hash: str, algorithm: str, max_length: int = 3) -> dict:
    # only using digits and lowercase for now, adding uppercase would make it way too slow
    charset = string.digits + string.ascii_lowercase

    attempts = 0
    start = time.perf_counter()

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1

            if check_if_match(candidate, target_hash, algorithm):
                elapsed = time.perf_counter() - start
                return {
                    "found": True,
                    "password": candidate,
                    "attempts": attempts,
                    "time": elapsed
                }

    elapsed = time.perf_counter() - start
    return {
        "found": False,
        "password": None,
        "attempts": attempts,
        "time": elapsed
    }


def print_result(result: dict, mode: str, algorithm: str) -> None:
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

def bcrypt_demo() -> None:
    password = "hunter2"  # Synthetic example, not a real credential.
    print("\n--- bcrypt password storage demonstration ---\n")
    start = time.perf_counter()
    first_hash = hash_password(password, "bcrypt")
    elapsed = time.perf_counter() - start
    second_hash = hash_password(password, "bcrypt")

    print(f"  first salted hash  : {first_hash}")
    print(f"  second salted hash : {second_hash}")
    print(f"  different hashes  : {first_hash != second_hash}")
    print(f"  correct password  : {check_if_match(password, first_hash, 'bcrypt')}")
    print(f"  wrong password    : {check_if_match('wrong', first_hash, 'bcrypt')}")
    print(f"  bcrypt hash creation (including salt): {elapsed * 1000:.1f} ms")
    start = time.perf_counter()
    hash_password(password, "md5")
    print(f"  MD5 hash creation: {(time.perf_counter() - start) * 1000:.4f} ms")
    print("  Illustrative timings only; hardware and workload affect results.")
    print("  Salts and computational cost help protect stored passwords.")


def main() -> None:
    target = "abc"
    wordlist = Path(__file__).resolve().parent / "wordlist.txt"

    print("\n=== Password Hasher: educational demo ===")
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


def run_cli() -> int:
    parser = argparse.ArgumentParser(description="Password Hasher: synthetic educational demos")
    parser.add_argument("--bcrypt", action="store_true", help="show salted password verification")
    args = parser.parse_args()
    try:
        if args.bcrypt:
            bcrypt_demo()
        else:
            main()
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run_cli())
