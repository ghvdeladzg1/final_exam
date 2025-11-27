import hashlib
import json
import sys
import os

def compute_hashes(filepath):
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256()
    }
    
    with open(filepath, "rb") as f:
        data = f.read()
        for h in hashes.values():
            h.update(data)
    
    return {alg: h.hexdigest() for alg, h in hashes.items()}


def save_hashes(hash_dict, output_file="hashes.json"):
    with open(output_file, "w") as f:
        json.dump(hash_dict, f, indent=4)


def load_hashes(json_path="hashes.json"):
    with open(json_path, "r") as f:
        return json.load(f)


def integrity_check(original_hashes, current_hashes):
    if original_hashes == current_hashes:
        print("Integrity Check: PASS")
        return True
    else:
        print("Integrity Check: FAIL — FILE HAS BEEN MODIFIED!")
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: python hash_util.py <file>")
        return

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print("Error: File not found.")
        return

    print(f"Computing hashes for: {file_path}")
    current_hashes = compute_hashes(file_path)

    # If hashes.json does not exist, create it (original file)
    if not os.path.exists("hashes.json"):
        print("Saving original hashes to hashes.json")
        save_hashes(current_hashes)
        print("Integrity Check: BASELINE CREATED")
    else:
        # Compare with existing hashes (tampered case)
        stored = load_hashes()
        integrity_check(stored, current_hashes)


if __name__ == "__main__":
    main()
