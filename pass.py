import tkinter as tk
from tkinter import messagebox
import hashlib
import requests
import re
import math
import string 

# BIG THANKS TO: 
# CHATGPT, https://haveibeenpwned.com/
# CONTACT ON DISCORD: .luckyhvh

# thanks gpt
def calculate_entropy(password: str) -> float:
    """Calculate the Shannon entropy of the password."""
    n = len(password)
    if n == 0:
        return 0
    freqs = {ch: password.count(ch) for ch in set(password)}
    # Shannon entropy formula (thanks gpt)
    entropy = -sum((count / n) * math.log2(count / n) for count in freqs.values())
    return entropy

# patterns
def contains_common_patterns(password: str) -> bool:
    """Checks if the password contains common patterns."""
    common_patterns = [
        r"1234", r"abcd", r"qwerty", r"password", r"letmein", r"welcome", r"monkey", r"12345", r"12345678", r"123123"
    ]
    for pattern in common_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return True
    return False

# more common words
def contains_dictionary_words(password: str) -> bool:
    """Checks if the password contains common dictionary words."""
    dictionary = set([
        'password', 'admin', 'welcome', 'qwerty', 'letmein', '12345', 'monkey', 'football', 'dragon', 'iloveyou', 'sunshine'
    ])
    words_in_password = set(password.lower().split())
    return not words_in_password.isdisjoint(dictionary)

def check_password_strength(password: str) -> str:
    """Evaluates password strength based on multiple criteria."""
    length = len(password)
    entropy = calculate_entropy(password)

    has_uppercase = any(c.isupper() for c in password)
    has_lowercase = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    # common words
    weak_patterns = contains_common_patterns(password)
    weak_words = contains_dictionary_words(password)

    # repeated chars
    has_repeated_chars = len(password) != len(set(password)) 

    # sequential patterns
    sequential_patterns = re.search(r"(012|123|234|345|456|567|678|789|1234|abcd|xyz)", password)

    strength = "Very Weak"
    
    if length < 8:
        strength = "Very Weak"
    elif 8 <= length < 12:
        strength = "Weak"
    elif 12 <= length < 16:
        strength = "Moderate"
    else:
        strength = "Strong"
    if has_uppercase and has_lowercase and has_digit and has_special:
        if entropy > 3.5 and not weak_patterns and not weak_words and not has_repeated_chars and not sequential_patterns:
            strength = "Very Strong"
        elif entropy > 2.5:
            strength = "Strong"
        elif not weak_patterns:
            strength = "Moderate"
        else:
            strength = "Weak"
    else:
        if weak_patterns or weak_words or has_repeated_chars:
            strength = "Very Weak"
        else:
            strength = "Weak"
    
    return strength

# function
def check_pwnage(password: str) -> str:
    """Check if the password has been pwned using the Have I Been Pwned API."""
    # hash sha
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = password_hash[:5]
    suffix = password_hash[5:]

    try:
        # api
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        response.raise_for_status()

        # response
        hashes = response.text.splitlines()
        for hash_entry in hashes:
            hash_value, count = hash_entry.split(':')
            if hash_value == suffix:
                return f"Your password has been pwned {count} times."
        
        return "Your password has not been pwned."
    
    except requests.exceptions.RequestException as e:
        return f"Error checking pwnage: {str(e)}"

# gui
def start_sniffing():
    password = password_entry.get()

    strength = check_password_strength(password)
    
    # api
    pwnage_status = check_pwnage(password)
    
    # gui - results
    strength_label.config(text=f"Strength: {strength}")
    pwnage_label.config(text=f"Pwnage Status: {pwnage_status}")

window = tk.Tk()
window.title("Password Strength & Pwnage Checker")

# size and lock in
window.geometry("400x250")

window.resizable(False, False)

password_label = tk.Label(window, text="Enter Password:")
password_label.pack(pady=10)

password_entry = tk.Entry(window, show="*", width=40)
password_entry.pack(pady=10)

check_button = tk.Button(window, text="Check Password", command=start_sniffing, width=20)
check_button.pack(pady=10)

# labels
strength_label = tk.Label(window, text="Strength: N/A")
strength_label.pack(pady=5)

pwnage_label = tk.Label(window, text="Pwnage Status: N/A")
pwnage_label.pack(pady=5)

# credits to luckyhvh <3

# gui
window.mainloop()
