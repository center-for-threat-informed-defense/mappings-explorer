# TODO: Replace with your module code.
def palindrome(s):
    for idx in range(len(s) // 2):
        if s[idx] != s[-idx - 1]:
            return False
    return True
