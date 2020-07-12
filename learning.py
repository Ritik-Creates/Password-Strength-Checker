import requests
import hashlib
import sys


def request_api_data(query_characters):
    url = 'https://api.pwnedpasswords.com/range/' + query_characters
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error Fetching: {res.status_code}, check your api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(mypassword):
    sha1hashlib = hashlib.sha1(mypassword.encode('utf-8')).hexdigest().upper()
    first5char, tail = sha1hashlib[:5], sha1hashlib[5:]
    response = request_api_data(first5char)
    return get_password_leaks_count(response, tail)


def main(*args):
    for passwordasker in args:
        count = pwned_api_check(passwordasker)
        if count:
            print(
                f'{passwordasker} was found {count} times... Immediately change your password')
        else:
            print(f'{passwordasker} not found, Continue with this passwwword')
    return 'done!'


if __name__ == "__main__":
    passwordasker = input('Enter Your Password to check it\'s security-> ')
    sys.exit(main(passwordasker))
