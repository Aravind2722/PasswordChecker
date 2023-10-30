import requests
import hashlib

def request_api_data(password_prefix):
  url = 'https://api.pwnedpasswords.com/range/' + password_prefix
  res = requests.get(url)
  if res.status_code != 200:
    raise RuntimeError(f'Error fetching: {res.status_code}\ncheck the api and try again')
  return res

def get_password_leaks_count(response, password_tail):
  suffix_and_counts = (line.split(':') for line in response.text.splitlines())
  for suffix, count in suffix_and_counts:
    if suffix == password_tail:
      return count
  return 0

def pwned_api_check(password):
  encoded_password = password.encode('utf-8')
  sha1password = hashlib.sha1(encoded_password).hexdigest().upper()
  first5_char, tail = sha1password[:5], sha1password[5:]
  response = request_api_data(first5_char)
  return get_password_leaks_count(response, tail)

def main():
  passwords = input().split()
  for password in passwords:
    count = pwned_api_check(password)
    if count:
      print(f'Your password \'{password}\' is (***breached / seen***) - \'{count}\' times...\nPassword unsafe! Time to change!\n\n')
    else:
      print(f'Your password \'{password}\' is safe!\n\n')
  return

if __name__ == '__main__':
    main()