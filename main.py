import os
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import base64
import time
from colorama import Fore, Back

def is_valid_fernet_key(key):
    try:
        decoded_key = base64.urlsafe_b64decode(key)
        return len(decoded_key) == 32
    except (base64.binascii.Error, ValueError):
        return False

def generate_key():
    response = input(Fore.RED + 'WARNING: Generating a new key will clear all passwords from passwords.txt. Do you want to continue? (yes/no): ' + Fore.YELLOW)
    if response.lower() != 'yes':
        print('Key generation cancelled.')
        input('Press enter to return to the main menu...')
        return

    # Clear the passwords.txt file
    open('passwords.txt', 'w').close()

    print('Generating key...')
    key = Fernet.generate_key()
    print('Key:', key.decode())
    print('''
    Warning: Store this key in a safe place.
    Losing this key means you cannot decrypt the data.
    ''')
    input('Press enter to return to the main menu...')

def encrypt_data():
    key = input('Please paste in your encryption key: ')
    os.system('cls' if os.name == 'nt' else 'clear')

    if not is_valid_fernet_key(key):
        print("Invalid key")
        input()
        return

    f = Fernet(key)
    
    plainText = input('Text: ')
    cipherText = f.encrypt(plainText.encode('utf-8'))
    
    print("CipherText:", cipherText.decode('utf-8'))
    
    with open("passwords.txt", "a") as file:
        file.write(cipherText.decode('utf-8') + "\n")
    print("Encrypted data has been appended to passwords.txt")
    
    del key
    input('Press enter to return to the main menu...')

def decrypt_data():
    try:
        key = input('Please paste in your encryption key: ')
        os.system('cls' if os.name == 'nt' else 'clear')

        if not is_valid_fernet_key(key):
            print("Invalid key")
            input()
            exit()

        f = Fernet(key)

        # Reading the encrypted data from the file
        with open("passwords.txt", "r") as file:
            lines = file.readlines()

        # Decrypting each line individually
        for line in lines:
            encrypted_password = line.strip()  # Removing any trailing newlines
            decrypted_password = f.decrypt(encrypted_password.encode('utf-8'))
            print(decrypted_password.decode('utf-8'))

    except InvalidToken:
        print("Error during decryption. Possibly due to an invalid key.")
    except FileNotFoundError:
        print("Error: passwords.txt file not found.")
        
    finally:
        # To ensure the key variable is deleted even if an error occurs.
        if 'key' in locals():
            del key
    input('Press enter to return to the main menu...')


def main():
    while True:       
        if firstStart:
            print(Fore.YELLOW + Back.BLACK +
'''
/  \__/  \__/  \__/  \__/  \__/  \__
\__/  \__/  \__/  \__/  \__/  \__/  
/  \__/  \__/  \__/  \__/  \__/  \__
\__/  \__/  \_            _/  \__/  
/  \__/  \__/   HoneyHex   \__/  \__
\__/  \__/  \_            _/  \__/  
/  \__/  \__/  \__/  \__/  \__/  \__
\__/  \__/  \__/  \__/  \__/  \__/  
''')
            time.sleep(3)
            firstStart = False
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print('''
        Password Manager:
        1. Generate Key
        2. Encrypt Data
        3. Decrypt Data
        4. Exit
        ''')

        choice = input('Choose an option: ')
        
        if choice == '1':
            generate_key()
        elif choice == '2':
            encrypt_data()
        elif choice == '3':
            decrypt_data()
        elif choice == '4':
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please choose a number between 1 and 4.")
            input('Press enter to continue...')

firstStart = True

if __name__ == "__main__":
    main()
