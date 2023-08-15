
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Function to perform monoalphabetic encryption
void monoalphabeticEncrypt(char plaintext[], char key[]) {
    int length = strlen(plaintext);
    for (int i = 0; i < length; i++) {
        if (isalpha(plaintext[i])) {
            if (isupper(plaintext[i])) {
                plaintext[i] = key[plaintext[i] - 'A'];
            } else {
                plaintext[i] = tolower(key[plaintext[i] - 'a']);
            }
        }
    }
}

// Function to perform monoalphabetic decryption
void monoalphabeticDecrypt(char ciphertext[], char key[]) {
    int length = strlen(ciphertext);
    for (int i = 0; i < length; i++) {
        if (isalpha(ciphertext[i])) {
            if (isupper(ciphertext[i])) {
                for (int j = 0; j < 26; j++) {
                    if (key[j] == ciphertext[i]) {
                        ciphertext[i] = 'A' + j;
                        break;
                    }
                }
            } else {
                for (int j = 0; j < 26; j++) {
                    if (tolower(key[j]) == ciphertext[i]) {
                        ciphertext[i] = 'a' + j;
                        break;
                    }
                }
            }
        }
    }
}

int main() {
    char key[] = "QWERTYUIOPASDFGHJKLZXCVBNM";
    char message[] = "HELLO, WORLD!";
    //char message[100];
    //printf("Enter the plain text :\n");
    //scanf("%s",&message);
    char encrypted[100];
    char decrypted[100];

    // Encrypt the message
    strcpy(encrypted, message);
    monoalphabeticEncrypt(encrypted, key);
    printf("Encrypted: %s\n", encrypted);

    // Decrypt the message
    strcpy(decrypted, encrypted);
    monoalphabeticDecrypt(decrypted, key);
    printf("Decrypted: %s\n", decrypted);

    return 0;
}
