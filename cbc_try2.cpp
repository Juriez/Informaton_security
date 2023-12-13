#include <iostream>
#include <fstream>
#include "aes.h"

using namespace std;

#define Total_round 10
#define padding_char '0'

int main() {
    // Read textToEncrypt from a text file
    ifstream textFile("plaintext.txt");
    if (!textFile.is_open()) {
        cout << "Error: Unable to open plaintext.txt" << endl;
        return 1;
    }
    string textToEncrypt;
    getline(textFile, textToEncrypt);
    textFile.close();

    // Read key from a text file
    ifstream keyFile("key.txt");
    if (!keyFile.is_open()) {
        cout << "Error: Unable to open key.txt" << endl;
        return 1;
    }
    string key;
    getline(keyFile, key);
    keyFile.close();

    key_expansion((unsigned char *)key.c_str());
    cout << endl;
    print_key();

    int text_length = textToEncrypt.length();
    int extended_length;

    // Calculate the extended length for padding
    if (text_length % AES_BLOCK_SIZE != 0) {
        extended_length = text_length + (AES_BLOCK_SIZE - (text_length % AES_BLOCK_SIZE));
    } else {
        extended_length = text_length;
    }

    unsigned char iv[AES_BLOCK_SIZE] = {0}; // Initialization Vector

    unsigned char padded_text[extended_length + 1];
    for (int i = 0; i < extended_length; i++) {
        if (i < text_length)
            padded_text[i] = textToEncrypt[i];
        else
            padded_text[i] = padding_char;
        if (i + 1 == extended_length)
            padded_text[i + 1] = '\0';
    }

    unsigned char encrypted_text[extended_length + 1];
    for (int i = 0; i < extended_length; i += AES_BLOCK_SIZE) {
        // Encryption
        unsigned char block[AES_BLOCK_SIZE];
        for (int k = 0; k < AES_BLOCK_SIZE; k++) {
            block[k] = padded_text[i + k] ^ iv[k]; // XOR with IV
        }

        encyption(block);

        for (int k = 0; k < AES_BLOCK_SIZE; k++) {
            encrypted_text[i + k] = block[k];
        }

        // Update IV with the current ciphertext block
        memcpy(iv, encrypted_text + i, AES_BLOCK_SIZE);
    }

    // Write the ciphertext to a text file
    ofstream ciphertextFile("ciphertext.txt");
    if (!ciphertextFile.is_open()) {
        cout << "Error: Unable to open ciphertext.txt" << endl;
        return 1;
    }
    for (int i = 0; i < extended_length; i++) {
        ciphertextFile << encrypted_text[i];
    }
    ciphertextFile.close();

    // Reset IV for decryption to the agreed-upon value
    memset(iv, 0, AES_BLOCK_SIZE); // Example: setting it to all zeros

    unsigned char decrypted_text[extended_length];
    for (int i = 0; i < extended_length; i += AES_BLOCK_SIZE) {
        // Decryption
        unsigned char block[AES_BLOCK_SIZE];
        for (int k = 0; k < AES_BLOCK_SIZE; k++) {
            block[k] = encrypted_text[i + k];
        }

        decryption(block);

        // XOR with the current IV
        for (int k = 0; k < AES_BLOCK_SIZE; k++) {
            decrypted_text[i + k] = block[k] ^ iv[k];
        }

        // Update IV with the current ciphertext block
        memcpy(iv, encrypted_text + i, AES_BLOCK_SIZE);
    }

    // Identify and remove padding
    int padding_length = 0;
    for (int i = extended_length - 1; i >= 0; i--) {
        if (decrypted_text[i] == padding_char) {
            padding_length++;
        } else {
            break;
        }
    }

    // Null-terminate the decrypted text
    decrypted_text[extended_length - padding_length] = '\0';

    // Write the decrypted text to a text file
    ofstream decryptedTextFile("decrypted.txt");
    if (!decryptedTextFile.is_open()) {
        cout << "Error: Unable to open decrypted_text.txt" << endl;
        return 1;
    }
    decryptedTextFile << (char *)decrypted_text;
    decryptedTextFile.close();

    return 0;
}
