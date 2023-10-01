#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Constants for SHA-512
#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

// SHA-512 functions
#define ROTRIGHT64(word, shift) ((word >> shift) | (word << (64 - shift)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x) (ROTRIGHT64(x, 28) ^ ROTRIGHT64(x, 34) ^ ROTRIGHT64(x, 39))
#define EP1(x) (ROTRIGHT64(x, 14) ^ ROTRIGHT64(x, 18) ^ ROTRIGHT64(x, 41))
#define SIG0(x) (ROTRIGHT64(x, 1) ^ ROTRIGHT64(x, 8) ^ (x >> 7))
#define SIG1(x) (ROTRIGHT64(x, 19) ^ ROTRIGHT64(x, 61) ^ (x >> 6))

// Initial hash values
uint64_t sha512_initial_hash[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// Helper function to process 512-bit blocks
void sha512_process_block(uint64_t block[16]) {
    const uint64_t sha512_constants[80] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019,
        0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe,
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
        0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210,
        0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001,
        0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910,
        0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60,
        0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9,
        0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6,
        0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };

    // SHA-512 message schedule
    uint64_t w[80];
    // Initialize the message schedule
    for (int t = 0; t < 16; ++t) {
        w[t] = block[t];
    }
    for (int t = 16; t < 80; ++t) {
        w[t] = SIG1(w[t - 2]) + w[t - 7] + SIG0(w[t - 15]) + w[t - 16];
    }

    uint64_t a = sha512_initial_hash[0];
    uint64_t b = sha512_initial_hash[1];
    uint64_t c = sha512_initial_hash[2];
    uint64_t d = sha512_initial_hash[3];
    uint64_t e = sha512_initial_hash[4];
    uint64_t f = sha512_initial_hash[5];
    uint64_t g = sha512_initial_hash[6];
    uint64_t h = sha512_initial_hash[7];

    for (int t = 0; t < 80; ++t) {
        uint64_t t1 = h + EP1(e) + CH(e, f, g) + sha512_constants[t] + w[t];
        uint64_t t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    sha512_initial_hash[0] += a;
    sha512_initial_hash[1] += b;
    sha512_initial_hash[2] += c;
    sha512_initial_hash[3] += d;
    sha512_initial_hash[4] += e;
    sha512_initial_hash[5] += f;
    sha512_initial_hash[6] += g;
    sha512_initial_hash[7] += h;
}

// Main SHA-512 hashing function
void sha512(uint8_t *message, uint64_t message_length, uint8_t *digest) {
    // Initialize hash values
    for (int i = 0; i < 8; ++i) {
        sha512_initial_hash[i] = sha512_initial_hash[i];
    }

    // Process each 1024-bit block
    for (uint64_t i = 0; i < message_length; i += SHA512_BLOCK_SIZE) {
        uint64_t block[16] = {0};

        // Copy the message block into the current block
        for (int j = 0; j < 16; ++j) {
            if ((i + j * 8) < message_length) {
                block[j] = ((uint64_t)message[i + j * 8] << 56) |
                           ((uint64_t)message[i + j * 8 + 1] << 48) |
                           ((uint64_t)message[i + j * 8 + 2] << 40) |
                           ((uint64_t)message[i + j * 8 + 3] << 32) |
                           ((uint64_t)message[i + j * 8 + 4] << 24) |
                           ((uint64_t)message[i + j * 8 + 5] << 16) |
                           ((uint64_t)message[i + j * 8 + 6] << 8) |
                           (uint64_t)message[i + j * 8 + 7];
            }
        }

        sha512_process_block(block);
    }

    // Finalize
    for (int i = 0; i < 8; ++i) {
        digest[i * 8 + 0] = (sha512_initial_hash[i] >> 56) & 0xFF;
        digest[i * 8 + 1] = (sha512_initial_hash[i] >> 48) & 0xFF;
        digest[i * 8 + 2] = (sha512_initial_hash[i] >> 40) & 0xFF;
        digest[i * 8 + 3] = (sha512_initial_hash[i] >> 32) & 0xFF;
        digest[i * 8 + 4] = (sha512_initial_hash[i] >> 24) & 0xFF;
        digest[i * 8 + 5] = (sha512_initial_hash[i] >> 16) & 0xFF;
        digest[i * 8 + 6] = (sha512_initial_hash[i] >> 8) & 0xFF;
        digest[i * 8 + 7] = sha512_initial_hash[i] & 0xFF;
    }
}

int main() {
    char message[2000];
    uint8_t digest[SHA512_DIGEST_SIZE] = {0};
    printf("Enter the message: ");
    fgets(message, sizeof(message), stdin);
    // Remove the newline character at the end, if present
    size_t len = strlen(message);
    if (len > 0 && message[len - 1] == '\n') {
        message[len - 1] = '\0';
    };

    sha512((uint8_t *)message, sizeof(message) - 1, digest);

    printf("SHA-512 Digest: ");
    for (int i = 0; i < SHA512_DIGEST_SIZE; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}


