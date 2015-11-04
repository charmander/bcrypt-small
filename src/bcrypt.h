int bcrypt_hashpass(const char* key, const char* salt, char* encrypted, size_t encryptedlen);

#define BCRYPT_VERSION '2'
#define BCRYPT_MAXSALT 16       /* Precomputation is just so nice */
#define BCRYPT_WORDS 6          /* Ciphertext words */
#define BCRYPT_MINLOGROUNDS 4   /* we have log2(rounds) in salt */

#define BCRYPT_SALTSPACE (7 + (BCRYPT_MAXSALT * 4 + 2) / 3 + 1)
#define BCRYPT_HASHSPACE 61
