#!/bin/bash
# Create a test file
echo "Hello, World! This is a secret message." > plain.txt

# Encrypt with a hex key (generate one randomly)
KEY=$(openssl rand -hex 32)
./filecrypt -e -k "$KEY" -i plain.txt -o encrypted.bin

# Decrypt back
./filecrypt -d -k "$KEY" -i encrypted.bin -o decrypted.txt

# Compare
diff plain.txt decrypted.txt && echo "SUCCESS: Files match" || echo "FAIL: Files differ"