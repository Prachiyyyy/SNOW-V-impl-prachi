#include <iostream>
#include <iomanip>
#include <cstring>
#include "SNOWV.h"
#include "ghash.h"

// Helper function to print hex arrays
void print_hex(const char* label, const u8* data, size_t length) {
    std::cout << label << ": ";
    for(size_t i = 0; i < length; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if(i < length - 1) std::cout << " ";
    }
    std::cout << std::dec << std::endl;
}

// Helper function to compare arrays
bool compare_arrays(const u8* expected, const u8* actual, size_t length) {
    return memcmp(expected, actual, length) == 0;
}

// Test vector structure
struct TestVector {
    const char* name;
    u8 key[32];
    u8 iv[16];
    u8 plaintext[64];
    u64 plaintext_len;
    u8 aad[64];
    u64 aad_len;
    u8 expected_ciphertext[64];
    u8 expected_tag[16];
};

// Test vectors - Add your test vectors here
TestVector test_vectors[] = {
    {
        "Test Vector 1",
        // Key
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
        // IV
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
        // Plaintext
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
        16, // plaintext length
        // AAD
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
        8, // aad length
        // Expected ciphertext (placeholder - replace with actual values)
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        // Expected tag (placeholder - replace with actual values)
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    }
    // Add more test vectors here...
};

// Function to run a single test vector
bool run_test_vector(const TestVector& tv) {
    std::cout << "\n=== " << tv.name << " ===" << std::endl;
    
    // Print inputs
    print_hex("Key", tv.key, 32);
    print_hex("IV", tv.iv, 16);
    print_hex("Plaintext", tv.plaintext, tv.plaintext_len);
    print_hex("AAD", tv.aad, tv.aad_len);
    
    // Allocate output buffers
    u8 ciphertext[64];
    u8 tag[16];
    
    // Perform encryption
    snowv_gcm_encrypt(tag, ciphertext, (u8*)tv.plaintext, tv.plaintext_len,
                      (u8*)tv.aad, tv.aad_len, (u8*)tv.key, (u8*)tv.iv);
    
    // Print outputs
    print_hex("Generated Ciphertext", ciphertext, tv.plaintext_len);
    print_hex("Generated Tag", tag, 16);
    print_hex("Expected Ciphertext", tv.expected_ciphertext, tv.plaintext_len);
    print_hex("Expected Tag", tv.expected_tag, 16);
    
    // Verify results
    bool ciphertext_match = compare_arrays(tv.expected_ciphertext, ciphertext, tv.plaintext_len);
    bool tag_match = compare_arrays(tv.expected_tag, tag, 16);
    
    if (ciphertext_match && tag_match) {
        std::cout << "✓ TEST PASSED" << std::endl;
        return true;
    } else {
        std::cout << "✗ TEST FAILED" << std::endl;
        if (!ciphertext_match) std::cout << "  - Ciphertext mismatch" << std::endl;
        if (!tag_match) std::cout << "  - Tag mismatch" << std::endl;
        return false;
    }
}

// Function to test decryption
bool test_decryption(const TestVector& tv) {
    std::cout << "\n=== Testing Decryption for " << tv.name << " ===" << std::endl;
    
    // Allocate buffers
    u8 ciphertext[64];
    u8 tag[16];
    u8 decrypted[64];
    
    // First encrypt to get ciphertext and tag
    snowv_gcm_encrypt(tag, ciphertext, (u8*)tv.plaintext, tv.plaintext_len,
                      (u8*)tv.aad, tv.aad_len, (u8*)tv.key, (u8*)tv.iv);
    
    // Then decrypt
    try {
        snowv_gcm_decrypt(tag, ciphertext, decrypted, tv.plaintext_len,
                          (u8*)tv.aad, tv.aad_len, (u8*)tv.key, (u8*)tv.iv);
        
        // Verify decryption
        bool decryption_match = compare_arrays(tv.plaintext, decrypted, tv.plaintext_len);
        
        if (decryption_match) {
            std::cout << "✓ DECRYPTION TEST PASSED" << std::endl;
            return true;
        } else {
            std::cout << "✗ DECRYPTION TEST FAILED" << std::endl;
            return false;
        }
    } catch (...) {
        std::cout << "✗ DECRYPTION TEST FAILED - Authentication error" << std::endl;
        return false;
    }
}

int main() {
    std::cout << "SNOW-V Test Vectors" << std::endl;
    std::cout << "==================" << std::endl;
    
    int total_tests = sizeof(test_vectors) / sizeof(test_vectors[0]);
    int passed_tests = 0;
    int passed_decryption_tests = 0;
    
    // Run all test vectors
    for (int i = 0; i < total_tests; i++) {
        if (run_test_vector(test_vectors[i])) {
            passed_tests++;
        }
        
        if (test_decryption(test_vectors[i])) {
            passed_decryption_tests++;
        }
    }
    
    // Print summary
    std::cout << "\n==================" << std::endl;
    std::cout << "TEST SUMMARY" << std::endl;
    std::cout << "==================" << std::endl;
    std::cout << "Encryption tests: " << passed_tests << "/" << total_tests << " passed" << std::endl;
    std::cout << "Decryption tests: " << passed_decryption_tests << "/" << total_tests << " passed" << std::endl;
    
    if (passed_tests == total_tests && passed_decryption_tests == total_tests) {
        std::cout << "✓ ALL TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cout << "✗ SOME TESTS FAILED" << std::endl;
        return 1;
    }
}