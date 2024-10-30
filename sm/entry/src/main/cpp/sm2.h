#include "napi.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string>
#include <vector>
#include <iostream>
#include <memory>

namespace sm2 {

#pragma once
const char *SM2_PUBLIC_KEY = R"(
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEWr91LPdgTLpIH/rzXQQw/qmJKkli
5nPj0xNfyE87kXdP2KakBHBSf8JGHOnyXcdnvNnNrc33jQseeIuTmPuJpQ==
-----END PUBLIC KEY-----
)";

#pragma once
const char *SM2_PRIVATE_KEY = R"(
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgZBIiMFLLF/+OmksS
+dlFpWxBgsJpj0NLon+bKN5Yz2ihRANCAARav3Us92BMukgf+vNdBDD+qYkqSWLm
c+PTE1/ITzuRd0/YpqQEcFJ/wkYc6fJdx2e82c2tzfeNCx54i5OY+4ml
-----END PRIVATE KEY-----
)";

// 自定义智能指针删除器
struct BIODeleter {
    void operator()(BIO *bio) { BIO_free_all(bio); }
};

struct EVP_PKEY_CTXDeleter {
    void operator()(EVP_PKEY_CTX *ctx) { EVP_PKEY_CTX_free(ctx); }
};

struct EVP_PKEYDeleter {
    void operator()(EVP_PKEY *key) { EVP_PKEY_free(key); }
};

// Base64 编码函数
std::string Base64Encode(const std::vector<unsigned char> &binary_data) {
    BIO *bio = nullptr;
    BIO *b64 = nullptr;
    BUF_MEM *bufferPtr = nullptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // 不添加换行符
    BIO_write(bio, binary_data.data(), binary_data.size());
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);
    return result;
}

// Base64 解码函数
std::vector<unsigned char> Base64Decode(const std::string &base64_data) {
    BIO *bio = nullptr;
    BIO *b64 = nullptr;
    std::vector<unsigned char> result(base64_data.size());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(base64_data.c_str(), -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // 不添加换行符
    int decoded_size = BIO_read(bio, result.data(), base64_data.size());

    BIO_free_all(bio);

    if (decoded_size > 0) {
        result.resize(decoded_size);
        return result;
    }
    return std::vector<unsigned char>();
}

// 错误处理函数
void PrintOpenSSLError() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::cerr << "OpenSSL Error: " << err_buf << std::endl;
    }
}

// 从字符串加载密钥
std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter> LoadKeyFromString(const std::string &keyStr, bool isPublic) {
    BIO *bio = BIO_new_mem_buf(keyStr.c_str(), -1);
    if (!bio) {
        std::cerr << "Error creating BIO" << std::endl;
        return nullptr;
    }

    EVP_PKEY *key = nullptr;
    if (isPublic) {
        key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    } else {
        key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    }

    BIO_free_all(bio);

    if (!key) {
        std::cerr << "Error reading key from string" << std::endl;
        PrintOpenSSLError();
        return nullptr;
    }

    return std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter>(key);
}

// 加密函数
bool Encrypt(const std::string &plaintext, EVP_PKEY *publicKey, std::string &base64Ciphertext) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter> ctx(EVP_PKEY_CTX_new(publicKey, nullptr));
    if (!ctx) {
        std::cerr << "Error creating encryption context" << std::endl;
        PrintOpenSSLError();
        return false;
    }

    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
        std::cerr << "Error initializing encryption" << std::endl;
        PrintOpenSSLError();
        return false;
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, reinterpret_cast<const unsigned char *>(plaintext.c_str()),
                         plaintext.length()) <= 0) {
        std::cerr << "Error determining ciphertext length" << std::endl;
        PrintOpenSSLError();
        return false;
    }

    std::vector<unsigned char> ciphertext(outlen);
    if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &outlen,
                         reinterpret_cast<const unsigned char *>(plaintext.c_str()), plaintext.length()) <= 0) {
        std::cerr << "Error during encryption" << std::endl;
        PrintOpenSSLError();
        return false;
    }
    ciphertext.resize(outlen);

    base64Ciphertext = Base64Encode(ciphertext);
    return true;
}

// 解密函数
bool Decrypt(const std::string &base64Ciphertext, EVP_PKEY *privateKey, std::string &plaintext) {
    std::vector<unsigned char> ciphertext = Base64Decode(base64Ciphertext);
    if (ciphertext.empty()) {
        std::cerr << "Error decoding base64 ciphertext" << std::endl;
        return false;
    }

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter> ctx(EVP_PKEY_CTX_new(privateKey, nullptr));
    if (!ctx) {
        std::cerr << "Error creating decryption context" << std::endl;
        PrintOpenSSLError();
        return false;
    }

    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
        std::cerr << "Error initializing decryption" << std::endl;
        PrintOpenSSLError();
        return false;
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        std::cerr << "Error determining plaintext length" << std::endl;
        PrintOpenSSLError();
        return false;
    }

    std::vector<unsigned char> out(outlen);
    if (EVP_PKEY_decrypt(ctx.get(), out.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        std::cerr << "Error during decryption" << std::endl;
        PrintOpenSSLError();
        return false;
    }

    plaintext = std::string(reinterpret_cast<char *>(out.data()), outlen);
    return true;
}

Napi::Value SM2_ENCRYPT(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 从字符串加载密钥
    auto publicKey = LoadKeyFromString(SM2_PUBLIC_KEY, true);
    auto privateKey = LoadKeyFromString(SM2_PRIVATE_KEY, false);

    if (!publicKey || !privateKey) {
        PrintOpenSSLError();
        return env.Null();
    }

    // 测试加密和解密
    const std::string originalText = info[0].As<Napi::String>();
    std::string base64Ciphertext;


    Encrypt(originalText, publicKey.get(), base64Ciphertext);

    return Napi::String::New(env, base64Ciphertext);
}

Napi::Value SM2_DECRYPT(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 从字符串加载密钥
    auto publicKey = LoadKeyFromString(SM2_PUBLIC_KEY, true);
    auto privateKey = LoadKeyFromString(SM2_PRIVATE_KEY, false);

    if (!publicKey || !privateKey) {
        PrintOpenSSLError();
        return env.Null();
    }

    const std::string originalText = info[0].As<Napi::String>();
    std::string decryptedText;

    Decrypt(originalText, privateKey.get(), decryptedText);

    return Napi::String::New(env, decryptedText);
}
}