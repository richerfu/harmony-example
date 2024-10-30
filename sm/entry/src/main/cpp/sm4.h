#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <sstream>
#include "napi.h"

namespace sm4 {

class SM4Cipher {
private:
    // 常量定义
    static const int KEY_SIZE = 16;   // SM4 密钥长度 (128 bits)
    static const int IV_SIZE = 16;    // IV 长度 (128 bits)
    static const int BLOCK_SIZE = 16; // 块大小 (128 bits)

    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;

    // 错误处理函数
    static void handleOpenSSLErrors() {
        unsigned long err;
        while ((err = ERR_get_error()) != 0) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            std::cerr << "OpenSSL Error: " << err_buf << std::endl;
        }
    }

    // 字节数组转十六进制字符串
    static std::string bytesToHex(const std::vector<unsigned char> &bytes) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned char byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    // 十六进制字符串转字节数组
    static std::vector<unsigned char> hexToBytes(const std::string &hex) {
        std::vector<unsigned char> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

public:
    // 构造函数：使用指定的密钥和 IV
    SM4Cipher(const std::vector<unsigned char> &key_data, const std::vector<unsigned char> &iv_data) {
        if (key_data.size() != KEY_SIZE) {
            throw std::runtime_error("Invalid key size");
        }
        if (iv_data.size() != IV_SIZE) {
            throw std::runtime_error("Invalid IV size");
        }
        key = key_data;
        iv = iv_data;
    }

    // 构造函数：随机生成密钥和 IV
    SM4Cipher() {
        key.resize(KEY_SIZE);
        iv.resize(IV_SIZE);

        if (RAND_bytes(key.data(), KEY_SIZE) != 1) {
            handleOpenSSLErrors();
            throw std::runtime_error("Failed to generate random key");
        }

        if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
            handleOpenSSLErrors();
            throw std::runtime_error("Failed to generate random IV");
        }
    }

    // 获取密钥和 IV
    std::string getKeyHex() const { return bytesToHex(key); }
    std::string getIVHex() const { return bytesToHex(iv); }

    // 加密函数
    std::vector<unsigned char> encrypt(const std::vector<unsigned char> &plaintext) {
        // 创建并配置加密上下文
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            handleOpenSSLErrors();
            throw std::runtime_error("Failed to create cipher context");
        }

        // 初始化加密操作
        if (EVP_EncryptInit_ex(ctx.get(), EVP_sm4_cbc(), nullptr, key.data(), iv.data()) != 1) {
            handleOpenSSLErrors();
            throw std::runtime_error("Failed to initialize encryption");
        }

        // 分配输出缓冲区
        std::vector<unsigned char> ciphertext(plaintext.size() + BLOCK_SIZE);
        int outlen1 = 0;
        int outlen2 = 0;

        // 加密数据
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outlen1, plaintext.data(), plaintext.size()) != 1) {
            handleOpenSSLErrors();
            throw std::runtime_error("Failed to encrypt data");
        }

        // 完成加密操作
        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outlen1, &outlen2) != 1) {
            handleOpenSSLErrors();
            throw std::runtime_error("Failed to finalize encryption");
        }

        // 调整输出大小
        ciphertext.resize(outlen1 + outlen2);
        return ciphertext;
    }

    // 解密函数
    std::vector<unsigned char> decrypt(const std::vector<unsigned char> &ciphertext) {
        // 创建并配置解密上下文
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            handleOpenSSLErrors();
            throw std::runtime_error("Failed to create cipher context");
        }

        // 初始化解密操作
        if (EVP_DecryptInit_ex(ctx.get(), EVP_sm4_cbc(), nullptr, key.data(), iv.data()) != 1) {
            handleOpenSSLErrors();
            throw std::runtime_error("Failed to initialize decryption");
        }

        // 分配输出缓冲区
        std::vector<unsigned char> plaintext(ciphertext.size());
        int outlen1 = 0;
        int outlen2 = 0;

        // 解密数据
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outlen1, ciphertext.data(), ciphertext.size()) != 1) {
            handleOpenSSLErrors();
            throw std::runtime_error("Failed to decrypt data");
        }

        // 完成解密操作
        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outlen1, &outlen2) != 1) {
            handleOpenSSLErrors();
            throw std::runtime_error("Failed to finalize decryption");
        }

        // 调整输出大小
        plaintext.resize(outlen1 + outlen2);
        return plaintext;
    }

    // 字符串加密便捷方法
    std::string encryptString(const std::string &plaintext) {
        std::vector<unsigned char> input(plaintext.begin(), plaintext.end());
        auto encrypted = encrypt(input);
        return bytesToHex(encrypted);
    }

    // 字符串解密便捷方法
    std::string decryptString(const std::string &hexCiphertext) {
        auto ciphertext = hexToBytes(hexCiphertext);
        auto decrypted = decrypt(ciphertext);
        return std::string(decrypted.begin(), decrypted.end());
    }
};

SM4Cipher globalCipher;

Napi::Value SM4_ENCRYPT(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    std::string text = info[0].As<Napi::String>();
    std::string ciper = globalCipher.encryptString(text);
    return Napi::String::New(env, ciper);
}

Napi::Value SM4_DECRYPT(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    std::string text = info[0].As<Napi::String>();

    std::string ciper = globalCipher.decryptString(text);
    return Napi::String::New(env, ciper);
}
}