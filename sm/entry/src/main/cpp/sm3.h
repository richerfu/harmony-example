#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <memory>
#include "napi.h"
#include "sm2.h"


namespace sm3 {
struct EVP_MD_CTXDeleter {
    void operator()(EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); }
};

// 计算 SM3 哈希值
std::vector<unsigned char> CalculateSM3(const std::string &input) {
    // 创建消息摘要上下文
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTXDeleter> mdctx(EVP_MD_CTX_new());
    if (!mdctx) {
        std::cerr << "Error creating EVP_MD_CTX" << std::endl;
        sm2::PrintOpenSSLError();
        return std::vector<unsigned char>();
    }

    // 获取 SM3 算法
    const EVP_MD *md = EVP_sm3();
    if (!md) {
        std::cerr << "Error getting SM3 algorithm" << std::endl;
        sm2::PrintOpenSSLError();
        return std::vector<unsigned char>();
    }

    // 初始化消息摘要上下文
    if (EVP_DigestInit_ex(mdctx.get(), md, nullptr) != 1) {
        std::cerr << "Error initializing digest" << std::endl;
        sm2::PrintOpenSSLError();
        return std::vector<unsigned char>();
    }

    // 更新消息摘要
    if (EVP_DigestUpdate(mdctx.get(), input.c_str(), input.length()) != 1) {
        std::cerr << "Error updating digest" << std::endl;
        sm2::PrintOpenSSLError();
        return std::vector<unsigned char>();
    }

    // 获取摘要结果
    std::vector<unsigned char> hash(EVP_MD_size(md));
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx.get(), hash.data(), &hash_len) != 1) {
        std::cerr << "Error finalizing digest" << std::endl;
        sm2::PrintOpenSSLError();
        return std::vector<unsigned char>();
    }

    hash.resize(hash_len);
    return hash;
}

// 将字节数组转换为十六进制字符串
std::string BytesToHexString(const std::vector<unsigned char> &bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// 将十六进制字符串转换为字节数组
std::vector<unsigned char> HexStringToBytes(const std::string &hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

Napi::Value SM3_ENCRYPT(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    std::string string1 = info[0].As<Napi::String>();

    std::vector<unsigned char> hash = CalculateSM3(string1);
    std::string hashHex = BytesToHexString(hash);

    return Napi::String::New(env, hashHex);
}
}