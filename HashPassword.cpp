/*
 * Copyright (C) 2016 Team Win Recovery Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This computes the "secret" used by Android as one of the parameters
 * to decrypt File Based Encryption. The secret is prefixed with
 * "Android FBE credential hash" padded with 0s to 128 bytes then the
 * user's password is appended to the end of the 128 bytes. This string
 * is then hashed with sha512 and the sha512 value is then converted to
 * hex with upper-case characters.
 *
 * PersonalizedHashSP800 implements the NIST SP 800-108 KDF in counter
 * mode with HMAC-SHA256, matching the Java implementation in Android's
 * SyntheticPasswordCrypto.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <string>

#include <openssl/digest.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "HashPassword.h"

#define PASS_PADDING_SIZE 128

// Hashes prefix, padded with 0s to PASS_PADDING_SIZE bytes, followed by
// key, with SHA-512. Streams the three parts into the digest so that no
// assembled buffer needs to be allocated on the heap.
static bool PersonalizedHashDigest(const char* prefix, const char* key,
                                   const size_t key_size,
                                   uint8_t hash[SHA512_DIGEST_LENGTH]) {
	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
			EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if (!ctx) return false; // failed to allocate the digest context
	if (EVP_DigestInit_ex(ctx.get(), EVP_sha512(), nullptr) != 1)
		return false;

	const size_t prefix_size = strlen(prefix);
	if (prefix_size > 0 &&
			EVP_DigestUpdate(ctx.get(), prefix, prefix_size) != 1) {
		return false;
	}
	static const uint8_t padding[PASS_PADDING_SIZE] = {};
	if (prefix_size < PASS_PADDING_SIZE &&
			EVP_DigestUpdate(ctx.get(), padding,
					PASS_PADDING_SIZE - prefix_size) != 1) {
		return false;
	}
	if (key_size > 0 && EVP_DigestUpdate(ctx.get(), key, key_size) != 1)
		return false;

	unsigned int hash_size = 0;
	if (EVP_DigestFinal_ex(ctx.get(), hash, &hash_size) != 1 ||
			hash_size != SHA512_DIGEST_LENGTH) {
		return false;
	}
	return true;
}

// Appends value to out as a big-endian 32-bit integer, the wire format
// used by the SP 800-108 KDF input.
static void AppendUint32Be(std::string* out, const uint32_t value) {
	const uint8_t bytes[4] = {
			static_cast<uint8_t>(value >> 24),
			static_cast<uint8_t>(value >> 16),
			static_cast<uint8_t>(value >> 8),
			static_cast<uint8_t>(value),
	};
	out->append(reinterpret_cast<const char*>(bytes), sizeof(bytes));
}

static std::string BytesToHexString(const uint8_t* bytes, const size_t size,
                                    const bool uppercase) {
	static const char digits_lower[] = "0123456789abcdef";
	static const char digits_upper[] = "0123456789ABCDEF";
	const char* digits = uppercase ? digits_upper : digits_lower;
	std::string hex;
	hex.reserve(size * 2);
	for (size_t i = 0; i < size; i++) {
		hex.push_back(digits[bytes[i] >> 4]);
		hex.push_back(digits[bytes[i] & 0xF]);
	}
	return hex;
}

void* PersonalizedHashBinary(const char* prefix, const char* key, const size_t key_size) {
	uint8_t hash[SHA512_DIGEST_LENGTH];
	if (!PersonalizedHashDigest(prefix, key, key_size, hash))
		return NULL; // hashing failed
	void* ret = malloc(SHA512_DIGEST_LENGTH);
	if (!ret) return NULL; // failed to malloc
	memcpy(ret, hash, SHA512_DIGEST_LENGTH);
	return ret;
}

std::string PersonalizedHash(const char* prefix, const char* key, const size_t key_size) {
	uint8_t hash[SHA512_DIGEST_LENGTH];
	if (!PersonalizedHashDigest(prefix, key, key_size, hash))
		return ""; // hashing failed
	return BytesToHexString(hash, sizeof(hash), true);
}

std::string PersonalizedHash(const char* prefix, const std::string& Password) {
	return PersonalizedHash(prefix, Password.c_str(), Password.size());
}

std::string PersonalizedHashSP800(const char* label, const char* context, const char* key, const size_t key_size) {
	// Assembles the SP 800-108 counter mode input:
	// counter || label || 0 || context || bit length of context || 256
	std::string input;
	input.reserve(4 + strlen(label) + 1 + strlen(context) + 8);
	AppendUint32Be(&input, 1);
	input.append(label);
	input.push_back('\0'); // divider between the label and the context
	input.append(context);
	AppendUint32Be(&input, strlen(context) * 8);
	AppendUint32Be(&input, 256);

	uint8_t hash[SHA256_DIGEST_LENGTH];
	unsigned int hash_size = 0;
	if (!HMAC(EVP_sha256(), key, key_size,
			reinterpret_cast<const uint8_t*>(input.data()), input.size(),
			hash, &hash_size) ||
			hash_size != SHA256_DIGEST_LENGTH) {
		return ""; // HMAC failed
	}
	return BytesToHexString(hash, sizeof(hash), false);
}

std::string HashPassword(const std::string& Password) {
	const char* prefix = FBE_PERSONALIZATION;
	return PersonalizedHash(prefix, Password);
}
