/*
 * Copyright (C) 2016 - 2020 The TeamWin Recovery Project
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

#include "Decrypt.h"
#include "FsCrypt.h"
#include <fscrypt/fscrypt.h>

#include <map>
#include <string>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <keyutils.h>
#include "cutils/properties.h"

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <dirent.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <fstream>
#include <future>
#include <algorithm>
#include <chrono>

#include <android/binder_manager.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <base/threading/platform_thread.h>
#include <android/hardware/confirmationui/1.0/types.h>
#include <aidl/android/hardware/gatekeeper/IGatekeeper.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/security/authorization/IKeystoreAuthorization.h>
#include <aidl/android/security/apc/BnConfirmationCallback.h>
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/keystore2/ResponseCode.h>
#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>

#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>
#include <hardware/hw_auth_token.h>

#include <gatekeeper/GateKeeperResponse.h>

#include <keystore/keystore.h>
#include <keystore/keystore_client.h>
#include <keystore/KeystoreResponse.h>
#include <keystore/keystore_hidl_support.h>
#include <keystore/keystore_return_types.h>
#include <keystore/keymaster_types.h>
#include <keymasterV4_1/Keymaster.h>
#include <keystore/OperationResult.h>
#include <keymint_support/authorization_set.h>
#include <keymasterV4_1/keymaster_utils.h>
#include <KeyMintUtils.h>

extern "C" {
#include "crypto_scrypt.h"
}

#include "fscrypt_policy.h"
#include "HashPassword.h"
#include "KeystoreInfo.hpp"
#include "KeyStorage.h"
#include "Weaver1.h"
#include "android/os/IVold.h"

namespace apc = ::aidl::android::security::apc;
namespace keymint = ::aidl::android::hardware::security::keymint;
namespace ks2 = ::aidl::android::system::keystore2;

using ::aidl::android::hardware::security::keymint::HardwareAuthenticatorType;
using ::aidl::android::hardware::security::keymint::HardwareAuthToken;
using ::aidl::android::hardware::security::keymint::km_utils::authToken2AidlVec;
using aidl::android::system::keystore2::IKeystoreService;
using android::hardware::gatekeeper::V1_0::GatekeeperStatusCode;
using AidlGatekeeperVerifyResp = aidl::android::hardware::gatekeeper::GatekeeperVerifyResponse;
using AidlIGatekeeper = aidl::android::hardware::gatekeeper::IGatekeeper;
using android::hardware::gatekeeper::V1_0::GatekeeperResponse;

static bool lookup_ref_key_internal(std::map<userid_t, UserPolicies> key_map, const uint8_t* policy,
                                    userid_t* user_id) {
#ifdef USE_FSCRYPT_POLICY_V1
    char policy_string_hex[FS_KEY_DESCRIPTOR_SIZE_HEX];
    char key_map_hex[FS_KEY_DESCRIPTOR_SIZE_HEX];
    bytes_to_hex(policy, FS_KEY_DESCRIPTOR_SIZE, policy_string_hex);
#else
    char policy_string_hex[FSCRYPT_KEY_IDENTIFIER_HEX_SIZE];
    char key_map_hex[FSCRYPT_KEY_IDENTIFIER_HEX_SIZE];
    bytes_to_hex(policy, FSCRYPT_KEY_IDENTIFIER_SIZE, policy_string_hex);
#endif

    for (auto& [userid, user_policies] : key_map) {
#ifdef USE_FSCRYPT_POLICY_V1
        bytes_to_hex(reinterpret_cast<const uint8_t*>(&user_policies.internal.key_raw_ref[0]),
                     FS_KEY_DESCRIPTOR_SIZE, key_map_hex);
#else
        bytes_to_hex(reinterpret_cast<const uint8_t*>(&user_policies.internal.key_raw_ref[0]),
                     FSCRYPT_KEY_IDENTIFIER_SIZE, key_map_hex);
#endif
        if (std::string(key_map_hex) == policy_string_hex) {
            *user_id = userid;
            return true;
        }
    }
    return false;
}

#ifdef USE_FSCRYPT_POLICY_V1
extern "C" bool lookup_ref_key(fscrypt_policy_v1* fep, uint8_t* policy_type) {
#else
extern "C" bool lookup_ref_key(fscrypt_policy_v2* fep, uint8_t* policy_type) {
#endif
    userid_t user_id = 0;
    std::string policy_type_string;

#ifdef USE_FSCRYPT_POLICY_V1
    char policy_hex[FS_KEY_DESCRIPTOR_SIZE_HEX];
    bytes_to_hex(fep->master_key_descriptor, FS_KEY_DESCRIPTOR_SIZE, policy_hex);
    if (std::strncmp((const char*)fep->master_key_descriptor, de_key_raw_ref.c_str(),
                     FS_KEY_DESCRIPTOR_SIZE) == 0) {
        policy_type_string = SYSTEM_DE_FSCRYPT_POLICY;
        memcpy(policy_type, policy_type_string.data(), policy_type_string.size());
        return true;
    }
    if (!lookup_ref_key_internal(s_de_policies, fep->master_key_descriptor, &user_id)) {
        if (!lookup_ref_key_internal(s_ce_policies, fep->master_key_descriptor, &user_id)) {
            return false;
        } else {
            policy_type_string = USER_CE_FSCRYPT_POLICY + std::to_string(user_id);
        }
    } else {
        policy_type_string = USER_DE_FSCRYPT_POLICY + std::to_string(user_id);
    }
#else
    char policy_hex[FSCRYPT_KEY_IDENTIFIER_HEX_SIZE];
    bytes_to_hex(fep->master_key_identifier, FSCRYPT_KEY_IDENTIFIER_SIZE, policy_hex);
    if (std::strncmp(reinterpret_cast<const char*>(fep->master_key_identifier), de_key_raw_ref.c_str(),
                     FSCRYPT_KEY_IDENTIFIER_SIZE) == 0) {
        policy_type_string = SYSTEM_DE_FSCRYPT_POLICY;
        memcpy(policy_type, policy_type_string.data(), policy_type_string.size());
        return true;
    }
    if (!lookup_ref_key_internal(s_de_policies, fep->master_key_identifier, &user_id)) {
        if (!lookup_ref_key_internal(s_ce_policies, fep->master_key_identifier, &user_id)) {
            return false;
        }
        policy_type_string = USER_CE_FSCRYPT_POLICY + std::to_string(user_id);
    } else {
        policy_type_string = USER_DE_FSCRYPT_POLICY + std::to_string(user_id);
    }
#endif

    memcpy(policy_type, policy_type_string.data(), policy_type_string.size());
    printf("storing policy type: %p\n", policy_type);
    return true;
}

extern "C" bool lookup_ref_tar(const uint8_t* policy_type, uint8_t* policy) {
    const auto policy_type_string = std::string((char*)policy_type);
#ifdef USE_FSCRYPT_POLICY_V1
    char policy_hex[FS_KEY_DESCRIPTOR_SIZE_HEX];
    bytes_to_hex(policy_type, FS_KEY_DESCRIPTOR_SIZE, policy_hex);
#else
    char policy_hex[FSCRYPT_KEY_IDENTIFIER_HEX_SIZE];
    bytes_to_hex(policy_type, FSCRYPT_KEY_IDENTIFIER_SIZE, policy_hex);
#endif

#ifdef USE_FSCRYPT_POLICY_V1
    if (policy_type_string.substr(0, 1) != FSCRYPT_V1) {
#else
    if (policy_type_string.substr(0, 1) != FSCRYPT_V2) {
#endif
        printf("Unexpected version: %d\n", policy_type[0]);
        return false;
    }

    if (policy_type_string.substr(1, 2) == SYSTEM_DE_KEY) {
        memcpy(policy, de_key_raw_ref.data(), de_key_raw_ref.size());
        return true;
    }

    std::string raw_ref;

    if (policy_type_string.substr(1, 1) == USER_DE_KEY) {
        if (const userid_t user_id = std::stoi(policy_type_string.substr(3, 4));
            lookup_key_ref(s_de_policies, user_id, &raw_ref)) {
            memcpy(policy, raw_ref.data(), raw_ref.size());
        } else
            return false;
    } else if (policy_type_string.substr(1, 1) == USER_CE_KEY) {
        if (const userid_t user_id = std::stoi(policy_type_string.substr(3, 4));
            lookup_key_ref(s_ce_policies, user_id, &raw_ref)) {
            memcpy(policy, raw_ref.data(), raw_ref.size());
        } else
            return false;
    } else {
        printf("unknown policy type: %p\n", policy_type);
        return false;
    }
    return true;
}

extern "C" bool Decrypt_DE() {
    printf("Attempting to initialize DE keys\n");
    // this deals with the overarching device encryption
    if (!fscrypt_initialize_systemwide_keys()) {
        printf("fscrypt_initialize_systemwide_keys returned fail\n");
        return false;
    }
    if (!fscrypt_init_user0()) {
        printf("fscrypt_init_user0 returned fail\n");
        return false;
    }
    return true;
}

// Crappy functions for debugging, please ignore unless you need to debug
// void output_hex(const std::string& in) {
// 	const char *buf = in.data();
// 	char hex[in.size() * 2 + 1];
// 	unsigned int index;
// 	for (index = 0; index < in.size(); index++)
// 		sprintf(&hex[2 * index], "%02X", buf[index]);
// }

// void output_hex(const char* buf, const int size) {
// 	char hex[size * 2 + 1];
// 	int index;
// 	for (index = 0; index < size; index++)
// 		sprintf(&hex[2 * index], "%02X", buf[index]);
// 	printf("%s", hex);
// }

// void output_hex(const unsigned char* buf, const int size) {
// 	char hex[size * 2 + 1];
// 	int index;
// 	for (index = 0; index < size; index++)
// 		sprintf(&hex[2 * index], "%02X", buf[index]);
// 	printf("%s", hex);
// }

// void output_hex(std::vector<uint8_t>* vec) {
// 	char hex[3];
// 	unsigned int index;
// 	for (index = 0; index < vec->size(); index++) {
// 		sprintf(&hex[0], "%02X", vec->at(index));
// 		printf("%s", hex);
// 	}
// }

/* Constants from SyntheticPasswordManager.java
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#146
 * and
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#169
 */
#define WEAVER_VERSION 1
#define STRETCHED_LSKF_LENGTH 32
/* Used when the LSKF is empty
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#144
 */
#define DEFAULT_PASSWORD "default-password"

/* This is the structure of the data in the password data (*.pwd) file, the Java
 * counterpart is the PasswordData class
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#359
 */
struct password_data_struct {
    int credential_type;
    unsigned char scrypt_log_n;
    unsigned char scrypt_log_r;
    unsigned char scrypt_log_p;
    int salt_len;
    void* salt;
    int handle_len;
    void* password_handle;
    /* Pin length field, only stored in version 2 of the password data and when
     * auto confirm is enabled, -1 (PIN_LENGTH_UNAVAILABLE) otherwise.  It is
     * not needed to decrypt, it is parsed for completeness only. */
    int pin_length;
};

/* Reads a big endian 32-bit integer from a serialized synthetic password state
 * file, mirroring the java.nio.ByteBuffer used by PasswordData.fromBytes and
 * loadWeaverSlot. */
static bool read_be_int(const std::string& data, size_t* offset, int* value) {
    if (data.size() < *offset + sizeof(int)) return false;
    const unsigned char* p = (const unsigned char*)data.data() + *offset;
    *value = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    *offset += sizeof(int);
    return true;
}

static bool Get_Spblob_Data(const std::string& spblob_path, const std::string& handle_str,
                     const std::string& suffix, const std::string& tag, std::string* data) {
    bool found_file = false;
    std::string file = spblob_path + handle_str + suffix;
    if (android::vold::pathExists(file)) {
        if (!android::base::ReadFileToString(file, data)) {
            printf("Failed to read '%s'\n", file.c_str());
        } else
            found_file = true;
    } else {
        // The Keystore alias uses the handle as-is, but the spblob files are
        // named after it zero-padded to 16 digits.
        printf("trying to read %s_file data with leading 0\n", tag.c_str());
        std::string padded = handle_str.size() < 16
                                     ? std::string(16 - handle_str.size(), '0') + handle_str
                                     : handle_str;
        file = spblob_path + padded + suffix;
        if (!android::base::ReadFileToString(file, data)) {
            printf("Failed to read '%s'\n", file.c_str());
        } else {
            found_file = true;
        }
    }
    return found_file;
}

/* C++ replacement for PasswordData.fromBytes
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#394
 * called here
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1398
 * Returning false means the file is missing or malformed; on failure anything
 * that was allocated is freed and the pointer fields are reset, so the caller
 * may still pass the struct to Free_Return(). */
static bool Get_Password_Data(const std::string& spblob_path, const std::string& handle_str,
                       password_data_struct* pwd) {
    std::string pwd_data;
    if (!Get_Spblob_Data(spblob_path, handle_str, ".pwd", "password", &pwd_data)) return false;
    // output_hex(pwd_data.data(), pwd_data.size());printf("\n");
    size_t offset = 0;
    int credential_type;
    if (!read_be_int(pwd_data, &offset, &credential_type)) {
        printf("Get_Password_Data: password data too short\n");
        return false;
    }
    /* fromBytes() truncates the credentialType int to a short.  All values fit
     * in a short anyway, and this also recovers from the temporary Android 14
     * beta format that stored a format version in the first two bytes.
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#411
     */
    pwd->credential_type = (int)(int16_t)(credential_type & 0xFFFF);
    // printf("credential type %i\n", pwd->credential_type); // 1 is pattern, 2 PIN or password
    // (legacy), 3 PIN, 4 password, -1 none
    if (pwd_data.size() < offset + 3) {
        printf("Get_Password_Data: password data too short\n");
        return false;
    }
    pwd->scrypt_log_n = (unsigned char)pwd_data[offset++];
    pwd->scrypt_log_r = (unsigned char)pwd_data[offset++];
    pwd->scrypt_log_p = (unsigned char)pwd_data[offset++];
    int salt_len;
    if (!read_be_int(pwd_data, &offset, &salt_len)) {
        printf("Get_Password_Data: password data too short\n");
        return false;
    }
    if (salt_len <= 0 || (int)pwd_data.size() < (int)offset + salt_len) {
        printf("Get_Password_Data invalid salt length %i\n", salt_len);
        return false;
    }
    pwd->salt_len = salt_len;
    pwd->salt = malloc(pwd->salt_len);
    if (!pwd->salt) {
        printf("Get_Password_Data malloc salt\n");
        pwd->salt_len = 0;
        return false;
    }
    memcpy(pwd->salt, pwd_data.data() + offset, pwd->salt_len);
    offset += pwd->salt_len;
    int handle_len;
    if (!read_be_int(pwd_data, &offset, &handle_len)) {
        printf("Get_Password_Data: password data too short\n");
        free(pwd->salt);
        pwd->salt = nullptr;
        pwd->salt_len = 0;
        return false;
    }
    if (handle_len > 0) {
        if ((int)pwd_data.size() < (int)offset + handle_len) {
            printf("Get_Password_Data handle overruns the file\n");
            free(pwd->salt);
            pwd->salt = nullptr;
            pwd->salt_len = 0;
            return false;
        }
        pwd->handle_len = handle_len;
        pwd->password_handle = malloc(pwd->handle_len);
        if (!pwd->password_handle) {
            printf("Get_Password_Data malloc password_handle\n");
            pwd->handle_len = 0;
            free(pwd->salt);
            pwd->salt = nullptr;
            pwd->salt_len = 0;
            return false;
        }
        memcpy(pwd->password_handle, pwd_data.data() + offset, pwd->handle_len);
    } else {
        // Not an error: the handle only exists when Weaver is not used
        // https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1437
        printf("Get_Password_Data handle_len is 0\n");
        pwd->handle_len = 0;
        pwd->password_handle = nullptr;
    }
    // Optional trailing pin length, absent on old protectors
    if (pwd_data.size() - offset >= sizeof(int)) {
        read_be_int(pwd_data, &offset, &pwd->pin_length);
    } else {
        pwd->pin_length = -1;  // LockPatternUtils.PIN_LENGTH_UNAVAILABLE
    }
    return true;
}

/* C++ replacement for stretchLskf
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1955
 * called here
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1413
 * pwd may be nullptr when the protector has no password data file, which means
 * the LSKF is empty; in that case the credential is zero-padded to
 * STRETCHED_LSKF_LENGTH instead of being run through scrypt.  Old protectors
 * always stored password data, so they scrypt the default password too. */
static bool Stretch_Lskf(const password_data_struct* pwd, const std::string& password,
                         unsigned char* stretched_lskf) {
    if (!stretched_lskf) {
        printf("stretched_lskf is null\n");
        return false;
    }
    // The default password is used when the LSKF is empty
    const std::string credential = password == "!" ? std::string(DEFAULT_PASSWORD) : password;
    if (!pwd) {
        // Arrays.copyOf(password, STRETCHED_LSKF_LENGTH)
        memset(stretched_lskf, 0, STRETCHED_LSKF_LENGTH);
        memcpy(stretched_lskf, credential.data(),
               std::min(credential.size(), static_cast<size_t>(STRETCHED_LSKF_LENGTH)));
        return true;
    }
    const uint64_t N = 1 << pwd->scrypt_log_n;
    const uint32_t r = 1 << pwd->scrypt_log_r;
    const uint32_t p = 1 << pwd->scrypt_log_p;
    // printf("N %i r %i p %i\n", N, r, p);
    const int ret = crypto_scrypt(reinterpret_cast<const uint8_t*>(credential.data()), credential.size(),
                            static_cast<const uint8_t*>(pwd->salt), pwd->salt_len, N, r, p,
                            stretched_lskf, STRETCHED_LSKF_LENGTH);
    if (ret != 0) {
        printf("scrypt error\n");
        return false;
    }
    return true;
}

// Data structure for the *.weaver file (WEAVER_SLOT_NAME), see Get_Weaver_Data below
struct weaver_data_struct {
    unsigned char version;
    int slot;
};

/* C++ replacement for loadWeaverSlot
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#904
 * called here
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1417
 */
static bool Get_Weaver_Data(const std::string& spblob_path, const std::string& handle_str,
                            weaver_data_struct* wd) {
    printf("Get_Weaver_Data\n");
    std::string weaver_data;
    if (!Get_Spblob_Data(spblob_path, handle_str, ".weaver", "weaver", &weaver_data)) {
        printf("Get_Weaver_Data: No weaver file found for %s\n", handle_str.c_str());
        return false;
    }
    // The file holds one version byte followed by the slot number as a big
    // endian int
    if (weaver_data.size() != sizeof(unsigned char) + sizeof(int)) {
        printf("Get_Weaver_Data: unexpected file size %zu\n", weaver_data.size());
        return false;
    }
    size_t offset = 0;
    wd->version = static_cast<unsigned char>(weaver_data[offset++]);
    if (wd->version != WEAVER_VERSION) {
        printf("Get_Weaver_Data: invalid weaver slot version %i\n", wd->version);
        return false;
    }
    read_be_int(weaver_data, &offset, &wd->slot);
    // printf("weaver slot %i\n", wd->slot);
    return true;
}

namespace android {

namespace keystore {

#define SYNTHETIC_PASSWORD_VERSION_V1 1
#define SYNTHETIC_PASSWORD_VERSION_V2 2
#define SYNTHETIC_PASSWORD_VERSION_V3 3
/* Renamed from SYNTHETIC_PASSWORD_PASSWORD_BASED, same value
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#156
 */
#define PROTECTOR_TYPE_LSKF_BASED 0

static ks2::KeyDescriptor keyDescriptor(const std::string& alias) {
    return {
            .domain = ks2::Domain::SELINUX,
            .nspace = NAMESPACE_LOCKSETTINGS,
            .alias = alias,
            .blob = {},
    };
}

static int unwrapError(const ndk::ScopedAStatus& status) {
    if (status.isOk()) return 0;
    if (status.getExceptionCode() == EX_SERVICE_SPECIFIC) {
        return status.getServiceSpecificError();
    }
    return static_cast<int>(ks2::ResponseCode::SYSTEM_ERROR);
}

static bool waitForServiceState(const char* service, const char* state) {
    char current[PROPERTY_VALUE_MAX] = {};
    std::string prop = std::string("init.svc.") + service;
    for (int i = 0; i < 100; i++) {
        property_get(prop.c_str(), current, "");
        if (!strcmp(current, state)) return true;
        usleep(100000);
    }
    printf("'%s' did not reach state '%s'\n", service, state);
    return false;
}

/* AServiceManager_waitForService() waits forever, which hangs the decrypt
 * UI when a declared service never registers. */
static ::ndk::SpAIBinder waitForService(const char* name) {
    for (int i = 0; i < 300; i++) {
        ::ndk::SpAIBinder binder(AServiceManager_checkService(name));
        if (binder.get() != nullptr) return binder;
        usleep(100000);
    }
    printf("timed out waiting for '%s'\n", name);
    return {};
}

/* keystore2 runs with its database on tmpfs so that nothing done here can
 * reach the real one. It still has to see the installed system's keys, so
 * seed it from /data before the first keystore2 call. */
bool syncKeystoreDb() {
    static bool synced = false;
    if (synced) return true;

    const std::string src = "/data/misc/keystore/persistent.sqlite";
    const std::string dst = "/tmp/misc/keystore/persistent.sqlite";
    if (!android::vold::pathExists(src)) {
        printf("no keystore database at '%s'\n", src.c_str());
        return false;
    }

    // keystore2 holds the destination open, so stop it for a clean copy.
    printf("stopping keystore2 to sync '%s'\n", src.c_str());
    property_set("ctl.stop", "keystore2");
    if (!waitForServiceState("keystore2", "stopped")) return false;

    unlink("/tmp/misc/keystore/persistent.sqlite-wal");
    unlink("/tmp/misc/keystore/persistent.sqlite-shm");
    unlink(dst.c_str());

    KeystoreInfo keystore_info;
    bool copied = keystore_info.backupDatabase(src, dst);
    if (copied) chmod(dst.c_str(), 0600);

    property_set("ctl.start", "keystore2");
    if (!waitForServiceState("keystore2", "running")) return false;
    for (int i = 0; i < 100; i++) {
        if (AServiceManager_checkService("android.system.keystore2.IKeystoreService/default") !=
            nullptr) {
            synced = copied;
            return copied;
        }
        usleep(100000);
    }
    printf("keystore2 did not register after restart\n");
    return false;
}

/* C++ replacement for function of the same name
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1635
 * returning an empty string indicates an error.  Only v2 and v3 blobs are
 * supported here: v1 blobs predate keystore2, their protector keys live in
 * the old uid-based keystore and use the reversed layering of
 * SyntheticPasswordCrypto.decryptBlobV1
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordCrypto.java#133
 */
static std::string unwrapSyntheticPasswordBlob(const std::string& spblob_path,
                                               const std::string& handle_str,
                                               const userid_t user_id, const void* protector_secret,
                                               const size_t protector_secret_size) {
    printf("Attempting to unwrap synthetic password blob\n");
    std::string disk_decryption_secret_key;

    android::ProcessState::self()->startThreadPool();

    // Read the data from the .spblob file per:
    // https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1637
    std::string spblob_data;
    if (!Get_Spblob_Data(spblob_path, handle_str, ".spblob", "spblob", &spblob_data))
        return disk_decryption_secret_key;
    if (spblob_data.size() < 2 + 12 + 16) {
        // 2 bytes of header, 12 for the IV, 16 for the GCM tag
        printf("spblob data too short: %zu bytes\n", spblob_data.size());
        return disk_decryption_secret_key;
    }
    auto* byteptr = reinterpret_cast<unsigned char*>(spblob_data.data());
    if (*byteptr != SYNTHETIC_PASSWORD_VERSION_V2 && *byteptr != SYNTHETIC_PASSWORD_VERSION_V1 &&
        *byteptr != SYNTHETIC_PASSWORD_VERSION_V3) {
        printf("Unsupported synthetic password version %i\n", *byteptr);
        return disk_decryption_secret_key;
    }
    const unsigned char* synthetic_password_version = byteptr;
    byteptr++;
    if (*byteptr != PROTECTOR_TYPE_LSKF_BASED) {
        printf("spblob data is not protected by an LSKF-based protector\n");
        return disk_decryption_secret_key;
    }
    byteptr++;  // Now we're pointing to the blob data itself
    if (*synthetic_password_version == SYNTHETIC_PASSWORD_VERSION_V1) {
        printf("spblob v1 (Android 8.0 era) is not supported\n");
        return disk_decryption_secret_key;
    }
    printf("spblob v2 / v3\n");
    /* Version 2 / 3 of the spblob is basically the same as version 1, but the order of getting the
     * intermediate key and disk decryption key have been flip-flopped as seen in
     * https://android.googlesource.com/platform/frameworks/base/+/5025791ac6d1538224e19189397de8d71dcb1a12
     */
    /* First decrypt call found in SyntheticPasswordCrypto.decryptBlob, which
     * decrypts the outer Keystore/KeyMint layer first
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordCrypto.java#168
     * We drive it through keystore2 directly, mirroring the parameters that
     * the Java cipher stack builds in
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/keystore/java/android/security/keystore2/AndroidKeyStoreCipherSpiBase.java
     * and
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/keystore/java/android/security/keystore2/AndroidKeyStoreAuthenticatedAESCipherSpi.java
     * The nonce and the MAC length are set as seen in two places:
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/keystore/java/android/security/keystore2/AndroidKeyStoreAuthenticatedAESCipherSpi.java#223
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/keystore/java/android/security/keystore2/AndroidKeyStoreAuthenticatedAESCipherSpi.java#319
     */
    // When the protector does not use Weaver, the key is created with
    // setUserAuthenticationRequired bound to the SID from the Gatekeeper
    // enrollment (SyntheticPasswordCrypto.java#212), so a Gatekeeper auth
    // token must be supplied to keystore2 prior to the begin operation.
    size_t maclen = 128;
    ::keystore::hidl_vec<uint8_t> iv_hidlvec;
    iv_hidlvec.setToExternal(byteptr, 12);  // The IV is the first 12 bytes of the spblob

    KeystoreInfo keystore_info;
    std::string handle = keystore_info.getHandle(user_id);
    std::string keystore_alias = keystore_info.getAlias(handle);
    unsigned char* cipher_text = byteptr + 12;  // The cipher text comes immediately after the IV
    ::keystore::hidl_vec<uint8_t> cipher_text_hidlvec;

    cipher_text_hidlvec.setToExternal(
            cipher_text,
            spblob_data.size() - 14 /* 1 each for version and protector type and 12 for the iv */);
    auto begin_params = keymint::AuthorizationSetBuilder()
                                .Authorization(keymint::TAG_ALGORITHM, ::keymint::Algorithm::AES)
                                .Authorization(::keymint::TAG_BLOCK_MODE, ::keymint::BlockMode::GCM)
                                .Padding(::keymint::PaddingMode::NONE)
                                .Authorization(keymint::TAG_PURPOSE, keymint::KeyPurpose::DECRYPT)
                                .Authorization(::keymint::TAG_NONCE, iv_hidlvec)
                                .Authorization(::keymint::TAG_MAC_LENGTH, maclen);

    ks2::KeyEntryResponse keyEntryResponse;
    ::ndk::SpAIBinder keystoreBinder(
            AServiceManager_checkService("android.system.keystore2.IKeystoreService/default"));
    auto keystore = ks2::IKeystoreService::fromBinder(keystoreBinder);
    if (auto rc = keystore->getKeyEntry(keyDescriptor(keystore_alias), &keyEntryResponse);
        !rc.isOk()) {
        if (auto error = unwrapError(rc);
            static_cast<ks2::ResponseCode>(error) == ks2::ResponseCode::KEY_NOT_FOUND) {
            printf("key not found\n");
        } else {
            printf("Failed to get key entry: %s\n", rc.getDescription().c_str());
        }
        return disk_decryption_secret_key;
    }
    ks2::CreateOperationResponse encOperationResponse;
    auto begin_rc = keyEntryResponse.iSecurityLevel->createOperation(
            keyEntryResponse.metadata.key, begin_params.vector_data(), true, &encOperationResponse);
    if (!begin_rc.isOk()) {
        printf("Begin Operation failed\n");
        return disk_decryption_secret_key;
    }
    if (encOperationResponse.upgradedBlob) {
        /* KeyMint rebound the synthetic password key because our OS
         * version or patch levels do not match the installed system.
         * The upgrade only lives in the tmpfs Keystore database, so the
         * blob on /data stays usable, but keystore2 has marked the old
         * one superseded and its garbage collector deletes superseded
         * blobs from KeyMint itself. That collector is gated on
         * sys.boot_completed, so it stays idle here unless something
         * sets that property. */
        printf("WARNING: KeyMint upgraded the synthetic password key\n");
        printf("WARNING: the recovery environment does not match the installed system\n");
        char boot_completed[PROPERTY_VALUE_MAX] = {};
        property_get("sys.boot_completed", boot_completed, "");
        if (!strcmp(boot_completed, "1")) {
            printf("ERROR: sys.boot_completed is set, so keystore2 will garbage\n");
            printf("ERROR: collect the original key blob. Do not set that property\n");
            printf("ERROR: in recovery.\n");
        }
    }
    std::optional<std::vector<uint8_t>> optPlaintext;

    begin_rc = encOperationResponse.iOperation->finish(cipher_text_hidlvec, {}, &optPlaintext);
    if (!begin_rc.isOk()) {
        printf("finish response failed\n");
        return disk_decryption_secret_key;
    }
    // The intermediate blob holds an IV plus at least the GCM tag
    if (!optPlaintext || optPlaintext->size() < 12 + 16) {
        printf("keystore2 returned invalid plaintext\n");
        return disk_decryption_secret_key;
    }

    auto keystore_result_size = optPlaintext->size();
    auto* keystore_result = static_cast<unsigned char*>(malloc(keystore_result_size));
    if (!keystore_result) {
        printf("malloc on keystore_result\n");
        return disk_decryption_secret_key;
    }
    memcpy(keystore_result, &optPlaintext->front(), keystore_result_size);

    const unsigned char* intermediate_iv = keystore_result;
    // printf("intermediate_iv: "); output_hex((const unsigned char*)intermediate_iv, 12);
    // printf("\n");
    const unsigned char* intermediate_cipher_text =
            static_cast<const unsigned char*>(keystore_result) +
            12;  // The cipher text comes immediately after the IV
    auto cipher_size = keystore_result_size - 12;
    /* Second decrypt call, the inner software layer
     * SyntheticPasswordCrypto.decrypt(byte[] keyBytes, byte[] personalization, byte[] ciphertext)
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordCrypto.java#115
     * First the protector secret is personalized with "application-id"
     * (PROTECTOR_SECRET_PERSONALIZATION) and the first 32 bytes of the hash
     * are used as the AES-256-GCM key */
    void* personalized_application_id = PersonalizedHashBinary(
            PERSONALISATION_APPLICATION_ID, (const char*)protector_secret, protector_secret_size);
    if (!personalized_application_id) {
        printf("Unable to obtain personalized_application_id\n");
        free(keystore_result);
        return disk_decryption_secret_key;
    }
    // printf("personalized protector secret: "); output_hex((unsigned
    // char*)personalized_application_id, SHA512_DIGEST_LENGTH); printf("\n"); Now we'll decrypt
    // using openssl AES/GCM/NoPadding
    OpenSSL_add_all_ciphers();
    int actual_size = 0, final_size = 0;
    EVP_CIPHER_CTX* d_ctx = EVP_CIPHER_CTX_new();
    const auto* key =
            (const unsigned char*)personalized_application_id;  // The key is the now personalized
                                                                // copy of the protector secret
    EVP_DecryptInit(d_ctx, EVP_aes_256_gcm(), key, intermediate_iv);
    auto cipher_size_no_tag = cipher_size - 16;  // The GCM tag trails the cipher text
    auto* secret_key = (unsigned char*)malloc(cipher_size_no_tag);
    if (!secret_key) {
        printf("malloc failure on secret key\n");
        EVP_CIPHER_CTX_free(d_ctx);
        free(personalized_application_id);
        free(keystore_result);
        return disk_decryption_secret_key;
    }
    EVP_DecryptUpdate(d_ctx, secret_key, &actual_size, intermediate_cipher_text,
                      cipher_size_no_tag);
    // The tag is the last 16 bytes of the intermediate blob
    EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16,
                        (void*)(intermediate_cipher_text + cipher_size_no_tag));
    if (EVP_DecryptFinal_ex(d_ctx, secret_key + actual_size, &final_size) <= 0) {
        printf("Failed to decrypt the SP secret (GCM tag mismatch)\n");
        EVP_CIPHER_CTX_free(d_ctx);
        free(personalized_application_id);
        free(keystore_result);
        free(secret_key);
        return disk_decryption_secret_key;
    }
    EVP_CIPHER_CTX_free(d_ctx);
    free(personalized_application_id);
    free(keystore_result);
    int secret_key_real_size = actual_size + final_size;
    // printf("secret key:  "); output_hex((const unsigned char*)secret_key, secret_key_real_size);
    // printf("\n");
    /* The synthetic password is turned into the disk decryption key by
     * deriveFileBasedEncryptionKey
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#256
     * which goes through deriveSubkey
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#238
     * We now have the disk decryption key! */
    if (*synthetic_password_version == SYNTHETIC_PASSWORD_VERSION_V3) {
        // V3 uses SP800 instead of SHA512
        disk_decryption_secret_key =
                PersonalizedHashSP800(PERSONALIZATION_FBE_KEY, PERSONALISATION_CONTEXT,
                                      (const char*)secret_key, secret_key_real_size);
    } else {
        disk_decryption_secret_key = PersonalizedHash(
                PERSONALIZATION_FBE_KEY, (const char*)secret_key, secret_key_real_size);
    }
    // printf("disk_decryption_secret_key: '%s'\n", disk_decryption_secret_key.c_str());
    free(secret_key);
    return disk_decryption_secret_key;
}
}  // namespace keystore
// /* C++ replacement for loadSecdiscardable
//  * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1823
//  * called here
//  * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1489 */
static bool Get_Secdis(const std::string& spblob_path, const std::string& handle_str,
                       std::string& secdis_data) {
    return Get_Spblob_Data(spblob_path, handle_str, ".secdis", "secdis", &secdis_data);
    // output_hex(secdis_data.data(), secdis_data.size());printf("\n");
}

// // C++ replacement for fakeUserId
// //
// https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1933
static userid_t fakeUid(const userid_t uid) {
    return 100000 + uid;
}

/* C++ replacement for the Gatekeeper verification half of
 * unlockLskfBasedProtector
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1444
 * The protector key in keystore2 is created with setUserAuthenticationRequired
 * bound to the SID of this enrollment when Weaver is not used
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordCrypto.java#212
 * so besides checking the LSKF this must hand the resulting HardwareAuthToken
 * to keystore2, otherwise the begin operation on the spblob key fails with
 * KEY_USER_NOT_AUTHORIZED. */
static bool Gatekeeper_Verify(const userid_t user_id, const void* password_handle,
                              const size_t handle_len, const unsigned char* stretched_lskf) {
    std::shared_ptr<AidlIGatekeeper> aidl_gk_device;
    // HIDL gatekeeper service.
    android::sp<android::hardware::gatekeeper::V1_0::IGatekeeper> gk_device;
    constexpr const char gatekeeperServiceName[] =
            "android.hardware.gatekeeper.IGatekeeper/default";
    if (AServiceManager_isDeclared(gatekeeperServiceName)) {
        aidl_gk_device =
                AidlIGatekeeper::fromBinder(keystore::waitForService(gatekeeperServiceName));
    }
    if (!aidl_gk_device) {
        gk_device = ::android::hardware::gatekeeper::V1_0::IGatekeeper::getService();
    }
    if (!aidl_gk_device && !gk_device) {
        printf("failed to get gatekeeper service\n");
        return false;
    }

    // stretchedLskfToGkPassword:
    // https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1965
    void* gk_pwd_token = PersonalizedHashBinary(PERSONALIZATION_USER_GK_AUTH,
                                                (const char*)stretched_lskf, STRETCHED_LSKF_LENGTH);
    if (!gk_pwd_token) {
        printf("malloc error getting gatekeeper password\n");
        return false;
    }
    android::hardware::hidl_vec<uint8_t> pwd_handle_hidl;
    pwd_handle_hidl.setToExternal(
            const_cast<uint8_t*>(static_cast<const uint8_t*>(password_handle)), handle_len);
    android::hardware::hidl_vec<uint8_t> gk_pwd_token_hidl;
    gk_pwd_token_hidl.setToExternal(static_cast<uint8_t*>(gk_pwd_token), STRETCHED_LSKF_LENGTH);

    // Serialized HardwareAuthToken (hw_auth_token_t) bytes
    std::vector<uint8_t> auth_token;
    if (aidl_gk_device) {
        AidlGatekeeperVerifyResp rsp;
        const auto result = aidl_gk_device->verify(fakeUid(user_id), 0 /* challenge */, pwd_handle_hidl,
                                             gk_pwd_token_hidl, &rsp);
        free(gk_pwd_token);
        if (!result.isOk()) {
            printf("gatekeeper verification failed\n");
            return false;
        }
        if (rsp.statusCode >= AidlIGatekeeper::STATUS_OK) {
            printf("GateKeeper status ok\n");
            auth_token = authToken2AidlVec(rsp.hardwareAuthToken);
        } else if (rsp.statusCode == AidlIGatekeeper::ERROR_RETRY_TIMEOUT) {
            printf("GateKeeper response timeout\n");
            return false;
        } else {
            printf("GateKeeper verification failed\n");
            return false;
        }
    } else {
        bool verified = false;
        const auto hwRet = gk_device->verify(
                fakeUid(user_id), 0 /* challenge */, pwd_handle_hidl, gk_pwd_token_hidl,
                [&verified, &auth_token](const GatekeeperResponse& rsp) {
                    printf("Gatekeeper status -> %d\n", rsp.code);
                    if (rsp.code >= GatekeeperStatusCode::STATUS_OK) {
                        printf("GateKeeper status ok\n");
                        auth_token.assign(rsp.data.begin(), rsp.data.end());
                        verified = true;
                    } else if (rsp.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT) {
                        printf("GateKeeper response timeout\n");
                    } else {
                        printf("GateKeeper response error\n");
                    }
                });
        free(gk_pwd_token);
        if (!hwRet.isOk() || !verified) {
            printf("gatekeeper verification failed\n");
            return false;
        }
    }

    if (auth_token.empty()) {
        // Nothing to hand to keystore2; the begin operation will fail if the
        // protector key really is auth-bound.
        printf("GateKeeper returned no auth token\n");
        return true;
    }
    if (auth_token.size() < sizeof(hw_auth_token_t)) {
        printf("GateKeeper returned a truncated auth token\n");
        return false;
    }
    const hw_auth_token_t* hwAuthToken =
            reinterpret_cast<const hw_auth_token_t*>(auth_token.data());
    HardwareAuthToken authToken;
    authToken.timestamp.milliSeconds = betoh64(hwAuthToken->timestamp);
    authToken.challenge = hwAuthToken->challenge;
    authToken.userId = hwAuthToken->user_id;
    authToken.authenticatorId = hwAuthToken->authenticator_id;
    authToken.authenticatorType =
            static_cast<HardwareAuthenticatorType>(betoh32(hwAuthToken->authenticator_type));
    authToken.mac.assign(&hwAuthToken->hmac[0], &hwAuthToken->hmac[32]);
    // Bounded wait, like everywhere else: a hanging wait would freeze the
    // decrypt UI if the service never registers.
    ::ndk::SpAIBinder binder(keystore::waitForService("android.security.authorization"));
    auto service =
            aidl::android::security::authorization::IKeystoreAuthorization::fromBinder(binder);
    if (!service) {
        printf("error: could not connect to keystore service\n");
        ALOGE("error: could not connect to keystore service\n");
        return false;
    }
    auto binder_result = service->addAuthToken(authToken);
    if (!binder_result.isOk()) {
        printf("error: addAuthToken failed: %s\n", binder_result.getDescription().c_str());
        return false;
    }
    return true;
}

bool Free_Return(bool retval, void* weaver_key, password_data_struct* pwd) {
    printf("Free_Return\n");
    if (weaver_key) free(weaver_key);
    if (pwd->salt) free(pwd->salt);
    if (pwd->password_handle) free(pwd->password_handle);
    return retval;
}

bool Decrypt_CE_storage(const userid_t user_id, const std::string& secret) {
    printf("Attempting to unlock user storage\n");
    int flags = android::os::IVold::STORAGE_FLAG_CE;
    if (!fscrypt_unlock_ce_storage(user_id, secret)) {
        printf("fscrypt_unlock_ce_storage returned fail\n");
        return false;
    }
    printf("Attempting to prepare user storage\n");
    if (!fscrypt_prepare_user_storage("", user_id, flags)) {
        printf("failed to fscrypt_prepare_user_storage\n");
        return false;
    }
    printf("User %i Decrypted Successfully!\n", user_id);
    return true;
}

/* Decrypt_User_Synth_Pass is the TWRP C++ equivalent to doVerifyCredential
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/LockSettingsService.java#2399
 * which drives unlockLskfBasedProtector
 * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1382
 */
bool Decrypt_User_Synth_Pass(const userid_t user_id, const std::string& Password) {
    printf("Attempting to unlock the user's LSKF-based SP protector\n");
    bool retval = false;
    void* weaver_key = nullptr;
    password_data_struct pwd{};
    pwd.salt = nullptr;
    pwd.salt_len = 0;
    pwd.password_handle = nullptr;
    pwd.handle_len = 0;
    // this will be the disk decryption key that is sent to vold
    std::string secret;
    char spblob_path_char[PATH_MAX];
    sprintf(spblob_path_char, "/data/system_de/%d/spblob/", user_id);
    std::string spblob_path = spblob_path_char;
    /* Get the protector ID: it is stored as the "sp-handle" lock setting
     * (LockPatternUtils.CURRENT_LSKF_BASED_PROTECTOR_ID_KEY), read by
     * getCurrentLskfBasedProtectorId
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/LockSettingsService.java#3010
     * KeystoreInfo::getHandle() reads it from locksettings.db. */
    KeystoreInfo keystore_info;
    std::string handle_str = keystore_info.getHandle(user_id);
    // The synthetic password key is looked up by alias, so keystore2 needs the
    // installed system's database before any of the calls below.
    if (!android::keystore::syncKeystoreDb()) {
        printf("Failed to sync the keystore database\n");
        return Free_Return(retval, weaver_key, &pwd);
    }
    /* Load the password data.  If the file doesn't exist, then the LSKF is
     * empty (CREDENTIAL_TYPE_NONE) and the scrypt and Gatekeeper steps are
     * skipped; old protectors stored the file even for an empty LSKF.
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1398
     */
    const bool empty_lskf = Password == "!";
    bool have_pwd = Get_Password_Data(spblob_path, handle_str, &pwd);
    if (!have_pwd && !empty_lskf) {
        // checkAgainstStoredType: a password can never match an empty LSKF
        // https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1405
        printf("No password data but a password was supplied\n");
        return Free_Return(retval, weaver_key, &pwd);
    }
    // The stretched LSKF replaces what older releases called the password token
    // https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1413
    unsigned char stretched_lskf[STRETCHED_LSKF_LENGTH];
    if (!Stretch_Lskf(have_pwd ? &pwd : nullptr, Password, &stretched_lskf[0])) {
        printf("Failed to stretch the LSKF\n");
        return Free_Return(retval, weaver_key, &pwd);
    }
    // output_hex(&stretched_lskf[0], STRETCHED_LSKF_LENGTH);printf("\n");
    // The protector secret is the stretched LSKF with either the hashed weaver
    // payload or the hashed secdiscardable appended (32 + 64 bytes)
    char protector_secret[STRETCHED_LSKF_LENGTH + SHA512_DIGEST_LENGTH];
    weaver_data_struct wd{};
    if (Get_Weaver_Data(spblob_path, handle_str, &wd)) {
        printf("using weaver\n");
        /* The protector uses Weaver to verify the LSKF:
         * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1418
         * The weaver key is the stretched LSKF personalized with "weaver-key"
         * then truncated to the weaver key size (done inside WeaverVerify),
         * stretchedLskfToWeaverKey
         * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1970
         */
        weaver_key = PersonalizedHashBinary(PERSONALISATION_WEAVER_KEY,
                                            (const char*)&stretched_lskf[0], STRETCHED_LSKF_LENGTH);
        if (!weaver_key) {
            printf("malloc error getting weaver_key\n");
            return Free_Return(retval, weaver_key, &pwd);
        }
        // Now we start driving weaverVerify:
        // https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1427
        android::vold::Weaver weaver;
        if (!weaver) {
            printf("Failed to get weaver service\n");
            return Free_Return(retval, weaver_key, &pwd);
        }
        // Get the key size from the weaver service
        uint32_t weaver_key_size = 0;
        if (!weaver.GetKeySize(&weaver_key_size)) {
            printf("Failed to get weaver key size\n");
            return Free_Return(retval, weaver_key, &pwd);
        } else {
            printf("weaver key size is %u\n", weaver_key_size);
        }
        // printf("weaver key: "); output_hex((unsigned char*)weaver_key, weaver_key_size);
        // printf("\n"); Send the slot from the .weaver file, the computed weaver key, and get the
        // escrowed key data
        std::vector<uint8_t> weaver_payload;
        // TODO: we should return more information about the status including time delays before the
        // next retry
        if (!weaver.WeaverVerify(wd.slot, weaver_key, &weaver_payload)) {
            printf("failed to weaver verify\n");
            return Free_Return(retval, weaver_key, &pwd);
        }
        // printf("weaver payload: "); output_hex(&weaver_payload); printf("\n");
        // Done with weaverVerify
        /* Now compute the protector secret via transformUnderWeaverSecret:
         * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1432
         * The escrowed weaver key data is prefixed with "weaver-pwd" padded to
         * 128 with nulls with the weaver payload appended then SHA512, and the
         * result is appended to the stretched LSKF */
        void* weaver_secret =
                PersonalizedHashBinary(PERSONALISATION_WEAVER_PASSWORD,
                                       (const char*)weaver_payload.data(), weaver_payload.size());
        if (!weaver_secret) {
            printf("malloc error getting weaver_secret\n");
            return Free_Return(retval, weaver_key, &pwd);
        }
        memcpy(&protector_secret[0], &stretched_lskf[0], STRETCHED_LSKF_LENGTH);
        memcpy(&protector_secret[STRETCHED_LSKF_LENGTH], weaver_secret, SHA512_DIGEST_LENGTH);
        free(weaver_secret);
        // printf("protector secret: "); output_hex((unsigned char*)protector_secret,
        // STRETCHED_LSKF_LENGTH + SHA512_DIGEST_LENGTH); printf("\n");
    } else {
        printf("using secdis to decrypt spblob\n");
        /* Weaver is not used, so the protector uses Gatekeeper to verify the
         * LSKF unless the LSKF is empty
         * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1437
         */
        if (have_pwd && pwd.handle_len > 0) {
            if (!Gatekeeper_Verify(user_id, pwd.password_handle, pwd.handle_len,
                                   &stretched_lskf[0])) {
                return Free_Return(retval, weaver_key, &pwd);
            }
        } else if (!empty_lskf) {
            printf("Missing Gatekeeper password handle for nonempty LSKF\n");
            return Free_Return(retval, weaver_key, &pwd);
        }
        /* Now load the secdiscardable and compute the protector secret via
         * transformUnderSecdiscardable:
         * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1495
         * The secdiscardable file is prefixed with "secdiscardable-transform"
         * padded to 128 with nulls with the file data appended then SHA512,
         * and the result is appended to the stretched LSKF */
        std::string secdis_data;
        if (!Get_Secdis(spblob_path, handle_str, secdis_data)) {
            printf("Failed to get secdis data\n");
            return Free_Return(retval, weaver_key, &pwd);
        }
        void* secdiscardable = PersonalizedHashBinary(
                PERSONALISATION_SECDISCARDABLE, (char*)secdis_data.data(), secdis_data.size());
        if (!secdiscardable) {
            printf("malloc error getting secdiscardable\n");
            return Free_Return(retval, weaver_key, &pwd);
        }
        memcpy((void*)&protector_secret[0], (void*)&stretched_lskf[0], STRETCHED_LSKF_LENGTH);
        memcpy((void*)&protector_secret[STRETCHED_LSKF_LENGTH], secdiscardable,
               SHA512_DIGEST_LENGTH);
        free(secdiscardable);
    }
    /* Now we unwrap the spblob with the protector secret:
     * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1506
     * The last bit that computes the disk decrypt key
     * (deriveFileBasedEncryptionKey) is done inside the call. */
    secret = android::keystore::unwrapSyntheticPasswordBlob(
            spblob_path, handle_str, user_id, (const void*)&protector_secret[0],
            STRETCHED_LSKF_LENGTH + SHA512_DIGEST_LENGTH);
    if (!secret.size()) {
        printf("failed to unwrapSyntheticPasswordBlob\n");
        return Free_Return(retval, weaver_key, &pwd);
    }

    if (!Decrypt_CE_storage(user_id, secret)) {
        return Free_Return(retval, weaver_key, &pwd);
    }

    retval = true;
    return Free_Return(retval, weaver_key, &pwd);
}

extern "C" int Get_Password_Type(const userid_t user_id, std::string& filename) {
    struct stat st{};
    char spblob_path_char[PATH_MAX];
    sprintf(spblob_path_char, "/data/system_de/%d/spblob/", user_id);
    if (stat(spblob_path_char, &st) == 0) {
        std::string spblob_path = spblob_path_char;
        KeystoreInfo keystore_info;
        std::string handle_str = keystore_info.getHandle(user_id);
        printf("Handle is '%s'\n", handle_str.c_str());
        password_data_struct pwd = {};
        if (!Get_Password_Data(spblob_path, handle_str, &pwd)) {
            printf("Failed to Get_Password_Data\n");
            return 0;
        }
        /* The password_data_struct holds the CREDENTIAL_TYPE_* values from
         * https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/com/android/internal/widget/LockPatternUtils.java#116
         * In Android type 1 is pattern
         * In Android <11 type 2 is PIN or password
         * In Android 11+ type 3 is PIN and type 4 is password */
        int type = 0;
        switch (pwd.credential_type) {
            case 1:  // CREDENTIAL_TYPE_PATTERN
                printf("Credential type: pattern\n");
                type = 2;  // In TWRP this means pattern
                break;
                // Legacy type
            // case 2: // CREDENTIAL_TYPE_PASSWORD_OR_PIN
            //     printf("credential type: password or PIN\n");
            //     type = 1; // In TWRP this means password or PIN (Android <11)
            //     break;
            case 3:  // CREDENTIAL_TYPE_PIN
                printf("Credential type: PIN\n");
                type = 3;  // In TWRP this means PIN
                break;
            case 4:  // CREDENTIAL_TYPE_PASSWORD
                printf("Credential type: password\n");
                type = 1;  // In TWRP this means password
                break;
            default:  // CREDENTIAL_TYPE_NONE(-1) or CREDENTIAL_TYPE_UNKNOWN(0)
                printf("unknown credential type: %d, using default password\n",
                       pwd.credential_type);
                break;
        }
        free(pwd.salt);
        free(pwd.password_handle);
        return type;
    }
    std::string path;
    if (user_id == 0) {
        path = "/data/system/";
    } else {
        char user_id_str[5];
        sprintf(user_id_str, "%i", user_id);
        path = "/data/system/users/";
        path += user_id_str;
        path += '/';
    }
    filename = path + "gatekeeper.password.key";
    if (stat(filename.c_str(), &st) == 0 && st.st_size > 0) return 1;
    filename = path + "gatekeeper.pattern.key";
    if (stat(filename.c_str(), &st) == 0 && st.st_size > 0) return 2;
    printf("Unable to locate gatekeeper password file '%s'\n", filename.c_str());
    filename = "";
    return 0;
}

extern "C" bool Decrypt_User(const userid_t user_id, const std::string& Password) {
    printf("Attempting to decrypt user\n");
    int ret = -1;

    struct stat st{};
    if (user_id > 9999) {
        printf("user_id is too big\n");
        return false;
    }
    std::string filename;
    bool Default_Password = Password == "!";
    if (Get_Password_Type(user_id, filename) == 0 && !Default_Password) {
        printf("Unknown password type\n");
        return false;
    }

    if (Default_Password) {
        if (!Decrypt_CE_storage(user_id, "!")) {
            return Decrypt_User_Synth_Pass(user_id, Password);
        }
        return true;
    }
    if (stat("/data/system_de/0/spblob", &st) == 0) {
        printf("Using synthetic password method\n");
        return Decrypt_User_Synth_Pass(user_id, Password);
    }
    // printf("password filename is '%s'\n", filename.c_str());
    if (stat(filename.c_str(), &st) != 0) {
        printf("error stating key file: %s\n", strerror(errno));
        return false;
    }
    std::string handle;
    if (!android::base::ReadFileToString(filename, &handle)) {
        printf("Failed to read '%s'\n", filename.c_str());
        return false;
    }
    bool request_reenroll = false;
    android::hardware::hidl_vec<uint8_t> curPwdHandle;
    curPwdHandle.setToExternal(const_cast<uint8_t*>((const uint8_t*)handle.c_str()), st.st_size);
    android::hardware::hidl_vec<uint8_t> enteredPwd;
    enteredPwd.setToExternal((unsigned char*)Password.c_str(), Password.size());

    // Devices that only declare the AIDL GateKeeper have no HIDL service.
    std::string gatekeeperServiceName = "android.hardware.gatekeeper.IGatekeeper/default";
    if (AServiceManager_isDeclared(gatekeeperServiceName.c_str())) {
        auto aidl_gk_device = AidlIGatekeeper::fromBinder(
                keystore::waitForService(gatekeeperServiceName.c_str()));
        if (!aidl_gk_device) {
            printf("failed to get gatekeeper service\n");
            return false;
        }
        AidlGatekeeperVerifyResp rsp;
        auto result =
                aidl_gk_device->verify(user_id, 0 /* challenge */, curPwdHandle, enteredPwd, &rsp);
        if (!result.isOk() || rsp.statusCode < AidlIGatekeeper::STATUS_OK) {
            printf("gatekeeper verification failed\n");
            return false;
        }
        printf("GateKeeper status ok\n");
        std::string secret = HashPassword(Password);
        return Decrypt_CE_storage(user_id, secret);
    }

    auto gk_device = ::android::hardware::gatekeeper::V1_0::IGatekeeper::getService();
    if (!gk_device) return false;

    android::hardware::Return<void> hwRet = gk_device->verify(
            user_id, 0 /* challenge */, curPwdHandle, enteredPwd,
            [&ret, &request_reenroll](const GatekeeperResponse& rsp) {
                ret = static_cast<int>(rsp.code);  // propagate errors
                if (rsp.code >= GatekeeperStatusCode::STATUS_OK) {
                    printf("GateKeeper status ok\n");
                    request_reenroll = rsp.code == GatekeeperStatusCode::STATUS_REENROLL;
                    ret = 0;  // all success states are reported as 0
                } else if (rsp.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT &&
                           rsp.timeout > 0) {
                    printf("GateKeeper response timeout: %u\n", rsp.timeout);
                    ret = rsp.timeout;
                } else {
                    printf("GateKeeper response error: %d\n", rsp.code);
                }
            });
    if (!hwRet.isOk() || ret != 0) {
        printf("gatekeeper verification failed\n");
        return false;
    }

    // The secret is "Android FBE credential hash" plus appended 0x00 to reach 128 bytes then append
    // the user's password then feed that to sha512sum
    if (std::string secret = HashPassword(Password); !Decrypt_CE_storage(user_id, secret)) {
        return false;
    }
    return true;
}
}  // namespace android
