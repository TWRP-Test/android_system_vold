/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef ANDROID_VOLD_CRYPTFS_H
#define ANDROID_VOLD_CRYPTFS_H

#include <string>

#include "KeyBuffer.h"
#include "KeyUtil.h"

#ifdef CONFIG_HW_DISK_ENCRYPTION
/* This flag is used to transition from L->M upgrade. L release passed
 * a byte for every nible of user password while M release is passing
 * ascii value of user password.
 * Random flag value is chosen so that it does not conflict with other use cases
 */
#define CRYPT_ASCII_PASSWORD_UPDATED 0x1000
#endif
int cryptfs_setup_ext_volume(const char* label, const char* real_blkdev,
                             const android::vold::KeyBuffer& key, std::string* out_crypto_blkdev);
const android::vold::KeyGeneration cryptfs_get_keygen();

#endif /* ANDROID_VOLD_CRYPTFS_H */
