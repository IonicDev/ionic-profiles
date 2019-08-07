/* Copyright 2018 - 2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_DEV_GET_SENSITIVE_INPUT_H
#define __IONIC_DEV_GET_SENSITIVE_INPUT_H

#include <string>

bool getSensitiveInput(const std::string& prompt, std::string& sensitiveInput, std::string& errorMessage);

#endif
