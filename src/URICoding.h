/* Copyright 2017-2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef  __IONIC_URICODING_H
#define  __IONIC_URICODING_H

#include <string>

std::string UriEncode(const std::string & sSrc);
std::string UriDecode(const std::string & sSrc);

#endif  //__IONIC_URICODING_H
