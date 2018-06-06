/* Copyright 2017-2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_DEVCLIUTILS_H
#define __IONIC_DEVCLIUTILS_H

#include <string>

void passOrDie(const int nErr, const std::string sMessage);
void fatal(const int nErr, const std::string sMessage);
void initIonicLogging(int nVerbose);

#endif // __IONIC_DEVCLIUTILS_H
