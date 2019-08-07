/* Copyright 2017-2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_DEVCLIUTILS_H
#define __IONIC_DEVCLIUTILS_H

#include <string>

namespace ISDevUtils {

	const char *const PROFILE_OPTION_ASSERTION_FILEPATH		= "assertion-file";
	const char *const PROFILE_OPTION_ES_URL					= "es-url";

	void passOrDie(const int nErr, const std::string& sMessage);
	void fatal(const int nErr, const std::string& sMessage);
	void initIonicLogging(int nVerbose);
	void readEsUrlFromAssertionFile(const std::string& sAssertionFilePath, std::string& sEsUrlFromAssertion);
	void validateAssertion(const std::string& sAssertionFilePath, const std::string& sEsGenAssnUrl, std::string& sEsUrlFromAssertion);
}

using namespace ISDevUtils;

#endif // __IONIC_DEVCLIUTILS_H
