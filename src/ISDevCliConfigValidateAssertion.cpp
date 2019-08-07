/* Copyright 2018-2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>

#include "ISDevCliConfigValidateAssertion.h"
#include "ISDevUtils.h"
#include "ISEnrollmentError.h"

void ISDevCliConfigValidateAssertion::printConfigBody() {

	cout	<< LINE_LEAD << PROFILE_OPTION_ASSERTION_FILEPATH << "         "
			<< COLON_SPACE << sAssertionFilePath
			<< endl;
	cout	<< LINE_LEAD << PROFILE_OPTION_ES_URL << "                 "
			<< COLON_SPACE << sEsGenAssnUrl
			<< endl;

	ISDevCliConfig::printConfigBody();
}

void ISDevCliConfigValidateAssertion::getConfigFromFile() {

	ISDevCliConfig::getConfigFromFile();

	// extract configs
	boost::optional<string> op;

	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_ASSERTION_FILEPATH))) {
		sAssertionFilePath = *op;
	}

	// check for es-url option
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_ES_URL))) {
		sEsGenAssnUrl = *op;
	}

}

void ISDevCliConfigValidateAssertion::getConfigFromCommandLine() {
	ISDevCliConfig::getConfigFromCommandLine();

	if (vm.count(PROFILE_OPTION_ASSERTION_FILEPATH)) {
		sAssertionFilePath = vm[PROFILE_OPTION_ASSERTION_FILEPATH].as<string>();
	}
	if (vm.count(PROFILE_OPTION_ES_URL)) {
		sEsGenAssnUrl = vm[PROFILE_OPTION_ES_URL].as<string>();
	}
}

void ISDevCliConfigValidateAssertion::printUsageHeader() {
	cout << PROFILES_VALIDATE_ASSERTION_DESCRIPTION << endl;
	ISDevCliConfig::printUsageHeader();
	cout << "\t" << PROFILES_VALIDATE_OPTIONS_LINE << endl;
}

void ISDevCliConfigValidateAssertion::printUsagePersistor() {
}

void ISDevCliConfigValidateAssertion::buildOptions() {
	ISDevCliConfig::buildOptions();

	validate_options_list.add_options()
		(PROFILE_OPTION_ASSERTION_FILEPATH, po::value<string>(),
			"path to assertion file for enrollment\n")
		(PROFILE_OPTION_ES_URL, po::value<string>(),
			"enrollment service url\n")
	;

}

void ISDevCliConfigValidateAssertion::buildOptionsList() {
	usage.add(config_options_list)
		.add(validate_options_list)
		.add(miscellaneous_options_list)
	;
}

void ISDevCliConfigValidateAssertion::validatePersistor(Persistor *persistor) {
}

void ISDevCliConfigValidateAssertion::validateConfig() {

	if (sAssertionFilePath == "") {
		fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
				"Missing arg: '" + (string)PROFILE_OPTION_ASSERTION_FILEPATH + "'");
	}

	// keep after 'ValidateAssertion' specific checks and before validateAssertion call
	ISDevCliConfig::validateConfig();

	string sEsUrlFromAssertion;
	ISDevUtils::validateAssertion(sAssertionFilePath, sEsGenAssnUrl, sEsUrlFromAssertion);
}


// Invoke the specific function for the Validate-Assertion action
void ISDevCliConfigValidateAssertion::invokeAction(ISAgent *pAgent) {
	cout << "Valid assertion." << endl;
}
