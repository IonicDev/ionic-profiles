/* Copyright 2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_ISDEVCLICONFIG_VALIDATEASSERTION_H
#define __IONIC_ISDEVCLICONFIG_VALIDATEASSERTION_H

#include "ISDevCliConfig.h"


class ISDevCliConfigValidateAssertion : public ISDevCliConfig {
	public:

		const char *const PROFILES_VALIDATE_ASSERTION_DESCRIPTION	= "Validate an assertion.";
		const char *const PROFILES_VALIDATE_OPTIONS_LINE			= "[--assertion-file <path>] [--es[-headless]-url <URL>]";

		ISDevCliConfigValidateAssertion(int verbosity = 0) :
			ISDevCliConfig(verbosity)
		{}

		~ISDevCliConfigValidateAssertion() {}

		void printConfigBody();

		void getConfigFromFile();

		void getConfigFromCommandLine();

		void printUsageHeader();

		void printUsagePersistor();

		void buildOptions();

		void buildOptionsList();

		void validatePersistor(Persistor *persistor);

		void validateConfig();

		void invokeAction(ISAgent *pAgent);


//	private:

		string	sEsGenAssnUrl;				// Generated SAML Assertion <aka headless>
		string	sAssertionFilePath;			// File path for assertion file

		po::options_description validate_options_list;

};

#endif // __IONIC_ISDEVCLICONFIG_VALIDATEASSERTION_H
