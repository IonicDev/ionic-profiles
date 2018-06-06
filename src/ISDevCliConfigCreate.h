/* Copyright 2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_ISDEVCLICONFIG_CREATE_H
#define __IONIC_ISDEVCLICONFIG_CREATE_H

#include "ISDevCliConfigSet.h"

#include "ISAgentDeviceProfilePersistor.h"

#if defined(_WIN32) || defined(_WIN64)
#include "ISAgentDeviceProfilePersistorWindows.h"
#endif


class ISDevCliConfigCreate : public ISDevCliConfigSet {
	public:

		enum AuthMethod {
			ENROLL_ASSERT,
			ENROLL_EMAIL
		};
		const char *const authMethodString[2] = {
			"assertion",
			"email"
		};

		const char *const PROFILE_OPTION_SET_ACTIVE				= "setactive";
		const char *const PROFILE_OPTION_SET_ACTIVE_CAPA		= "setActive";

		const char *const PROFILE_OPTION_AUTH_METHOD			= "auth-method";
		const char *const PROFILE_OPTION_ENROLLMENT_METHOD		= "enrollment-method";	// DEPRECATED - use AUTH_METHOD
		const char *const PROFILE_OPTION_KEYSPACE				= "keyspace";
		const char *const PROFILE_OPTION_ASSERTION_FILEPATH		= "assertion-file";
		const char *const PROFILE_OPTION_ES_URL					= "es-url";
		const char *const PROFILE_OPTION_ES_HEADLESS_URL		= "es-headless-url";
		const char *const PROFILE_OPTION_ES_PUBKEY_URL			= "es-pubkey-url";	// DEPRECATED
		const char *const PROFILE_OPTION_API_URL				= "api-url";		// DEPRECATED

		const char *const PROFILE_OPTION_DEVICE_NAME			= "device-name";

		const char *const PROFILES_CREATE_DESCRIPTION			= "Create a new profile - DEFAULT";
		const char *const PROFILES_AUTHMETHOD_LINE				= "[--auth-method <email|assertion>] | [--enrollment-method <email|assertion>] DEPRECATED";
		const char *const PROFILES_KEYSPACE_LINE				= "[--keyspace <KEYSPACE>] [--assertion-file <path>] [--es[-headless]-url <URL>]";
		const char *const PROFILES_PUBKEY_URL_DEPRECATED_LINE	= "[--es-pubkey-url <URL>]\t\tDEPRECATED";
		const char *const PROFILES_API_URL_DEPRECATED_LINE		= "[--api-url <URL>]\t\tDEPRECATED";
		const char *const PROFILES_DEVICE_NAME_LINE				= "[--device-name <DEVICE_NAME>]";
		const char *const PROFILES_SET_ACTIVE_LINE				= "[--setactive <true|false>]";



		ISDevCliConfigCreate(int action = PROFILE_COMMAND_CREATE, int verbosity = 0) :
			sAuthMethod{authMethodString[ENROLL_ASSERT]},
			bSetActive{true},
			ISDevCliConfigSet(action, verbosity)
		{}

		~ISDevCliConfigCreate() {}

		void printConfigBody();

		void getConfigFromFile();

		void getConfigFromCommandLine();

		void printUsageHeader();

		void printUsagePersistor();

		void printUsageEnd();

		void buildOptions();

		void buildOptionsList();

		void validateConfig();

		string getAssertionFromFile(string sAssertionFilePath);

		void invokeAction(ISAgent *pAgent);

		void performGenAssnDeviceEnrollment(ISAgent *pAgent);

		string emailRequestBody();

		string samlRequestBody();

		void getIonicAuthentication(string & sToken, string & sUidauth);

		void getEnrollmentServicePublicKey(string & sEsPublicKeyBase64);

		void createIonicProfile(ISAgent * pAgent,
				string sTokenIn, string sUidauthIn,
				string sEsPublicKeyBase64In,
				ISAgentDeviceProfile & deviceProfileOut);

		void storeIonicProfile(ISAgent * pAgent, ISAgentDeviceProfile & deviceProfileIn);


//	private:

		string	sAuthMethod;				// Enrollment Authentication Method - email, assertion
		string	sEsGenAssnUrl;				// Generated SAML Assertion <aka headless>
		string	sEsPubkeyUrl;				// DEPRECATED - Pubkey Url should be pulled from response
		string	sApiUrl;					// DEPRECATED - API Url should be pulled from response
		string	sKeyspace;					// Keyspace where enrollment requested
		string	sAssertionFilePath;			// File path for assertion file
		string	sAssertionData;
		bool	bSetActive;					// Automatically set new profile to active
		string	sDeviceName;				// Device Name for profile being created and stored (Create)


		po::options_description auth_options_list;
		po::options_description keyspace_options_list;
		po::options_description deprecated_options_list;
		po::options_description device_name_options_list;
		po::options_description set_active_options_list;

};

#endif // __IONIC_ISDEVCLICONFIG_CREATE_H
