/* Copyright 2018 - 2019 Ionic Security Inc. All Rights Reserved.
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
			ENROLL_EMAIL,
			ENROLL_IONIC_AUTHENTICATION
		};
		const char *const authMethodString[3] = {
			"assertion",
			"email",
			"ionic-authentication"
		};

		const char *const PROFILE_OPTION_SET_ACTIVE		= "setactive";
		const char *const PROFILE_OPTION_SET_ACTIVE_CAPA	= "setActive";

		const char *const PROFILE_OPTION_AUTH_METHOD		= "auth-method";
		const char *const PROFILE_OPTION_ENROLLMENT_METHOD	= "enrollment-method";	// DEPRECATED - use AUTH_METHOD
		const char *const PROFILE_OPTION_NO_VALIDATE_ASSERTION	= "no-validate-assertion";
		const char *const PROFILE_OPTION_KEYSPACE		= "keyspace";
		const char *const PROFILE_OPTION_ES_HEADLESS_URL	= "es-headless-url";
		const char *const PROFILE_OPTION_ES_PUBKEY_URL		= "es-pubkey-url";	// DEPRECATED
		const char *const PROFILE_OPTION_API_URL		= "api-url";		// DEPRECATED

		const char *const PROFILE_OPTION_EMAIL			= "email";
		const char *const PROFILE_OPTION_IONIC_USER_NAME	= "ionic-user-name";
		const char *const PROFILE_OPTION_IONIC_PASSWORD		= "ionic-password";
		const char *const PROFILE_OPTION_DEVICE_NAME		= "device-name";

		const char *const PROFILES_CREATE_DESCRIPTION		= "Create a new profile - DEFAULT";
		const char *const PROFILES_AUTHMETHOD_LINE		= "[--auth-method <assertion|email|ionic-authentication>] | "
									  "[--enrollment-method <assertion|email|ionic-authentication>] DEPRECATED";
		const char *const PROFILES_KEYSPACE_LINE		= "[--keyspace <KEYSPACE>] [--assertion-file <path> [--no-validate-assertion]] [--es[-headless]-url <URL>]";
		const char *const PROFILES_PUBKEY_URL_DEPRECATED_LINE	= "[--es-pubkey-url <URL>]\t\tDEPRECATED";
		const char *const PROFILES_API_URL_DEPRECATED_LINE	= "[--api-url <URL>]\t\tDEPRECATED";
		const char *const PROFILES_EMAIL_LINE			= "[--email <EMAIL_ADDRESS>]";
		const char *const PROFILES_IONIC_AUTHENTICATION_LINE	= "[--ionic-user-name <IONIC-USER-NAME>] [--ionic-password <IONIC-PASSWORD>]";
		const char *const PROFILES_DEVICE_NAME_LINE		= "[--device-name <DEVICE_NAME>]";
		const char *const PROFILES_SET_ACTIVE_LINE		= "[--setactive <true|false>]";



		ISDevCliConfigCreate(int verbosity = 0) :
			sAuthMethod{authMethodString[ENROLL_ASSERT]},
			bSetActive{true},
			ISDevCliConfigSet(verbosity)
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

		string ionicAuthenticationRequestBody();

		string samlRequestBody();

		void getAuthentication(string & sToken, string & sUidauth);

		void getEnrollmentServicePublicKey(string & sEsPublicKeyBase64);

		void createIonicProfile(ISAgent * pAgent,
				string sTokenIn, string sUidauthIn,
				string sEsPublicKeyBase64In,
				ISAgentDeviceProfile & deviceProfileOut);

		void storeIonicProfile(ISAgent * pAgent, ISAgentDeviceProfile & deviceProfileIn);


//	private:

		string	sAuthMethod;				// Enrollment Authentication Method - assertion, email or ionic-authentication
		string	sEsGenAssnUrl;				// Generated SAML Assertion <aka headless>
		string	sEsPubkeyUrl;				// DEPRECATED - Pubkey Url should be pulled from response
		string	sApiUrl;					// DEPRECATED - API Url should be pulled from response
		string	sKeyspace;					// Keyspace where enrollment requested
		string	sAssertionFilePath;			// File path for assertion file
		bool	bValidateAssertion;			// Whether to locally validate assertion -- true by default
		string	sAssertionData;
		bool	bSetActive;					// Automatically set new profile to active
		string	sDeviceName;				// Device Name for profile being created and stored (Create)
		string	sEmailAddress;				// E-mail address to receive enrollment code (sToken) for profile being created and stored (Create)
		string	sIonicUserName;				// Ionic user name for authenticating to create profile
		string	sIonicPassword;				// Ionic user name for authenticating to create profile

		po::options_description auth_options_list;
		po::options_description keyspace_options_list;
		po::options_description deprecated_options_list;
		po::options_description email_address_options_list;
		po::options_description ionic_authentication_options_list;
		po::options_description device_name_options_list;
		po::options_description set_active_options_list;


private:
		bool getRegisterURL(std::string& registerURL, std::string& errorMessage) const;

};

#endif // __IONIC_ISDEVCLICONFIG_CREATE_H
