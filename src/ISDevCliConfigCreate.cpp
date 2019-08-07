/* Copyright 2018 - 2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <sstream>

#include "ISHTTP.h"
#include "URICoding.h"
#include "ISDevRest.h"
#include "ISDevGetSensitiveInput.h"

#include "ISDevCliConfigCreate.h"

#include "ISDevUtils.h"
#include "ISEnrollmentError.h"

#include "boost/filesystem.hpp"
namespace fs = boost::filesystem;

void ISDevCliConfigCreate::printConfigBody() {

	cout	<< LINE_LEAD << PROFILE_OPTION_AUTH_METHOD << "            "
			<< COLON_SPACE << sAuthMethod
			<< endl;
	cout	<< LINE_LEAD << PROFILE_OPTION_KEYSPACE << "               "
			<< COLON_SPACE << sKeyspace
			<< endl;
	cout	<< LINE_LEAD << PROFILE_OPTION_ASSERTION_FILEPATH << "         "
			<< COLON_SPACE << sAssertionFilePath
			<< endl;
	if (!bValidateAssertion) {
		cout	<< LINE_LEAD << PROFILE_OPTION_NO_VALIDATE_ASSERTION << "  "
				<< COLON_SPACE << true
				<< endl;
	}
	cout	<< LINE_LEAD << PROFILE_OPTION_ES_URL << "                 "
			<< COLON_SPACE << sEsGenAssnUrl
			<< endl;
	cout	<< LINE_LEAD << PROFILE_OPTION_ES_PUBKEY_URL << "          "
			<< COLON_SPACE << sEsPubkeyUrl
			<< endl;
	cout	<< LINE_LEAD << PROFILE_OPTION_API_URL << "                "
			<< COLON_SPACE << sApiUrl
			<< endl;

	ISDevCliConfigSet::printConfigBody();
}

void ISDevCliConfigCreate::getConfigFromFile() {

	ISDevCliConfig::getConfigFromFile();

	// extract configs
	boost::optional<string> op;

	// Select Enrollment Method: Assertion, E-mail
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_AUTH_METHOD))) {
		sAuthMethod = *op;
	} else if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_ENROLLMENT_METHOD))) {  // DEPRECATED
		sAuthMethod = *op;
	}

	// Select Keyspace profile belongs in
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_KEYSPACE))) {
		sKeyspace = *op;
	}

	// If Enrollment method is assertion provide path and filename
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_ASSERTION_FILEPATH))) {
		sAssertionFilePath = *op;
	}

	// set bValidateAssertion to true iff no-validate-assertion is not specified
	bValidateAssertion = !jsonConfig.get_optional<bool>(PROFILE_OPTION_NO_VALIDATE_ASSERTION);

	// check for es-url option
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_ES_URL))) {
		sEsGenAssnUrl = *op;
	}
	// only check for es-headless-url option if no es-url
	else if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_ES_HEADLESS_URL))) {
		sEsGenAssnUrl = *op;
	}

	// Set Url for PubKey <Deprecated in favor of extracting from response>
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_ES_PUBKEY_URL))) {
		sEsPubkeyUrl = *op;
	}

	// Set Url for API <Deprecated in favor of extracting from response>
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_API_URL))) {
		sApiUrl = *op;
	}

}

void ISDevCliConfigCreate::getConfigFromCommandLine() {
	ISDevCliConfig::getConfigFromCommandLine();

	if (vm.count(PROFILE_OPTION_AUTH_METHOD)) {
		sAuthMethod = vm[PROFILE_OPTION_AUTH_METHOD].as<string>();
	} else if (vm.count(PROFILE_OPTION_ENROLLMENT_METHOD)) {  // Deprecated option
		sAuthMethod = vm[PROFILE_OPTION_ENROLLMENT_METHOD].as<string>();
	}

	if (bQuiet && (0 == sAuthMethod.compare(PROFILE_OPTION_EMAIL))) {
		fatal(ISSET_ERROR_ARG_CONFLICT,
				"Conflicting arg: quiet mode not allowed with email authentication method");
	}

	if (vm.count(PROFILE_OPTION_KEYSPACE)) {
		sKeyspace = vm[PROFILE_OPTION_KEYSPACE].as<string>();
	}
	if (vm.count(PROFILE_OPTION_ASSERTION_FILEPATH)) {
		sAssertionFilePath = vm[PROFILE_OPTION_ASSERTION_FILEPATH].as<string>();
	}
	bValidateAssertion = !vm.count(PROFILE_OPTION_NO_VALIDATE_ASSERTION);
	if (vm.count(PROFILE_OPTION_ES_URL)) {
		sEsGenAssnUrl = vm[PROFILE_OPTION_ES_URL].as<string>();
	// only check for es-headless-url if no es-url
	} else if (vm.count(PROFILE_OPTION_ES_HEADLESS_URL)) {
		sEsGenAssnUrl = vm[PROFILE_OPTION_ES_HEADLESS_URL].as<string>();
	}
	if (vm.count(PROFILE_OPTION_ES_PUBKEY_URL)) {
		sEsPubkeyUrl = vm[PROFILE_OPTION_ES_PUBKEY_URL].as<string>();
	}
	if (vm.count(PROFILE_OPTION_API_URL)) {
		sApiUrl = vm[PROFILE_OPTION_API_URL].as<string>();
	}
	if (vm.count(PROFILE_OPTION_EMAIL)) {
		sEmailAddress = vm[PROFILE_OPTION_EMAIL].as<string>();
	}
	if (vm.count(PROFILE_OPTION_IONIC_USER_NAME)) {
		sIonicUserName = vm[PROFILE_OPTION_IONIC_USER_NAME].as<string>();
	}
	if (vm.count(PROFILE_OPTION_IONIC_PASSWORD)) {
		sIonicPassword = vm[PROFILE_OPTION_IONIC_PASSWORD].as<string>();
	}
	if (vm.count(PROFILE_OPTION_DEVICE_NAME)) {
		sDeviceName = vm[PROFILE_OPTION_DEVICE_NAME].as<string>();
	}
	if (vm.count(PROFILE_OPTION_SET_ACTIVE)) {
		bSetActive = vm[PROFILE_OPTION_SET_ACTIVE].as<bool>();
	} else if (vm.count(PROFILE_OPTION_SET_ACTIVE_CAPA)) {  // deprecated setActive
		bSetActive = vm[PROFILE_OPTION_SET_ACTIVE_CAPA].as<bool>();
	}

	if (sAuthMethod.compare(authMethodString[ENROLL_ASSERT]) == 0) {
		// Check for CLI param for assertion-file
		if (vm.count(PROFILE_OPTION_ASSERTION_FILEPATH)) {
			sAssertionFilePath =
					vm[PROFILE_OPTION_ASSERTION_FILEPATH].as<string>();
		}

		// Check if assertion-file set from config file or CLI
		//   and get assertion data from file if so
		if (!sAssertionFilePath.empty()) {
			sAssertionData = getAssertionFromFile(
					sAssertionFilePath);
		}
	}
}

void ISDevCliConfigCreate::printUsageHeader() {
	cout << PROFILES_CREATE_DESCRIPTION << endl;
	ISDevCliConfig::printUsageHeader();
}

void ISDevCliConfigCreate::printUsagePersistor() {

	cout << "\t" << PROFILES_AUTHMETHOD_LINE << endl;
	cout << "\t" << PROFILES_KEYSPACE_LINE << endl;
	ISDevCliConfig::printUsagePersistor();
}

void ISDevCliConfigCreate::printUsageEnd() {
	cout << "\t" << PROFILES_PUBKEY_URL_DEPRECATED_LINE << endl;
	cout << "\t" << PROFILES_API_URL_DEPRECATED_LINE << endl;
	cout << "\t" << PROFILES_EMAIL_LINE;
	cout << "\t" << PROFILES_IONIC_AUTHENTICATION_LINE;
	cout << " "  << PROFILES_DEVICE_NAME_LINE;
	cout << " "  << PROFILES_SET_ACTIVE_LINE;
	cout << endl;

	ISDevCliConfig::printUsageEnd();

}

void ISDevCliConfigCreate::buildOptions() {
	ISDevCliConfig::buildOptions();

	auth_options_list.add_options()
		(PROFILE_OPTION_AUTH_METHOD, po::value<string>(),
			"authentication method \n(email, ionic-authentication, assertion)\n")
		(PROFILE_OPTION_ENROLLMENT_METHOD, po::value<string>(),
			"DEPRECATED: authentication method \n(email, ionic-authentication, assertion)\n")
	;

	keyspace_options_list.add_options()
		(PROFILE_OPTION_KEYSPACE, po::value<string>(),
			"keyspace for enrollment\n")
		(PROFILE_OPTION_ASSERTION_FILEPATH, po::value<string>(),
			"path to assertion file for enrollment\n")
		(PROFILE_OPTION_NO_VALIDATE_ASSERTION, po::value<bool>()->zero_tokens(),
			"don't validate the assertion file before sending the enrollment request (default is to validate)\n")
		(PROFILE_OPTION_ES_URL, po::value<string>(),
			"enrollment service url\n")
		(PROFILE_OPTION_ES_HEADLESS_URL, po::value<string>(),
			"enrollment service url\n")
	;

	deprecated_options_list.add_options()
		(PROFILE_OPTION_ES_PUBKEY_URL, po::value<string>(),
			"DEPRECATED: URL for Enrollment Services’s public key.\n"
			"This overrides the value returned from the registration endpoint\n")
		(PROFILE_OPTION_API_URL, po::value<string>(),
			"DEPRECATED: URL for tenant’s API server.\n"
			"This overrides the value returned from the registration endpoint\n")
	;

	email_address_options_list.add_options()
		(PROFILE_OPTION_EMAIL,	po::value<string>()->implicit_value(""),
			"For scripting, provide email address\n")
	;

	ionic_authentication_options_list.add_options()
		(PROFILE_OPTION_IONIC_PASSWORD, po::value<string>()->implicit_value(""),
			"For scripting, provide Ionic password\n")
		(PROFILE_OPTION_IONIC_USER_NAME, po::value<string>()->implicit_value(""),
			"For scripting, provide Ionic user name\n")
	;

	device_name_options_list.add_options()
		(PROFILE_OPTION_DEVICE_NAME,	po::value<string>()->implicit_value(""),
			"For scripting, provide device name for profile\n")
	;

	set_active_options_list.add_options()
		(PROFILE_OPTION_SET_ACTIVE, po::value<bool>(),
			"Automatically set new profile as Active\n")
	;

}

void ISDevCliConfigCreate::buildOptionsList() {
	usage.add(config_options_list)
		.add(auth_options_list)
		.add(keyspace_options_list)
		.add(persistor_options_list)
		.add(deprecated_options_list)
		.add(email_address_options_list)
		.add(ionic_authentication_options_list)
		.add(device_name_options_list)
		.add(set_active_options_list)
		.add(miscellaneous_options_list)
	;
}

bool ISDevCliConfigCreate::getRegisterURL(string& registerURL, string& errorMessage) const {
	// Get the keyspace and enrollment URLs. The keyspace URL is
	// initialized while retrieving the enrollment URL.
	string keyspaceURL;
	string enrollmentURL;
	if (!getEnrollmentURL(sKeyspace, keyspaceURL, enrollmentURL, errorMessage)) {
		return false;
	}

	// Make sure the enrollment URL could end in "/register", based on its length
	string slashRegister("/register");
	if (enrollmentURL.empty()) {
		errorMessage.assign("enrollment URL from " + keyspaceURL + " is empty");
		return false;
	}
	if (enrollmentURL.length() < slashRegister.length()) {
		errorMessage.assign("enrollment URL [" + enrollmentURL + "] from " + keyspaceURL + " should end in \"/register\"");
		return false;
	}

	// Make sure the enrollment URL actually does end in "/register".
	// It is safe to start a substring call with the difference between
	// the length of enrollmentURL and that of "/register", because the
	// result of that subtraction is positive.
	size_t baseUrlEndPos = enrollmentURL.length() - slashRegister.length();
	if (enrollmentURL.substr(baseUrlEndPos, slashRegister.length()) != slashRegister) {
		errorMessage.assign("enrollment URL [" + enrollmentURL + "] from " + keyspaceURL + " should end in \"/register\"");
		return false;
	}

	// Construct the identity source URL, and use it to get a map of /register URLs
	string identitySourcesURL(enrollmentURL.substr(0, baseUrlEndPos) + "/identity_sources");
	string identitySourceType; // Set to  "SAML", "LOUDEMAIL" or "IDC", then passed to getRegisterURLs
	string defaultName;
	string globalDefaultName;
	std::map<string, string> registerURLs;
	if (sAuthMethod.compare(authMethodString[ENROLL_ASSERT]) == 0) {
		identitySourceType.assign("SAML");
	}
	if (sAuthMethod.compare(authMethodString[ENROLL_EMAIL]) == 0) {
		identitySourceType.assign("LOUDEMAIL");
	}
	if (sAuthMethod.compare(authMethodString[ENROLL_IONIC_AUTHENTICATION]) == 0) {
		identitySourceType.assign("IDC");
	}
	if (identitySourceType.empty()) {
		errorMessage.assign(
		  PROFILE_OPTION_AUTH_METHOD + string(" or ") + PROFILE_OPTION_ENROLLMENT_METHOD +
		  string(" must be set to ") + authMethodString[ENROLL_ASSERT] + string(", ") +
		  authMethodString[ENROLL_IONIC_AUTHENTICATION] + string(" or ") +
		  authMethodString[ENROLL_EMAIL] + string(" in order to create a profile without providing option --") +
		  PROFILE_OPTION_ES_URL
		);
		return false;
	}
	if (!getRegisterURLs(identitySourcesURL, identitySourceType, registerURLs, defaultName, globalDefaultName, errorMessage)) {
		return false;
	}

	// Use the default registerURL, if available.
	if (defaultName.empty()) {
		errorMessage.assign("No default URL was listed for " + identitySourceType + " in response to GET from " + identitySourcesURL);
		return false;
	}

	// Check for the internal error that defaultName was set but is not a key!
	auto it = registerURLs.find(defaultName);
	if (it == registerURLs.end()) {
		errorMessage.assign("Internal error finding uri with name [" + defaultName + "] under the response from " + identitySourcesURL);
	}

	// It is finally safe to assign registerURL
	registerURL.assign(it->second);
	return true;
}

void ISDevCliConfigCreate::validateConfig() {

	// 'Create'-specific checks

	if (sKeyspace.empty()) {
		fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
				"Missing arg: '" + (string)PROFILE_OPTION_KEYSPACE + "'");
	}
	// If assertion method, assertion file is required
	if (sAuthMethod.compare(authMethodString[ENROLL_ASSERT]) == 0) {
		if (sAssertionFilePath.empty()) {
			fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
					"Missing arg: '" + (string)PROFILE_OPTION_ASSERTION_FILEPATH + "'");
		}
		string sEsUrlFromAssertion;
		if (bValidateAssertion) {
			ISDevUtils::validateAssertion(sAssertionFilePath, sEsGenAssnUrl, sEsUrlFromAssertion); // also read es-url from assertion file
		} else {
			ISDevUtils::readEsUrlFromAssertionFile(sAssertionFilePath, sEsUrlFromAssertion);
		}
		if (sEsGenAssnUrl.empty() && !sEsUrlFromAssertion.empty()) {
			if (nVerbose > 1) {
				cout << "Using " << PROFILE_OPTION_ES_URL << " " << sEsUrlFromAssertion << " from assertion file." << endl;
			}
			sEsGenAssnUrl = sEsUrlFromAssertion;
		}
		if (sEsGenAssnUrl.empty()) {
			fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
					"Missing arg: '" + (string)PROFILE_OPTION_ES_URL + "'");
		}
		if (sAssertionData.empty()) {
			fatal(ISSET_ERROR_ASSERTIONFILE_LOAD_FAILED,
					"Failed to load assertion data");
		}
	}

	// keep after Create specific checks
	ISDevCliConfig::validateConfig();

}


string ISDevCliConfigCreate::getAssertionFromFile(string sAssertionFilePath) {
// load Generated SAML Assertion
	string sAssertionData;
	ifstream fileAssertion(sAssertionFilePath.c_str());
	if (fileAssertion) {
		stringstream buffer;
		buffer << fileAssertion.rdbuf();
		sAssertionData = buffer.str();
		fileAssertion.close();
	}
	if (sAssertionData.size() == 0) {
		fatal(ISSET_ERROR_ASSERTIONFILE_LOAD_FAILED,
				"Failed to load assertion data from file: " + sAssertionFilePath);
	}

	return sAssertionData;
}


// Invoke the specific function for the Create action
void ISDevCliConfigCreate::invokeAction(ISAgent *pAgent) {
	performGenAssnDeviceEnrollment(pAgent);
}


void ISDevCliConfigCreate::performGenAssnDeviceEnrollment(ISAgent *pAgent) {
	string sToken;
	string sUidauth;
	string sEsPublicKeyBase64;
	ISAgentDeviceProfile deviceProfile;

	pAgent->initializeWithoutProfiles();

	// perform headless device enrollment
	getAuthentication(sToken, sUidauth);
	if (nVerbose >= 1) {
		cout << LINE_LEAD << "Authentication: " << sUidauth << endl;
	}

	getEnrollmentServicePublicKey(sEsPublicKeyBase64);
	createIonicProfile(pAgent, sToken, sUidauth, sEsPublicKeyBase64,
			deviceProfile);
	storeIonicProfile(pAgent, deviceProfile);

	// Confirm functional new registration.
	if (nVerbose >= 1) {
		cout << "Confirm functional new registration" << endl;
	}
	ISAgentGetResourcesRequest::Resource reqIn =
			ISAgentGetResourcesRequest::Resource();
	ISAgentGetResourcesResponse responseOut;

	// Make upto 2 tries to get successful response from back end as 1st try may be too quick
	int result = pAgent->getResource(reqIn, responseOut);
	if (result != ISAGENT_OK ) {
		int result2 = pAgent->getResource(reqIn, responseOut);
		if (result2 != ISAGENT_OK) {
			fatal(ISSET_ERROR_CONFIRMATION_FAILED,
					"Failed to confirm functional new registration.");
		} else if (nVerbose >= 1) {
			cout << "Confirmed registration on 2nd try" << endl;
		}
	} else if (nVerbose >= 1) {
		cout << "Confirmed registration on 1st try" << endl;
	}
}

string ISDevCliConfigCreate::emailRequestBody() {

	while (sEmailAddress.empty()) {
		cout << "\nPlease enter email address: ";
		getline(cin, sEmailAddress);
	}

	return "email=" + UriEncode(sEmailAddress);
}

string ISDevCliConfigCreate::ionicAuthenticationRequestBody() {
	while (sIonicUserName.empty()) {
		cout << "\nEnter your Ionic user name: ";
		getline(cin, sIonicUserName);
	}
	while (sIonicPassword.empty()) {
		// Try to hide input when getting the user's password.
		string errorMessage;
		bool gotPassword = getSensitiveInput("\nEnter your Ionic password", sIonicPassword, errorMessage);
		if ((nVerbose >= 1) && !errorMessage.empty()) {
			cout <<	"[+] Recoverable error was encountered while hiding password as it is entered on the console: " + errorMessage << endl;
		}
		cout << endl; // Newline was one of the hidden characters

		// getSensitiveInput() can fail if the terminal is not
		// what ionic-profiles is compiled for, such as a git
		// bash terminal rather than a DOS terminal on
		// Windows. If such failure was detected, the fallback
		// is to let the password be echoed.
		if (!gotPassword) {
			cout << "Enter your Ionic password (NOTE - it will echo to the screen): ";
			getline(cin, sIonicPassword);
		}
	}
	return "username=" + UriEncode(sIonicUserName) + "&password=" + UriEncode(sIonicPassword);
}

string ISDevCliConfigCreate::samlRequestBody() {
	return "SAMLResponse=" + UriEncode(sAssertionData);
}

void ISDevCliConfigCreate::getAuthentication(string & sToken,
		string & sUidauth) {

	if (nVerbose >= 1) {
		cout	<< endl
				<< "[+] Getting authentication from Enrollment Service"
				<< endl
		;
	}

	if (sEsGenAssnUrl.empty()) {
		string registerURL;
		string errorMessage;
		if (!getRegisterURL(registerURL, errorMessage)) {
			if (bQuiet) {
				// Quiet Mode: Report error missing
				// required ES Url arg
				string fatalMessage("Quiet mode: could not construct " + string(PROFILE_OPTION_ES_URL) + ": " + errorMessage);
				fatal(ISSET_ERROR_MISSING_REQUIRED_ARG, fatalMessage.c_str());
			} else {
				// Interactive Mode: Note the error
				// and request that the user enter the
				// ES Url
				if (nVerbose > 1) {
					cout << "Encountered an error constructing " << PROFILE_OPTION_ES_URL << ": " << errorMessage << endl;
				}
				cout << "Please provide the appropriate enrollment URL: " << endl;
				getline(cin, registerURL);
			}
		}
		sEsGenAssnUrl = registerURL;
		if (nVerbose > 1) {
			cout << "Using " << PROFILE_OPTION_ES_URL << " " << sEsGenAssnUrl << "." << endl;
		}
	}

	string sBody;
	// create HTTP request
	if (sAuthMethod.compare(authMethodString[ENROLL_EMAIL]) == 0) {
		if (bQuiet) {
			// Quiet mode: Unable to complete email enrollment authentication since user input required
			fatal(ISSET_ERROR_ENROLLMENT_REQUEST_FAILED,
				"Quiet mode: Unable to complete email enrollment authenication as user input is required");
		} else {
			// Interactive mode: build email request body
			sBody = emailRequestBody();
		}
	} else if (sAuthMethod.compare(authMethodString[ENROLL_IONIC_AUTHENTICATION]) == 0) {
		if (bQuiet && (sIonicUserName.empty() || sIonicPassword.empty())) {
			// Quiet mode: Unable to complete Ionic authentication enrollment since user input required
			fatal(ISSET_ERROR_ENROLLMENT_REQUEST_FAILED,
				"Quiet mode: Unable to complete Ionic Authenication as user input is required");
		} else {
			// Interactive mode: build Ionic authentication request body
			sBody = ionicAuthenticationRequestBody();
		}
	} else {
		// Assertion enrollment: build assertion request body
		sBody = samlRequestBody();
	}

	ISHTTPRequest httpRequest;
	httpRequest.setMethod(HTTP_POST);
	httpRequest.setUrl(sEsGenAssnUrl);
	httpRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");
	httpRequest.setBody(sBody);
	if (nVerbose >= 1) {
		cout	<< LINE_LEAD << "Making HTTP Request: POST "
				<< sEsGenAssnUrl
				<< endl
		;
	}

	// send HTTP request
	ISHTTPResponse httpResponse;
	ISHTTP * pHttp = ISHTTPFactory::getInstance().createDefault();
	pHttp->send(httpRequest, httpResponse);
	int nHttpResponseCode = httpResponse.getResponseCode();
	if (nVerbose >= 1) {
		cout	<< LINE_LEAD << "Received HTTP Response: "
				<< nHttpResponseCode
				<< endl
		;
	}
	if (nHttpResponseCode != HTTP_OK) {
		fatal(ISSET_ERROR_ENROLLMENT_REQUEST_FAILED,
				"HTTP Request to enrollment URL failed");
	}

	// get response body
	ISHTTPData body = httpResponse.getBody();

	if (nVerbose >= 2) {
		string sBodyData = string((char*) body.getData(),
				body.getLen());
		cout << sBodyData << endl;
		const vector<ISHTTPHeader>& headers = httpResponse.getHeaders();
		auto iter = headers.begin();

		for (; iter != headers.end(); ++iter) {
			cout << iter->first << ": " << iter->second << endl;
		}
	}

	// Extract ionic assertion from headers
	if (sAuthMethod.compare(authMethodString[ENROLL_EMAIL]) == 0) {
		cout << endl;
		cout << "A Registration Code has been sent to your email: " << sEmailAddress << endl;
		cout << "Enter Registration Code: ";
		getline(cin, sToken);
	} else {
		// This branch works for authenticating with either
		// Ionic authentication or SAML assertions
		sToken = httpResponse.getHeader("X-Ionic-Reg-Stoken");
		if (nVerbose >= 2) {
			cout << "STOKEN: " << sToken << endl;
		}
	}

	// Check Token
	if (sToken == "") {
		fatal(ISSET_ERROR_STOKEN_PARSE_FAILED,
				"Failed to extract 'sToken' from generated authentication response");
	}

	// Check API Url
	if (sApiUrl == "") {
		// API Url not specified in args:
		// Attempt to extract API Url from generated enrollment response
		sApiUrl = httpResponse.getHeader("X-Ionic-Reg-Ionic-Url");
		if (sApiUrl == "") {
			// Failed to extract API Url from generated enrollment response
			fatal(ISSET_ERROR_NO_API_URL,
					"Failed to extract 'api url' from generated authentication response & one wasn't specified in config arguments");
		}
	}

	// Check ES Pubkey Url
	if (sEsPubkeyUrl == "") {
		// Pubkey Url not specified in args:
		// Attempt to extract pubkey url from generated enrollment response
		sEsPubkeyUrl = httpResponse.getHeader(
				"X-Ionic-Reg-Pubkey-Url");

		if (sEsPubkeyUrl == "") {
			// Failed to extract ES Pubkey Url from generated enrollment response
			fatal(ISSET_ERROR_NO_PUBKEY_URL,
					"Failed to extract 'pubkey url' from generated authentication response & one wasn't specified in config arguments");
		}
	}

	// Extract UID Auth from headers
	sUidauth = httpResponse.getHeader("X-Ionic-Reg-Uidauth");
	if (sUidauth == "") {
		fatal(ISSET_ERROR_UIDAUTH_PARSE_FAILED,
				"Failed to extract 'Uidauth' from generated authentication response");
	}

	// debug
	if (nVerbose >= 1) {
		cout	<< LINE_LEAD << "Extracted sToken   : " << sToken	<< endl;
		cout	<< LINE_LEAD << "Extracted sUidauth : " << sUidauth	<< endl;
		cout	<< LINE_LEAD << "Pubkey URL         : " << sEsPubkeyUrl
				<< endl;
		cout	<< LINE_LEAD << "API URL            : " << sApiUrl	<< endl;
	}
}

void ISDevCliConfigCreate::getEnrollmentServicePublicKey(string & sEsPublicKeyBase64) {

	if (nVerbose >= 1) {
		cout	<< endl << "[+] Getting Enrollment Service Public Key"
				<< endl;
	}

	// create HTTP request
	ISHTTPRequest httpRequest;
	httpRequest.setMethod(HTTP_GET);
	httpRequest.setUrl(sEsPubkeyUrl);
	if (nVerbose >= 1) {
		cout	<< LINE_LEAD << "Making HTTP Request: GET " << sEsPubkeyUrl
				<< endl;
	}

	// send HTTP request
	ISHTTPResponse httpResponse;
	ISHTTP * pHttp = ISHTTPFactory::getInstance().createDefault();
	pHttp->send(httpRequest, httpResponse);
	int nHttpResponseCode = httpResponse.getResponseCode();
	if (nVerbose >= 1) {
		cout	<< LINE_LEAD << "Received HTTP Response: " << nHttpResponseCode
				<< endl;
	}
	if (nHttpResponseCode != HTTP_OK) {
		fatal(ISSET_ERROR_PUBKEY_REQUEST_FAILED,
				"HTTP request to enrollment service public key URL failed");
	}

	// extract pubkey from HTTP response
	ISHTTPData body = httpResponse.getBody();
	sEsPublicKeyBase64 = string((char*) body.getData(), body.getLen());
	sEsPublicKeyBase64.erase(
			remove(sEsPublicKeyBase64.begin(), sEsPublicKeyBase64.end(),
					'\n'), sEsPublicKeyBase64.end());
	sEsPublicKeyBase64.erase(
			remove(sEsPublicKeyBase64.begin(), sEsPublicKeyBase64.end(),
					'\r'), sEsPublicKeyBase64.end());
	if (nVerbose >= 1) {
		cout	<< LINE_LEAD << "Extracted PublicKey: " << sEsPublicKeyBase64
				<< endl;
	}
}

void ISDevCliConfigCreate::createIonicProfile(ISAgent * pAgent,
		string sTokenIn, string sUidauthIn,
		string sEsPublicKeyBase64In,
		ISAgentDeviceProfile & deviceProfileOut) {
	int nErr;

	if (nVerbose >= 1) {
		cout	<< endl << "[+] Creating Ionic Device Profile"
				<< endl;
		;
	}

	// create client ephemeral RSA keypair
	ISCryptoRsaKeyGenerator rsa;
	ISCryptoRsaPrivateKey clientRsaPrivateKey;
	ISCryptoRsaPublicKey clientRsaPublicKey;
	nErr = rsa.generatePrivateKey(3072, clientRsaPrivateKey);
	if (nErr != ISCRYPTO_OK) {
		fatal(ISSET_ERROR_EPHEMERAL_KEYPAIR_GENERATION_FAILED,
				"Failed to generate ephemeral private key");
	}
	nErr = rsa.generatePublicKey(clientRsaPrivateKey, clientRsaPublicKey);
	if (nErr != ISCRYPTO_OK) {
		fatal(ISSET_ERROR_EPHEMERAL_KEYPAIR_GENERATION_FAILED,
				"Failed to generate ephemeral public key");
	}

	// create device registration request
	ISAgentCreateDeviceRequest createDeviceRequest;
	createDeviceRequest.setToken(sTokenIn);
	createDeviceRequest.setUidAuth(sUidauthIn);
	createDeviceRequest.setETag(sKeyspace);
	createDeviceRequest.setServer(sApiUrl);
	createDeviceRequest.setEiRsaPublicKeyBase64(
			ISCryptoBase64String(sEsPublicKeyBase64In));
	createDeviceRequest.setClientRsaPublicKey(clientRsaPublicKey);
	createDeviceRequest.setClientRsaPrivateKey(clientRsaPrivateKey);

	if (sDeviceName == "") {
		if (bQuiet) {
			fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
				"Quiet mode must provide device-name for profile");
		} else {
			string deviceName = "";
			cout << "Create a name for this profile: " << endl;
			getline(cin, deviceName);
			createDeviceRequest.setDeviceProfileName(deviceName);
		}
	} else {
		createDeviceRequest.setDeviceProfileName(sDeviceName);
	}

	// send device registration request
	ISAgentCreateDeviceResponse createDeviceResponse;
	nErr = pAgent->createDevice(createDeviceRequest, createDeviceResponse);
	if (nErr != ISAGENT_OK) {
		if (nErr == ISAGENT_UNEXPECTEDRESPONSE) {
			fatal(ISSET_ERROR_DEVICE_REGISTRATION_FAILED,
				"Registration request to API server failed (Try verifying email)");
		} else {
			fatal(ISSET_ERROR_DEVICE_REGISTRATION_FAILED,
				"Registration request to API server failed");
		}
	}

	// extract device profile from registration response
	deviceProfileOut = createDeviceResponse.getDeviceProfile();
	if (nVerbose >= 1) {
		cout	<< LINE_LEAD << "DeviceId  : " << deviceProfileOut.getDeviceId()
				<< endl;
		cout	<< LINE_LEAD << "Server    : " << deviceProfileOut.getServer()
				<< endl;
	}
}

void ISDevCliConfigCreate::storeIonicProfile(ISAgent * pAgent,
		ISAgentDeviceProfile & deviceProfileIn) {
	int nErr;

	ISAgentDeviceProfilePersistor * pPersistor = NULL;
	if (nVerbose >= 1) {
		cout	<< endl << "[+] Storing Ionic Device Profile"
				<< endl
		;
		cout << "Device profile data: \n"
		<< "\n\tisLoaded: " << deviceProfileIn.isLoaded()
		<< "\n\tgetName: " << deviceProfileIn.getName()
		<< "\n\tgetCreationTimestampSecs: " << deviceProfileIn.getCreationTimestampSecs()
		<< "\n\tgetDeviceId: " << deviceProfileIn.getDeviceId()
		<< "\n\tgetKeySpace: " << deviceProfileIn.getKeySpace()
		<< "\n\tgetServer: " << deviceProfileIn.getServer()
		<< "\n\tgetAesCdIdcProfileKey: " << "Not showing IDCstring"
		<< "\n\tgetAesCdEiProfileKey: " << "Not showing EIstring"
		<<  endl;
	}

	// use plaintext persistor
	if (leadPersistor.sType == PERSISTOR_TYPE_PLAINTEXT) {
		if (nVerbose >= 1) {
			cout	<< LINE_LEAD << "Using plaintext persistor"
					<< endl
					<< endl
			;
		}
		pPersistor = new ISAgentDeviceProfilePersistorPlaintext();
		((ISAgentDeviceProfilePersistorPlaintext*) pPersistor)->setFilePath(
				leadPersistor.sPath);
	}

	// use password persistor
	if (leadPersistor.sType == PERSISTOR_TYPE_PASSWORD) {
		if (nVerbose >= 1) {
			cout	<< LINE_LEAD << "Using password persistor"
					<< endl
					<< endl
			;
		}
		pPersistor = new ISAgentDeviceProfilePersistorPassword();
		((ISAgentDeviceProfilePersistorPassword*) pPersistor)->setFilePath(
				leadPersistor.sPath);

		((ISAgentDeviceProfilePersistorPassword*) pPersistor)->setPassword(
				leadPersistor.sPassword);
	}

	// use aesgcm persistor
	if (leadPersistor.sType == PERSISTOR_TYPE_AESGCM) {
		if (nVerbose >= 1) {
			cout	<< LINE_LEAD << "Using aes persistor"
					<< endl
					<< endl
			;
		}

		string sAuthData = leadPersistor.sAesGcmAdata;
		ISCryptoBytes cbAuthData((byte*) sAuthData.data(), sAuthData.size());

		ISCryptoBytes cbPersistorKey;
		ISCryptoHexString chsPersistorKey = leadPersistor.sAesGcmKey;
		chsPersistorKey.toBytes(cbPersistorKey);

		pPersistor = new ISAgentDeviceProfilePersistorAesGcm();
		((ISAgentDeviceProfilePersistorAesGcm*) pPersistor)->setFilePath(
				leadPersistor.sPath);
		((ISAgentDeviceProfilePersistorAesGcm*) pPersistor)->setKey(
				cbPersistorKey);
		((ISAgentDeviceProfilePersistorAesGcm*) pPersistor)->setAuthData(
				cbAuthData);
	}

	// use default persistor
	if (leadPersistor.sType == PERSISTOR_TYPE_DEFAULT) {
		if (nVerbose >= 1) {
			cout	<< LINE_LEAD << "Using default persistor"
					<< endl
					<< endl
			;
		}

		if (sPlatform == PLATFORM_WINDOWS) {
#if defined(_WIN32) || defined(_WIN64)
			ISAgentDeviceProfilePersistorWindows* pWinPersistor = new ISAgentDeviceProfilePersistorWindows();
			if (leadPersistor.sVersion != "") {
				pWinPersistor->setFormatVersionOverride(leadPersistor.sVersion);
			}
			pPersistor = pWinPersistor;
			if (leadPersistor.sPath.empty()) {
				leadPersistor.sPath = pWinPersistor->getDefaultFilePath();
			}
#else
			fatal(ISSET_ERROR_INVALID_PERSISTOR,
					"Invalid state. Can not use Windows persistor on a non-Windows system");
#endif
		} else {
			pPersistor = new ISAgentDeviceProfilePersistorDefault();
		}
	}

	// verify persistor is not null (this should never happen)
	if (pPersistor == NULL) {
		fatal(ISSET_ERROR_INVALID_PERSISTOR,
				"CRITICAL ERROR. Persistor is NULL.");
	}

	// load any profiles that may already exist on the persistor
	nErr = pAgent->loadProfiles(*pPersistor);
	if (nErr != ISAGENT_OK) {
		fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
				"Failed to load profiles from existing persistor");
	}

	// save profile to persistor
	pAgent->addProfile(deviceProfileIn);
	if (bSetActive) {
		pAgent->setActiveProfile(deviceProfileIn.getDeviceId());
	}

	// Before we try to have the SDK save the profiles
	//   We have to confirm the path to the persistor file Exists
	//   OR we have to create that missing path
	fs::path p = leadPersistor.sPath;
	// if parent_path is empty then file will be saved in current directory
	if (p.parent_path().empty() == false) {
		if (!fs::exists(p.parent_path())) {
			if (!fs::create_directories(p.parent_path())) {
				fatal(ISSET_ERROR_PERSISTOR_SAVE_FAILED,
						"Unable to create missing directories in path of persistor file\n" + p.parent_path().string());
			}
		}
	}

	// Path OK so save the Profile(s)
	nErr = pAgent->saveProfiles(*pPersistor);
	if (nErr != ISAGENT_OK) {
		fatal(ISSET_ERROR_PERSISTOR_SAVE_FAILED,
				"Failed to save profiles to persistor");
	}

	cout	<< "[SUCCESS] Saved ionic profile "
			<< deviceProfileIn.getDeviceId()
			<< endl
	;
}
