/* Copyright 2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <sstream>

#include "ISHTTP.h"
#include "URICoding.h"

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

	if (vm.count(PROFILE_OPTION_KEYSPACE)) {
		sKeyspace = vm[PROFILE_OPTION_KEYSPACE].as<string>();
	}
	if (vm.count(PROFILE_OPTION_ASSERTION_FILEPATH)) {
		sAssertionFilePath = vm[PROFILE_OPTION_ASSERTION_FILEPATH].as<string>();
	}
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
	if (vm.count(PROFILE_OPTION_DEVICE_NAME)) {
		sDeviceName = vm[PROFILE_OPTION_DEVICE_NAME].as<string>();
	}
	if (vm.count(PROFILE_OPTION_SET_ACTIVE)) {
		bSetActive = vm[PROFILE_OPTION_SET_ACTIVE].as<bool>();
	} else if (vm.count(PROFILE_OPTION_SET_ACTIVE_CAPA)) {  // deprecated setActive
		bSetActive = vm[PROFILE_OPTION_SET_ACTIVE_CAPA].as<bool>();
	}

	if (sAuthMethod.compare(authMethodString[ENROLL_ASSERT]) == 0
			&& vm.count(PROFILE_OPTION_ASSERTION_FILEPATH)) {
		sAssertionFilePath =
				vm[PROFILE_OPTION_ASSERTION_FILEPATH].as<string>();
		sAssertionData = getAssertionFromFile(
				sAssertionFilePath);
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
	cout << "\t" << PROFILES_DEVICE_NAME_LINE;
	if (nProfileCommand == PROFILE_COMMAND_CREATE) {
		cout << " "  << PROFILES_SET_ACTIVE_LINE;
	}
	cout << endl;

	ISDevCliConfig::printUsageEnd();

}

void ISDevCliConfigCreate::buildOptions() {
	ISDevCliConfig::buildOptions();

	auth_options_list.add_options()
		(PROFILE_OPTION_AUTH_METHOD, po::value<string>(),
			"authentication method \n(email, assertion)\n")
		(PROFILE_OPTION_ENROLLMENT_METHOD, po::value<string>(),
			"DEPRECATED: authentication method \n(email, assertion)\n")
	;

	keyspace_options_list.add_options()
		(PROFILE_OPTION_KEYSPACE, po::value<string>(),
			"keyspace for enrollment\n")
		(PROFILE_OPTION_ASSERTION_FILEPATH, po::value<string>(),
			"path to assertion file for enrollment\n")
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
		.add(device_name_options_list)
		.add(set_active_options_list)
		.add(miscellaneous_options_list)
	;
}

void ISDevCliConfigCreate::validateConfig() {

	ISDevCliConfig::validateConfig();

	// 'Create'-specific checks

	if (sKeyspace == "") {
		fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
				"Missing arg: '" + (string)PROFILE_OPTION_KEYSPACE + "'");
	}
	// If assertion method, assertion file is required
	if (sAuthMethod.compare(authMethodString[ENROLL_ASSERT]) == 0) {
		if (sEsGenAssnUrl == "") {
			fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
					"Missing arg: '" + (string)PROFILE_OPTION_ES_URL + "'");
		}
		if (sAssertionFilePath == "") {
			fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
					"Missing arg: '" + (string)PROFILE_OPTION_ASSERTION_FILEPATH + "'");
		}
		if (sAssertionData == "") {
			fatal(ISSET_ERROR_ASSERTIONFILE_LOAD_FAILED,
					"Failed to load assertion data");
		}
	}

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
				"Failed to load assertion file");
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
	getIonicAuthentication(sToken, sUidauth);
	if (nVerbose >= 1) {
		cout << LINE_LEAD << "Ionic Authentication: " << sUidauth << endl;
	}

	getEnrollmentServicePublicKey(sEsPublicKeyBase64);
	createIonicProfile(pAgent, sToken, sUidauth, sEsPublicKeyBase64,
			deviceProfile);
	storeIonicProfile(pAgent, deviceProfile);

	ISAgentGetResourcesRequest::Resource reqIn =
			ISAgentGetResourcesRequest::Resource();
	ISAgentGetResourcesResponse* responseOut =
			new ISAgentGetResourcesResponse();
	int result = pAgent->getResource(reqIn, *responseOut);
	int result2 = pAgent->getResource(reqIn, *responseOut);

	if (result != ISAGENT_OK && result2 != ISAGENT_OK) {
		fatal(ISSET_ERROR_CONFIRMATION_FAILED,
				"Failed to confirm functional new registration.");
	}
}

string ISDevCliConfigCreate::emailRequestBody() {
	string sEmailAddress;

	cout << "\nEnter email address: ";
	getline(cin, sEmailAddress);

	return "email=" + UriEncode(sEmailAddress);
}

string ISDevCliConfigCreate::samlRequestBody() {
	return "SAMLResponse=" + UriEncode(sAssertionData);
}

void ISDevCliConfigCreate::getIonicAuthentication(string & sToken,
		string & sUidauth) {

	if (nVerbose >= 1) {
		cout	<< endl
				<< "[+] Getting Ionic Auth from Enrollment Service"
				<< endl
		;
	}

	// Check ES Url
	while (sEsGenAssnUrl == "") {
		if (bQuiet) {
			// Quiet Mode: Report error missing required ES Url arg
			fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
				"Quiet mode: Unable to complete request, please provide es-url setting the appropriate enrollment URL");
		} else {
			// Interactive Mode: Request User enter ES Url
			cout << "Please provide the appropriate enrollment URL: " << endl;
			getline(cin, sEsGenAssnUrl);
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
		cout << "\nA Registration Code has been sent to your email.";
		cout << "\nEnter Registration Code: ";
		getline(cin, sToken);
	} else {
		//
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
