/* Copyright 2018-2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <sstream>

#include "ISDevCliConfigList.h"

#include "ISDevUtils.h"
#include "ISEnrollmentError.h"


void ISDevCliConfigList::printUsageHeader() {
	cout << PROFILES_LIST_DESCRIPTION << endl;
	ISDevCliConfig::printUsageHeader();
}

// Invoke the specific function for the List action
void ISDevCliConfigList::invokeAction(ISAgent *pAgent) {
	listAllProfiles();
}

// List all profiles for a given type of persistor in a given persistor path
void ISDevCliConfigList::listAllProfiles() {

	// Get a vector of profiles for this persistor at this path. In
	// the case of a default persistor, leadPersistor.sType does
	// not name the persistor file and is left out of the status
	// message.
	if (leadPersistor.sPath.empty()) {
		cout	<< "---> Getting profiles in '"	<<	leadPersistor.sType
			<< "' Persistor"
			<< endl;
	}
	else {
		cout	<< "---> Getting profiles in '"	<<	leadPersistor.sType
			<< "' Persistor in file '"	<<	leadPersistor.sPath	<<	"'"
			<< endl;
	}
	vector<ISAgentDeviceProfile> vecProfilesOut = getVector();

	if (vecProfilesOut.empty()) {
		cout << "No profiles were found of the requested persistor type." << endl;
		exit(0);
	} else {
		// For each profile, show its name, deviceId, and server name
		for (vector<ISAgentDeviceProfile>::size_type i =
				vecProfilesOut.size() - 1;
				i != (std::vector<ISAgentDeviceProfile>::size_type) -1; i--) {
			string profileName = vecProfilesOut[i].getName();
			string deviceId = vecProfilesOut[i].getDeviceId();
			string serverName = vecProfilesOut[i].getServer();

			cout	<<	"Name: "		<< profileName	<< endl;
			cout	<<	"DeviceId: "	<< deviceId		<< endl;
			cout	<<	"Server: "		<< serverName	<< endl;
		}
		// For readability...
		cout	<<	endl;
	}
}

// Load profiles by respective Persistor into a vector
// Return vector of profiles; return empty vector if:
// (1) invalid type of persistor... bad user input, OR
// (2) the user has no profiles for that type of persistor in that filepath
vector<ISAgentDeviceProfile> ISDevCliConfigList::getVector() {
	vector<ISAgentDeviceProfile> vecProfilesOut;
	string sActiveDeviceIdOut;

	if (leadPersistor.sType.compare(PERSISTOR_TYPE_DEFAULT) == 0) { // Default Persistor
		// Persistor config
		ISAgentDeviceProfilePersistorDefault defaultPersistor;

		// Load profiles into vector
		int nErr = defaultPersistor.loadAllProfiles(vecProfilesOut,
				sActiveDeviceIdOut);
		if (nErr != ISAGENT_OK) {
			fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
				"[!FATAL] Failed to load profiles.");
		}

		// Newlines for readability...
		cout << endl << "Number of Default Persistor profiles: "
				<< vecProfilesOut.size() << endl << endl;

	} else if (leadPersistor.sType.compare(PERSISTOR_TYPE_PLAINTEXT) == 0) { // Plaintext Persistor
		// Persistor config
		ISAgentDeviceProfilePersistorPlaintext plaintextPersistor;
		plaintextPersistor.setFilePath(leadPersistor.sPath);

		// Load profiles into vector
		int nErr = plaintextPersistor.loadAllProfiles(vecProfilesOut,
				sActiveDeviceIdOut);
		if (nErr != ISAGENT_OK) {
			fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
				"[!FATAL] Failed to load profiles.");
		}

		// Newlines for readability...
		cout << endl << "Number of Plaintext Persistor profiles: "
				<< vecProfilesOut.size() << endl << endl;

	} else if (leadPersistor.sType.compare(PERSISTOR_TYPE_PASSWORD) == 0) { // Password Persistor
		// Persistor config
		ISAgentDeviceProfilePersistorPassword passwordPersistor;
		passwordPersistor.setPassword(leadPersistor.sPassword);
		passwordPersistor.setFilePath(leadPersistor.sPath);

		// Load profiles into vector
		int nErr = passwordPersistor.loadAllProfiles(vecProfilesOut,
				sActiveDeviceIdOut);
		if (nErr != ISAGENT_OK) {
			fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
					"[!FATAL] Failed to load profiles.");
		}

		// Newlines for readability...
		cout	<< endl << "Number of Password Persistor profiles: "
				<< vecProfilesOut.size() << endl << endl;

	} else if (leadPersistor.sType.compare(PERSISTOR_TYPE_AESGCM) == 0) { // AesGcm Persistor
		// Persistor config
		ISAgentDeviceProfilePersistorAesGcm AesGcmPersistor;
		string authData = leadPersistor.sAesGcmAdata;
		ISCryptoBytes cbAuthData((byte*) authData.data(), authData.size());
		ISCryptoBytes cbPersistorKey;
		ISCryptoHexString chsPersistorKey = leadPersistor.sAesGcmKey;
		chsPersistorKey.toBytes(cbPersistorKey);

		AesGcmPersistor.setKey(cbPersistorKey);
		AesGcmPersistor.setAuthData(cbAuthData);
		AesGcmPersistor.setFilePath(leadPersistor.sPath);

		// Load profiles into vector
		int nErr = AesGcmPersistor.loadAllProfiles(vecProfilesOut,
				sActiveDeviceIdOut);
		if (nErr != ISAGENT_OK) {
			fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
					"[!FATAL] Failed to load profiles.");
		}
		cout	<< endl << "Number of AesGcm Persistor profiles: "
				<< vecProfilesOut.size() << endl << endl;

	} else {
		return vecProfilesOut;
	}

	return vecProfilesOut;
}

