/* Copyright 2018 - 2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <sstream>

#include "ISDevCliConfigDelete.h"

#include "ISDevUtils.h"
#include "ISEnrollmentError.h"
#include "Confirmation.h"

#include "boost/filesystem.hpp"
namespace fs = boost::filesystem;


void ISDevCliConfigDelete::printUsageHeader() {
	cout << PROFILES_DELETE_DESCRIPTION << endl;
	ISDevCliConfig::printUsageHeader();
}

void ISDevCliConfigDelete::printUsagePersistor() {
	ISDevCliConfigSet::printUsagePersistor();
}

void ISDevCliConfigDelete::validateConfig() {

	// 'Set/Delete'-specific checks

	// Device-ID required
	if (sDeviceId == "") {
		fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
				"You must provide the device ID you wish to remove.\n"
				"Use the list option to see all of your device IDs.");
	}

	// keep after 'Delete'-specific checks
	ISDevCliConfig::validateConfig();

}

// Invoke the specific function for the Delete action
void ISDevCliConfigDelete::invokeAction(ISAgent *pAgent) {
	removeProfile(pAgent);
}

// Remove specified profile of a given type of persistor in a given persistor path
void ISDevCliConfigDelete::removeProfile(ISAgent *pAgent) {

	// Initialize the agent and retrieve Persistor for the according type and path
	std::unique_ptr<ISAgentDeviceProfilePersistor> persistor = initWithPersistor(pAgent, leadPersistor);
	if (persistor == nullptr) {
		fatal(ISSET_ERROR_INVALID_PERSISTOR,
				"[!FATAL] Invalid type of Persistor; failed to initialize Ionic Agent.");
	}

	cout	<< "---> Finding Device Profile with ID: " << sDeviceId
			<< endl;

	// Remove profile. Note: if this profile was the active profile, the user no longer has a current active profile.
	//  They must set a new current active profile.
	cout	<< "You are about to delete the profile with ID: "
			<< sDeviceId << endl;
	string activeId = pAgent->getActiveProfile().getDeviceId();
	if (activeId.compare(sDeviceId) == 0) {
		cout
				<< "This is currently the active profile device.\n"
					"If you delete it, you must use the set option to set a new active profile from existing profiles"
					" shown in the list option or from a new profile created with the create option."
				<< endl;
	}
	if ((bQuiet) || (question_yesno("Are you sure?"))) {
		if (pAgent->removeProfile(sDeviceId)) {
			int nErr = pAgent->saveProfiles(*persistor);
			if (nErr != ISAGENT_OK) {
				fatal(ISSET_ERROR_PERSISTOR_SAVE_FAILED,
					"[!FATAL] Failed to save deletion changes to profiles.");
			}
			cout	<< "[SUCCESS] Found profile with ID: " << sDeviceId
					<< " and deleted it." << endl;
		} else {
			// check if file exists
			if (!fs::exists(leadPersistor.sPath)) {
				//error on no file
				fatal(ISSET_ERROR_PERSISTOR_SAVE_FAILED,
					"[!FATAL] Delete profile could not find file for given Persistor type (" +
					leadPersistor.sType + ") in given path (" +
					leadPersistor.sPath +
					"). Check persistor-path.");
			} else {
				// error on deviceId
				fatal(ISSET_ERROR_DEVICE_ID_NOTFOUND,
					"[!FATAL] Delete profile could not find a profile of given Persistor type (" +
					leadPersistor.sType + ") with given device ID (" +
					sDeviceId + ") in given path (" +
					leadPersistor.sPath +
					").\n Use the list option to view your existing profiles.");
			}
		}
	} else {
		cout	<< "Okay, did NOT delete profile with ID: "
				<< sDeviceId << endl;
	}
}
