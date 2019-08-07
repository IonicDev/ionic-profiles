/* Copyright 2018-2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <sstream>

#include "ISDevCliConfigShow.h"
#include "ISDevUtils.h"
#include "ISEnrollmentError.h"


void ISDevCliConfigShow::printUsageHeader() {
	cout << PROFILES_SHOW_DESCRIPTION << endl;
	ISDevCliConfig::printUsageHeader();
}


// Invoke the specific function for the Show action
void ISDevCliConfigShow::invokeAction(ISAgent *pAgent) {
	showActiveProfile(pAgent);
}


// Show current active profile for a given type of persistor in a given persistor path
void ISDevCliConfigShow::showActiveProfile(ISAgent *pAgent) {

	// Initialize the agent for the according Persistor for this type and path
	std::unique_ptr<ISAgentDeviceProfilePersistor> persistor = initWithPersistor(pAgent, leadPersistor);
	if (persistor == nullptr) {
		fatal(ISSET_ERROR_INVALID_PERSISTOR,
				"[!FATAL] Invalid type of Persistor; failed to initialize Ionic Agent.");
	}

	cout << "---> Getting the current active profile" << endl;

	// Show active profile specs
	if (pAgent->hasActiveProfile()) {
		const ISAgentDeviceProfile activeProfile = pAgent->getActiveProfile();
		string profileName = activeProfile.getName();
		string deviceId = activeProfile.getDeviceId();
		string serverName = activeProfile.getServer();

		cout << "Name: " << profileName << endl;
		cout << "DeviceId: " << deviceId << endl;
		cout << "Server: " << serverName << endl;
	} else {
		cout << "There are no active profiles. You can set an active profile using the set option.\n"
			"If you need to create a profile, use the create option. You can see all of your existing "
			"profiles with the list option." << endl;
	}
}
