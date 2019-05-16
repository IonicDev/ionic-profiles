/* Copyright 2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <sstream>

#include "ISDevCliConfigSet.h"

#include "ISDevUtils.h"
#include "ISEnrollmentError.h"

#include "boost/filesystem.hpp"
namespace fs = boost::filesystem;


void ISDevCliConfigSet::printConfigBody() {
	cout	<< LINE_LEAD << PROFILE_OPTION_DEVICE_ID << "              "
			<< COLON_SPACE << sDeviceId
			<< endl;

	ISDevCliConfig::printConfigBody();
}


/*  FYI: We don't want PROILE_OPTION_DEVICE_ID from config file,
 *  everything else we need is captured from base class ISDevCliConfig
 *  so no getConfigFromFile
*/


void ISDevCliConfigSet::getConfigFromCommandLine() {
	ISDevCliConfig::getConfigFromCommandLine();

	if (vm.count(PROFILE_OPTION_DEVICE_ID)) {
		sDeviceId = vm[PROFILE_OPTION_DEVICE_ID].as<string>();
	}
}

void ISDevCliConfigSet::printUsageHeader() {
	cout << PROFILES_SET_DESCRIPTION << endl;
	ISDevCliConfig::printUsageHeader();
}

void ISDevCliConfigSet::printUsagePersistor() {
	cout << "\t" << DEVICE_ID_USAGE << endl;
	ISDevCliConfig::printUsagePersistor();
}

void ISDevCliConfigSet::buildOptions() {
	ISDevCliConfig::buildOptions();

	device_id_options_list.add_options()
		(PROFILE_OPTION_DEVICE_ID, po::value<std::string>(),
			"Device ID of profile for operation\n")
	;
}

void ISDevCliConfigSet::buildOptionsList() {
	usage.add(config_options_list)
		.add(device_id_options_list)
		.add(persistor_options_list)
		.add(miscellaneous_options_list)
	;
}

void ISDevCliConfigSet::validateConfig() {

	ISDevCliConfig::validateConfig();

	// 'Set/Delete'-specific checks

	// Device-ID required
	if (sDeviceId == "") {
		fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
				"You must provide the device ID you wish to make active.\n"
				"Use the list option to see all of your device IDs.");
	}

}

// Invoke the specific function for the Set action
void ISDevCliConfigSet::invokeAction(ISAgent *pAgent) {
	setActiveProfile(pAgent);
}


// Set active profile for a given type of persistor in a given persistor path
void ISDevCliConfigSet::setActiveProfile(ISAgent *pAgent) {

	// Initialize the agent and retrieve Persistor for the according type and path
	ISAgentDeviceProfilePersistor *persistor = initWithPersistor(pAgent, leadPersistor);
	if (persistor == nullptr) {
		delete(persistor); // Heap alloc in abstracted function
		fatal(ISSET_ERROR_INVALID_PERSISTOR,
			"[!FATAL] Invalid type of Persistor; failed to initialize Ionic Agent.");
	}

	cout	<< "---> Finding Device Profile with ID: " << sDeviceId
			<< endl;

	// Set the current active profile
	if (pAgent->setActiveProfile(sDeviceId)) {
		int nErr = pAgent->saveProfiles(*persistor);
		if (nErr != ISAGENT_OK) {
			fatal(ISSET_ERROR_PERSISTOR_SAVE_FAILED,
					"[!FATAL] Failed to save active profile changes to profiles.");
		}
		cout	<< "[SUCCESS] Set profile with ID: " << sDeviceId
				<< " as current active device profile." << endl;
	} else {
		// check if file exists
		if (!fs::exists(leadPersistor.sPath)) {
			//error on no file
			fatal(ISSET_ERROR_PERSISTOR_SAVE_FAILED,
				"[!FATAL] Set active profile could not find file for given Persistor type (" +
				leadPersistor.sType + ") in given path (" +
				leadPersistor.sPath +
				"). Check persistor-path.");
		} else {
			// error on deviceId
			fatal(ISSET_ERROR_DEVICE_ID_NOTFOUND,
				"[!FATAL] Set active profile could not find a profile of given Persistor type (" +
				leadPersistor.sType + ") with given device ID (" +
				sDeviceId + ") in given path (" +
				leadPersistor.sPath +
				").\n Use the list option to view your existing profiles.");
		}
	}

	delete(persistor);		  // Heap alloc in abstracted function

}
