/* Copyright 2018-2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <sstream>

#include "ISDevCliConfigConvert.h"

#include "ISDevUtils.h"
#include "ISEnrollmentError.h"
#include "Confirmation.h"

#include "boost/filesystem.hpp"
namespace fs = boost::filesystem;


void ISDevCliConfigConvert::printConfigBody() {

	ISDevCliConfigSet::printConfigBody();

	cout	<< LINE_LEAD << PROFILE_OPTION_TARGET_PERSISTOR << "       "
			<< COLON_SPACE << targetPersistor.sType
			<< endl;
	cout	<< LINE_LEAD << PROFILE_OPTION_TARGET_PERSISTOR_PATH << "  "
			<< COLON_SPACE << targetPersistor.sPath
			<< endl;

	if (targetPersistor.sType.compare(PERSISTOR_TYPE_PASSWORD) == 0) {
		cout	<< LINE_LEAD << PROFILE_OPTION_TARGET_PERSISTOR_PASSWORD << " "
				<< COLON_SPACE << targetPersistor.sPassword
				<< endl;
	}

	if (targetPersistor.sType.compare(PERSISTOR_TYPE_AESGCM) == 0) {
		cout	<< LINE_LEAD << PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_KEY << " "
				<< COLON_SPACE << targetPersistor.sAesGcmKey
				<< endl;
		cout	<< LINE_LEAD << PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_ADATA << " "
				<< COLON_SPACE << targetPersistor.sAesGcmAdata
				<< endl;
	}
}

void ISDevCliConfigConvert::getConfigFromFile() {

	// Parse base config file
	ISDevCliConfig::getConfigFromFile();

	// Check if Target Config File defined
	if (vm.count(PROFILE_OPTION_TARGET_CONFIG) == 0) {
		return;
	}

	// Parse target config file
	string sTargetConfigFilePath = vm[PROFILE_OPTION_TARGET_CONFIG].as<string>();
	parseConfigFile(sTargetConfigFilePath);

	// extract configs
	boost::optional<string> op;

	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_TARGET_PERSISTOR))) {
		targetPersistor.sType = *op;
	}
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_TARGET_PERSISTOR_PATH))) {
		targetPersistor.sPath = *op;
	}
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_TARGET_PERSISTOR_PASSWORD))) {
		targetPersistor.sPassword = *op;
	}
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_KEY))) {
		targetPersistor.sAesGcmKey = *op;
	}
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_ADATA))) {
		targetPersistor.sAesGcmAdata = *op;
	}
}

void ISDevCliConfigConvert::getConfigFromCommandLine() {
	ISDevCliConfigSet::getConfigFromCommandLine();

	if (vm.count(PROFILE_OPTION_TARGET_PERSISTOR)) {
		targetPersistor.sType = vm[PROFILE_OPTION_TARGET_PERSISTOR].as<string>();
	}
	if (vm.count(PROFILE_OPTION_TARGET_PERSISTOR_PATH)) {
		targetPersistor.sPath = vm[PROFILE_OPTION_TARGET_PERSISTOR_PATH].as<string>();
	}
	if (vm.count(PROFILE_OPTION_TARGET_PERSISTOR_PASSWORD)) {
		targetPersistor.sPassword = vm[PROFILE_OPTION_TARGET_PERSISTOR_PASSWORD].as<string>();
	}
	if (vm.count(PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_KEY)) {
		targetPersistor.sAesGcmKey = vm[PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_KEY].as<string>();
	}
	if (vm.count(PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_ADATA)) {
		targetPersistor.sAesGcmAdata =
				vm[PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_ADATA].as<string>();
	}
}

void ISDevCliConfigConvert::printUsageHeader() {
	cout << PROFILES_CONVERT_DESCRIPTION << endl;
	ISDevCliConfig::printUsageHeader();
	cout << "  " << TARGET_CONFIG_PATH_USAGE;
}

void ISDevCliConfigConvert::printUsagePersistor() {
	ISDevCliConfigSet::printUsagePersistor();

	cout << "\t" << PROFILES_USAGE_TARGET_PERSISTOR_LINE1 << endl;
	cout << "\t" << PROFILES_USAGE_TARGET_PERSISTOR_LINE2 << endl;
}

void ISDevCliConfigConvert::buildOptions() {
	ISDevCliConfigSet::buildOptions();

	target_config_options_list.add_options()
		(PROFILE_OPTION_TARGET_CONFIG, po::value<string>(),
			"path to target config file\n")
	;

	target_persistor_options_list.add_options()
		(PROFILE_OPTION_TARGET_PERSISTOR,
			po::value<string>(),
			"Convert output profile persistor type\n(plaintext, password, aesgcm, default) 'default' if none given\n")
		(PROFILE_OPTION_TARGET_PERSISTOR_PATH, po::value<string>(),
			"Convert output path to target profile\n")
		(PROFILE_OPTION_TARGET_PERSISTOR_PASSWORD,
			po::value<string>()->implicit_value(""),
			"Convert output password to use to protect a 'password' persistor. \n"
			"Only applicable if '--target-persistor' is set to 'password'\n ")
		(PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_KEY, po::value<string>(),
			"Convert output hex-encoded AES-256 key used to protect an 'aesgcm' persistor. \n"
			"Only applicable if '--target-persistor' is set to 'aesgcm'.\n")
		(PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_ADATA, po::value<string>(),
			"Convert output authentication data used when encrypting an 'aesgcm' persistor.\n"
			"Only applicable if '--target-persistor' is set to 'aesgcm'.\n")
	;

}

void ISDevCliConfigConvert::buildOptionsList() {
	usage.add(config_options_list)
		.add(target_config_options_list)
		.add(device_id_options_list)
		.add(persistor_options_list)
		.add(target_persistor_options_list)
		.add(miscellaneous_options_list)
	;
}

void ISDevCliConfigConvert::validateConfig() {

	// 'Convert'-specific checks

	// Note: Skip past ISDevCliConfigSet::validateConfig since device id doesn't need to be defined
	ISDevCliConfig::validateConfig();

	validatePersistor(&targetPersistor);

}

// Invoke the specific function for the Convert action
void ISDevCliConfigConvert::invokeAction(ISAgent *pAgent) {
	convertProfiles(pAgent);
}

// Set up for conversion of profile persistor type for a given profile in a given path
void ISDevCliConfigConvert::convertProfiles(ISAgent *pAgent) {

	// Initialize the agent and retrieve Persistor for the according type and path
	std::unique_ptr<ISAgentDeviceProfilePersistor> persistor = initWithPersistor(pAgent, leadPersistor);
	if (persistor == nullptr) {
		fatal(ISSET_ERROR_INVALID_PERSISTOR,
			"[!FATAL] Invalid type of Persistor; failed to initialize Ionic Agent.");
	}

	cout << "---> Loading profiles in '" << leadPersistor.sType
			<< "' Persistor in '" << leadPersistor.sPath << "'" << endl;

	// check if file exists
	if ((leadPersistor.sPath.empty()) || !fs::exists(leadPersistor.sPath)) {
		//error on no file
		fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
			"[!FATAL] Convert profile could not find file for source Persistor type (" +
			leadPersistor.sType + ") in given path (" +
			leadPersistor.sPath +
			"). Check persistor-path.");
	}

	// Get a vector of profiles for this persistor at this path
	vector<ISAgentDeviceProfile> vecProfilesOut;
	string sActiveDeviceIdOut;
	int nErr = persistor->loadAllProfiles(vecProfilesOut, sActiveDeviceIdOut);
	if (nErr != ISAGENT_OK) {
		fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
			"[!FATAL] Failed to load profiles.");
	}

	if (vecProfilesOut.empty()) {
		fatal(ISSET_ERROR_INVALID_PERSISTOR,
			"[!FATAL] There are no profiles of that Persistor type.");
	}

	// See if the given file already exists
	ifstream infile(targetPersistor.sPath);
	if (infile.good()) {
		ostringstream stringStream;
		stringStream << "Target path ("
				<< targetPersistor.sPath
				<< ") already exists. Are you sure you want to modify this file?";

		if ((!bQuiet) && (!question_yesno(stringStream.str()))) {
			cout << "Okay, did NOT convert any profiles." << endl;
			return;
		}
	}
	infile.close();

	convertHelper(vecProfilesOut, sActiveDeviceIdOut);
}

void ISDevCliConfigConvert::persistorPathFixer() {
	// use default persistor
	if (targetPersistor.sType == PERSISTOR_TYPE_DEFAULT) {
		if (nVerbose >= 1) {
			cout << LINE_LEAD << "Using default persistor" << endl << endl;
		}

		if (sPlatform == PLATFORM_WINDOWS) {
#if defined(_WIN32) || defined(_WIN64)
			ISAgentDeviceProfilePersistorWindows* pWinPersistor = new ISAgentDeviceProfilePersistorWindows();
			if (targetPersistor.sVersion != "") {
				pWinPersistor->setFormatVersionOverride(targetPersistor.sVersion);
			}
			if (targetPersistor.sPath.empty()) {
				targetPersistor.sPath = pWinPersistor->getDefaultFilePath();
			}
#else
			fatal(ISSET_ERROR_INVALID_PERSISTOR,
					"Invalid state. Can not use Windows persistor on a non-Windows system");
#endif
		}
	}

	// Before we try to have the SDK save the profiles
	//   We have to confirm the path to the persistor file Exists
	//   OR we have to create that missing path
	fs::path p = targetPersistor.sPath;
	// if parent_path is empty then file will be saved in current directory
	if (p.parent_path().empty() == false) {
		if (!fs::exists(p.parent_path())) {
			if (!fs::create_directories(p.parent_path())) {
				fatal(ISSET_ERROR_PERSISTOR_SAVE_FAILED,
						"Unable to create missing directories in path of persistor file\n"
								+ p.parent_path().string());
			}
		}
	}
}

// Helper function to convert profile persistor type
// Uses information gathered in convertProfiles()
void ISDevCliConfigConvert::convertHelper(
		vector<ISAgentDeviceProfile>& vecProfilesOut,
		string sActiveDeviceIdOut) {

	// Convert the profiles
	// Initialize new agent and retrieve new Persistor to convert to
	ISAgent *pAgent = new ISAgent();
	std::unique_ptr<ISAgentDeviceProfilePersistor> persistor = initWithPersistor(pAgent, targetPersistor);
	int nErr;

	// See which device profile to convert or ALL device profiles
	if (sDeviceId == "") {
		ostringstream stringStream;
		stringStream << "Are you sure you want to convert "
				<< vecProfilesOut.size()
				<< " profiles? You will not lose their"
						" original versions as you long as you do not override their file path.";

		if ((bQuiet) || (question_yesno(stringStream.str()))) {

			persistorPathFixer();

			cout << "Converting all profiles to '" << targetPersistor.sType
					<< "' Persistor in '" << targetPersistor.sPath << "'"
					<< endl;
			// Save all profiles into the new persistor
			nErr = persistor->saveAllProfiles(vecProfilesOut,
					sActiveDeviceIdOut);
			if (nErr != ISAGENT_OK) {
				fatal(ISSET_ERROR_PERSISTOR_SAVE_FAILED,
					"[!FATAL] Failed to save profiles into Persistor.");
			}

			// Load profiles from persistor to agent
			nErr = pAgent->loadProfiles(*persistor);
			if (nErr != ISAGENT_OK) {
				fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
					"[!FATAL] Failed to load profiles from Persistor.");
			}
		} else {
			cout << "Okay, did NOT convert any profiles." << endl;
			return;
		}
	} else {
		cout << "Converting profile with ID '" << sDeviceId
				<< "' to '" << targetPersistor.sType << "' Persistor in '"
				<< targetPersistor.sPath << "'" << endl;

		// Retrieve the profile according to this Device Id
		ISAgentDeviceProfile *profileToConvert = nullptr;
		for (vector<ISAgentDeviceProfile>::size_type i =
				vecProfilesOut.size() - 1;
				i != (vector<ISAgentDeviceProfile>::size_type) -1; i--) {
			if (sDeviceId.compare(vecProfilesOut[i].getDeviceId())
					== 0) {
				profileToConvert = new ISAgentDeviceProfile(vecProfilesOut[i]);
				break;
			}
		}

		// Make sure we found a/the right profile
		if ((profileToConvert == nullptr)
				|| (profileToConvert->getDeviceId().compare(sDeviceId) != 0)) {
			fatal(ISSET_ERROR_PERSISTOR_SAVE_FAILED,
				"[!FATAL] Could not find a profile with that ID.");
		}

		// Add the profile to the agent that had been initialized with new persistor
		pAgent->addProfile(*profileToConvert);
	}

	persistorPathFixer();

	// Save changes
	nErr = pAgent->saveProfiles(*persistor);

	if (nErr != ISAGENT_OK) {
		fatal(ISSET_ERROR_PERSISTOR_SAVE_FAILED,
			"[!FATAL] Failed to save conversion changes to profiles.");
	}

	cout << "[SUCCESS] Converted profile(s) to " << targetPersistor.sType
			<< " in file: " << targetPersistor.sPath << endl;
}
