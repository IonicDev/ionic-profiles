/* Copyright 2017-2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <sstream>

#include "version.h"

#include "ISDevCliConfig.h"
#include "ISDevUtils.h"
#include "ISEnrollmentError.h"

#include "boost/filesystem.hpp"
namespace fs = boost::filesystem;


const char *const PROFILES_USAGE_COMMANDS_STRING		=
	"[[create] | list  | show | set | convert | delete | validate-assertion]";
const char *const PROFILES_USAGE_PERSISTOR_LINE1		=
	"[--persistor <PERSISTOR>] [--persistor-path <PATH>] [--persistor-password <PASSWORD>]";
const char *const PROFILES_USAGE_PERSISTOR_LINE2		=
	"[--persistor-aesgcm-key <KEY>] [--persistor-aesgcm-adata <AUTHDATA>]";
const char *const PROFILES_USAGE_PERSISTOR_LINE3		=
	"[--persistor-version <VERSION>]";
const char *const PROFILES_USAGE_MISCELLANEOUS_STRING	=
	"[--verbose <LEVEL>] [--quiet] [--help] [--version]";

const char *const PROFILES_COMMAND_HELP_STRING =
	"\tionic-profiles [create] - Create a profile - DEFAULT \
	\n\t\tsee ionic-profiles create --help for options \
	\n\n\tionic-profiles list - Display a list of profiles \
	\n\t\tsee ionic-profiles list --help for options \
	\n\n\tionic-profiles show - Show active profile \
	\n\t\tsee ionic-profiles show --help for options \
	\n\n\tionic-profiles set - Set active profile \
	\n\t\tsee ionic-profiles set --help for options \
	\n\n\tionic-profiles convert - Convert profile from one persistor type to another \
	\n\t\tsee ionic-profiles convert --help for options \
	\n\n\tionic-profiles delete - Delete a profile \
	\n\t\tsee ionic-profiles delete --help for options \
	\n\n\tionic-profiles validate-assertion - Validate an assertion file \
	\n\t\tsee ionic-profiles validate-assertion --help for options\n";


void ISDevCliConfig::printConfig() {
	printConfigHeader();
	printConfigBody();
	printConfigEnd();
}

void ISDevCliConfig::printConfigHeader() {
	cout	<< endl
			<< "[+] EnrollmentConfig" << endl;
	cout	<< "    Platform               : "	<< sPlatform << endl;
	cout	<< "    " << getCommandDescription()
			<< endl;
}

void ISDevCliConfig::printConfigBody() {
	cout	<< LINE_LEAD << PROFILE_OPTION_PERSISTOR << "              "
			<< COLON_SPACE << leadPersistor.sType
			<< endl;
	cout	<< LINE_LEAD << PROFILE_OPTION_PERSISTOR_PATH << "         "
			<< COLON_SPACE << leadPersistor.sPath
			<< endl;

	if (leadPersistor.sType.compare(PERSISTOR_TYPE_PASSWORD) == 0) {
		cout	<< LINE_LEAD << PROFILE_OPTION_PERSISTOR_PASSWORD << "     "
				<< COLON_SPACE << leadPersistor.sPassword
				<< endl;
	} else if (leadPersistor.sType.compare(PERSISTOR_TYPE_AESGCM) == 0) {
		cout	<< LINE_LEAD << PROFILE_OPTION_PERSISTOR_AESGCM_KEY << "   "
				<< COLON_SPACE << leadPersistor.sAesGcmKey
				<< endl;
		cout	<< LINE_LEAD << PROFILE_OPTION_PERSISTOR_AESGCM_ADATA << " "
				<< COLON_SPACE << leadPersistor.sAesGcmAdata
				<< endl;
	}

	if (PLATFORM == PLATFORM_WINDOWS) {
		cout	<< LINE_LEAD << PROFILE_OPTION_PERSISTOR_VERSION << "      "
				<< COLON_SPACE << leadPersistor.sVersion
				<< endl;
	}

}

void ISDevCliConfig::printConfigEnd() {
	cout	<< LINE_LEAD << PROFILE_OPTION_VERBOSE << "                "
			<< COLON_SPACE << verboseLevelString[nVerbose]
			<< endl;
	cout	<< LINE_LEAD << PROFILE_OPTION_QUIET << "                  "
			<< COLON_SPACE << quietModeString[bQuiet]
			<< endl;
}

void ISDevCliConfig::parseConfigFile(string sConfigFilePath) {
	ifstream file(sConfigFilePath.c_str());
	if (file) {
		// parse json string
		try {
			boost::property_tree::read_json(sConfigFilePath, jsonConfig);
		} catch (boost::property_tree::json_parser_error& e) {
			fatal(ISSET_ERROR_CONFIG_PARSE_FAILED,
					"Failed to parse config file");
		}
		file.close();
	}
}


void ISDevCliConfig::getConfigFromFile() {

	// Check if base Config File defined
	if (vm.count(PROFILE_OPTION_CONFIG) == 0) {
		return;
	}

	// Parse base config file
	string sConfigFilePath = vm[PROFILE_OPTION_CONFIG].as<string>();
	parseConfigFile(sConfigFilePath);

	// extract configs
	boost::optional<string> op;

	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_PERSISTOR))) {
		leadPersistor.sType = *op;
	}
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_PERSISTOR_PATH))) {
		leadPersistor.sPath = *op;
	}
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_PERSISTOR_PASSWORD))) {
		leadPersistor.sPassword = *op;
	}
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_PERSISTOR_AESGCM_KEY))) {
		leadPersistor.sAesGcmKey = *op;
	}
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_PERSISTOR_AESGCM_ADATA))) {
		leadPersistor.sAesGcmAdata = *op;
	}
	if ((op = jsonConfig.get_optional<string>(PROFILE_OPTION_PERSISTOR_VERSION))) {
		leadPersistor.sVersion = *op;
	}

	// We don't get QUIET, VERBOSE or HELP from config file (Nor CONFIG for that matter).

}

void ISDevCliConfig::getConfigFromCommandLine() {

	if (vm.count(PROFILE_OPTION_APP_VERSION)) {
		printAppVersion();
		if (argCount <= 2) {
			// only asked for app version
			exit(ISSET_SUCCESS);
		}
	}

	if (vm.count(PROFILE_OPTION_HELP)) {
		printUsage();
		// If you've asked for help you've succeeded
		exit(ISSET_SUCCESS);
	}

	if (vm.count(PROFILE_OPTION_QUIET)) {
		bQuiet=true;
	}
	if (vm.count(PROFILE_OPTION_VERBOSE)) {
		nVerbose = vm[PROFILE_OPTION_VERBOSE].as<int>();
	}
	if (vm.count(PROFILE_OPTION_PERSISTOR)) {
		leadPersistor.sType = vm[PROFILE_OPTION_PERSISTOR].as<string>();
	}
	if (vm.count(PROFILE_OPTION_PERSISTOR_PATH)) {
		leadPersistor.sPath = vm[PROFILE_OPTION_PERSISTOR_PATH].as<string>();
	}
	if (vm.count(PROFILE_OPTION_PERSISTOR_PASSWORD)) {
		leadPersistor.sPassword = vm[PROFILE_OPTION_PERSISTOR_PASSWORD].as<string>();
	}
	if (vm.count(PROFILE_OPTION_PERSISTOR_AESGCM_KEY)) {
		leadPersistor.sAesGcmKey = vm[PROFILE_OPTION_PERSISTOR_AESGCM_KEY].as<string>();
	}
	if (vm.count(PROFILE_OPTION_PERSISTOR_AESGCM_ADATA)) {
		leadPersistor.sAesGcmAdata =
				vm[PROFILE_OPTION_PERSISTOR_AESGCM_ADATA].as<string>();
	}
}

void ISDevCliConfig::printAppVersion() {
	cout << IONIC_PROFILES_NAME << "  " << IONICTOOLS_APP_VERSION << endl;
}


void ISDevCliConfig::printUsageHeader() {
	cout << IONIC_PROFILES_NAME << "  ";
	if (isNoActionCommand()) {
		cout << PROFILES_USAGE_COMMANDS_STRING;
	} else {
		cout << getCommandName();
	}
	cout << "  " << CONFIG_PATH_USAGE;
}

void ISDevCliConfig::printUsagePersistor() {
	cout << endl;
	cout << "\t" << PROFILES_USAGE_PERSISTOR_LINE1 << endl;
	cout << "\t" << PROFILES_USAGE_PERSISTOR_LINE2 << endl;
	cout << "\t" << PROFILES_USAGE_PERSISTOR_LINE3 << endl;
}

void ISDevCliConfig::printUsageEnd() {
	cout << "\t" << PROFILES_USAGE_MISCELLANEOUS_STRING << endl;
	if (isNoActionCommand()) {
		cout << PROFILES_COMMAND_HELP_STRING << endl;
	}
}



void ISDevCliConfig::buildOptions() {
	config_options_list.add_options()
		(PROFILE_OPTION_CONFIG, po::value<string>(),
			"path to config file\n")
	;

	persistor_options_list.add_options()
		(PROFILE_OPTION_PERSISTOR, po::value<string>(),
			"profile persistor type\n(plaintext, password, aesgcm, default) 'default' if none given\n")
		(PROFILE_OPTION_PERSISTOR_PATH, po::value<string>(),
			"path to profile file\n")
		(PROFILE_OPTION_PERSISTOR_PASSWORD, po::value<string>()->implicit_value(""),
			"password to use to protect a 'password' persistor. \n"
			"Only applicable if '--persistor' is set to 'password'\n ")
		(PROFILE_OPTION_PERSISTOR_AESGCM_KEY, po::value<string>(),
			"Hex-encoded AES-256 key used to protect an 'aesgcm' persistor. \n"
			"Only applicable if '--persistor' is set to 'aesgcm'.\n")
		(PROFILE_OPTION_PERSISTOR_AESGCM_ADATA, po::value<string>(),
			"Authentication data used when encrypting an 'aesgcm' persistor.\n"
			"Only applicable if '--persistor' is set to 'aesgcm'.\n")
		(PROFILE_OPTION_PERSISTOR_VERSION, po::value<string>(),
			"Set version of persistor to use. Current versions are 1.0 and 1.1.\n"
			"Only relevant in Windows environment.\n")
	;

	miscellaneous_options_list.add_options()
		(PROFILE_OPTION_VERBOSE, po::value<int>(),
			"set verbosity level\n")
		(PROFILE_OPTION_QUIET,
			"For scripting, fail on missing info\n")
		(PROFILE_OPTION_HELP,
				"Display Usage information\n")
		(PROFILE_OPTION_APP_VERSION,
				"Display application version information\n")
	;

	profile_command_options_list.add_options()
		(HIDDEN_PROFILE_OPTION_PROFILE_COMMAND, po::value<string>(),
			"Profile Commands: create, list, show, set, convert, delete, validate-assertion :)\n")
	;

}

void ISDevCliConfig::buildOptionsList() {
	usage.add(config_options_list)
		.add(persistor_options_list)
		.add(miscellaneous_options_list)
	;
}


void ISDevCliConfig::parseConfig(const int argc, const char** argv) {

	string commandString = getCommandName();

	// parse command line arguments
	buildOptions();
	buildOptionsList();

	// super_usage holds hidden profile-command option along with rest of usage
	super_usage.add(profile_command_options_list).add(usage);

	// Handle special case of running command with no options
	if ((argc <= 1) ||
		(strcmp(argv[1],"--help")==0) ) {
		cout << "Usage:"
				<< endl << endl;
				printUsage();
				cout << usage << endl;
		exit(ISSET_SUCCESS);
	}

	try {
		po::parsed_options parsed3 = po::parse_command_line(argc, argv, super_usage);
		vm.insert(make_pair(commandString, po::variable_value()));
		po::store(parsed3, vm);
	} catch (po::error) {
		cout << "[!] Failed to parse command line arguments. Usage:"
				<< endl << endl;
				printUsage();
				cout << usage << endl;
		exit(ISSET_ERROR_COMMANDLINE_PARSE_FAILED);
	}

}


void ISDevCliConfig::getConfig(const int argc, const char** argv, ISAgent *pAgent) {

	argCount = argc;

	// parse command line arguments
	parseConfig(argc, argv);

	getConfigFromFile();

	getConfigFromCommandLine();

	initIonicLogging(nVerbose);

	validateConfig();

	if (nVerbose >= 1) {
		printConfig();
	}

	invokeAction(pAgent);
}


void ISDevCliConfig::validatePersistor(Persistor *persistor) {

	// If persistor is specified, make sure it is valid
	if (persistor->sType != PERSISTOR_TYPE_PLAINTEXT
			&& persistor->sType != PERSISTOR_TYPE_DEFAULT
			&& persistor->sType != PERSISTOR_TYPE_PASSWORD
			&& persistor->sType != PERSISTOR_TYPE_AESGCM) {
		fatal(ISSET_ERROR_INVALID_PERSISTOR,
				"An invalid persistor was specified");
	}

	// If Platform is Linux, Persistor cannot be Persistor type 'default'
	if (nVerbose >= 1) {
		cout << "Platform is: " << PLATFORM << endl;
	}
	if (PLATFORM == PLATFORM_LINUX) {
		if (nVerbose >= 1) {
			cout << "Verify Persistor type is not 'default'" << endl;
		}
		if (persistor->sType == PERSISTOR_TYPE_DEFAULT) {
			fatal(ISSET_ERROR_DEFAULT_PERSISTOR_INVALID_FOR_LINUX,
					"Default persistor is invalid on Linux systems");
		}
	}

	// If no persistor path is specified, set default path
	if (persistor->sPath == "") {
		string homedrivePrefix;
		string homedirPrefix;
		string ionicsecurityDir;
		string platformPathPrefix;
		const char *homedir = NULL;
		const char *homedrive = NULL;
		if (PLATFORM == PLATFORM_WINDOWS) {
			homedir = getenv("HOMEPATH");
			homedrive = getenv("HOMEDRIVE");
		} else { // Linux and OSX
			homedir = getenv("HOME");
		}
		homedrivePrefix  = (string)((homedrive==NULL) ? "" : homedrive);
		homedirPrefix    = (string)((homedir==NULL)   ? "" : homedir);
		ionicsecurityDir = (string)((PLATFORM == PLATFORM_WINDOWS) ? "\\.ionicsecurity\\" : "/.ionicsecurity/");
		platformPathPrefix = homedrivePrefix + homedirPrefix + ionicsecurityDir;

		if (persistor->sType == PERSISTOR_TYPE_PLAINTEXT) {
			persistor->sPath = platformPathPrefix + "profiles.pt";
		} else if (persistor->sType == PERSISTOR_TYPE_PASSWORD) {
			persistor->sPath = platformPathPrefix + "profiles.pw";
		} else if (persistor->sType == PERSISTOR_TYPE_AESGCM) {
			persistor->sPath = platformPathPrefix + "profiles.aesgcm";
		}
		// Note: When a 'default' persistor is used, the profile is saved to a platform-dependent location.
	}

	fs::path p = persistor->sPath;
	if (fs::exists(p) && fs::is_directory(p)) {
		fatal(ISSET_ERROR_INVALID_PERSISTOR_PATH,
				"Persistor path must include filename\n"
						+ persistor->sPath);
	}

	// password persistor checks
	if (persistor->sType == PERSISTOR_TYPE_PASSWORD) {
		if (bQuiet) { // non-interactive
			// If persistor type is password, a password argument must be provided (throw error)
			if (persistor->sPassword.empty()) {
				fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
					"If 'password' persistor is specified, 'persistor-password' must be provided");
			}
			// If peristor password must be at least 6 characters long (throw error)
			if (persistor->sPassword.size() < 6) {
				fatal(ISSET_ERROR_INVALIDARG_PERSISTOR_PASSWORD,
					"Persistor password must be at least 6 characters");
			}
		} else { // interactive
			if (sCommandName.compare("create") == 0) {
				// creating new password allow repeat try if too short
				while (persistor->sPassword.size() < 6) {
					cout << "Please create/enter password for this persistor (must be at least 6 characters): ";
					getline(cin, persistor->sPassword);
				}
			} else if (persistor->sPassword.empty()) {
				// Password should be known for other commands no retry
				cout << "Please enter password for this persistor: ";
				getline(cin, persistor->sPassword);
			}
		}
	}

	// aesgcm persistor checks
	if (persistor->sType == PERSISTOR_TYPE_AESGCM) {
		// If persistor type is aesgcm, a key argument must be provided (throw error)
		// AES-256-GCM Key: 64 hex char (x4)==> 256 bits (/8)==> 32 bytes
		while (persistor->sAesGcmKey.size() != 64) {
			if (bQuiet) {
				fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
					"Quiet mode: If 'aesgcm' persistor is specified, 'persistor-aesgcm-key' must be provided");
			} else {
				cout << "Please enter your AES-256-GCM key for this profile (64 hex characters): ";
				getline(cin, persistor->sAesGcmKey);
			}
		}

		// If persistor type is aesgcm, authdata must be provided
		while (persistor->sAesGcmAdata == "") {
			if (bQuiet) {
				fatal(ISSET_ERROR_MISSING_REQUIRED_ARG,
					"Quiet mode: If 'aesgcm' persistor is specified, 'persistor-aesgcm-adata' must be provided");
			} else {
				cout << "Please enter your AesGcm data for this profile: ";
				getline(cin, persistor->sAesGcmAdata);
			}
		}
	}
}

void ISDevCliConfig::validateConfig() {

	validatePersistor(&leadPersistor);

	// Persistor Version is Windows Platform Specific
	if (PLATFORM == PLATFORM_WINDOWS) {
		// persistor version checks
		if (!leadPersistor.sVersion.empty()) {
			// persistor version length checks
			if (leadPersistor.sVersion.length() > 3
				|| leadPersistor.sVersion.length() < 2) {
					fatal(ISSET_ERROR_PERSISTOR_VERSION_LENGTH,
						"Persistor version length must be in valid range");
			}

			// If persistor version, it must exist
			if (leadPersistor.sVersion.compare("1.0") != 0
				&& leadPersistor.sVersion.compare("1.1") != 0) {
					fatal(ISSET_ERROR_INVALID_PERSISTOR_VERSION,
						"Persistor version must exist. Current Versions are 1.0 and 1.1");
			}
		}
	}

}

// Invoke the specific function for a given action
void ISDevCliConfig::invokeAction(ISAgent *pAgent) {

}


// Initialize the agent with a respective Persistor
// Returns respective Persistor for further use in other functions
// Returns nullptr if invalid type of Persistor
std::unique_ptr<ISAgentDeviceProfilePersistor> ISDevCliConfig::initWithPersistor(ISAgent *pAgent, Persistor persistor) {

	if (persistor.sType.compare(PERSISTOR_TYPE_DEFAULT) == 0) { // Default Persistor
		cout << "---> Initializing Ionic Agent Default Persistor profiles"
				<< endl;

		// Persistor config
		std::unique_ptr<ISAgentDeviceProfilePersistorDefault> defaultPersistor(new ISAgentDeviceProfilePersistorDefault());

		// Initialize the Ionic Agent
		int nErr = pAgent->initialize(*defaultPersistor);
		if (nErr != ISAGENT_OK) {
			fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
					"[!FATAL] Failed to initialize Ionic Agent.");
		}

		return std::move(defaultPersistor);

	} else if (persistor.sType.compare(PERSISTOR_TYPE_PLAINTEXT) == 0) { // Plaintext Persistor
		cout
				<< "---> Initializing Ionic Agent Plaintext Persistor profiles"
				<< endl;

		// Persistor config
		std::unique_ptr<ISAgentDeviceProfilePersistorPlaintext> plaintextPersistor(new ISAgentDeviceProfilePersistorPlaintext());
		plaintextPersistor->setFilePath(persistor.sPath);

		// Initialize the Ionic Agent
		int nErr = pAgent->initialize(*plaintextPersistor);
		if (nErr != ISAGENT_OK) {
			fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
					"[!FATAL] Failed to initialize Ionic Agent.");
		}

		return std::move(plaintextPersistor);

	} else if (persistor.sType.compare(PERSISTOR_TYPE_PASSWORD) == 0) { // Password Persistor
		cout
				<< "---> Initializing Ionic Agent for Password Persistor profiles"
				<< endl;

		// Persistor config
		std::unique_ptr<ISAgentDeviceProfilePersistorPassword> passwordPersistor(new ISAgentDeviceProfilePersistorPassword());
		passwordPersistor->setPassword(persistor.sPassword);
		passwordPersistor->setFilePath(persistor.sPath);


		// Initialize the Ionic Agent
		int nErr = pAgent->initialize(*passwordPersistor);
		if (nErr != ISAGENT_OK) {
			fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
					"[!FATAL] Failed to initialize Ionic Agent.");
		}

		return std::move(passwordPersistor);

	} else if (persistor.sType.compare(PERSISTOR_TYPE_AESGCM) == 0) { // AesGcm Persistor
		cout
				<< "---> Initializing Ionic Agent for AesGcm Persistor profiles"
				<< endl;

		// Persistor config
		std::unique_ptr<ISAgentDeviceProfilePersistorAesGcm> pAesGcmPersistor(new ISAgentDeviceProfilePersistorAesGcm());
		string authData = persistor.sAesGcmAdata;
		ISCryptoBytes cbAuthData((byte*) authData.data(), authData.size());
		ISCryptoBytes cbPersistorKey;
		ISCryptoHexString chsPersistorKey = persistor.sAesGcmKey;
		chsPersistorKey.toBytes(cbPersistorKey);

		pAesGcmPersistor->setFilePath(persistor.sPath);
		pAesGcmPersistor->setKey(cbPersistorKey);
		pAesGcmPersistor->setAuthData(cbAuthData);

		// Initialize the Ionic Agent
		int nErr = pAgent->initialize(*pAesGcmPersistor);
		if (nErr != ISAGENT_OK) {
			fatal(ISSET_ERROR_PERSISTOR_LOAD_FAILED,
					"[!FATAL] Failed to initialize Ionic Agent.");
		}

		return std::move(pAesGcmPersistor);

	} else {
		return nullptr;
	}
}
