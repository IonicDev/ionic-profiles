/* Copyright 2017-2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_ISDEVCLICONFIG_H
#define __IONIC_ISDEVCLICONFIG_H

#include "boost/property_tree/ptree.hpp"
#include "boost/property_tree/json_parser.hpp"

#include "boost/program_options.hpp"
namespace po = boost::program_options;

using namespace std;

#include "ISAgent.h"


#if defined(__linux__)
#define PLATFORM "linux"
#elif defined(_WIN32) || defined(_WIN64)
#define PLATFORM "windows"
#include "ISAgentDeviceProfilePersistorWindows.h"
#elif defined(__APPLE__)
#define PLATFORM "osx"
#endif



class ISDevCliConfig {
	public:

		// Type of Profile manipulation to execute
		enum ProfileCommand {
			PROFILE_COMMAND_NONE		= 0,		// No Command Selected
			PROFILE_COMMAND_CREATE		= 1,		// Create a new profile
			PROFILE_COMMAND_LIST		= 2,		// List profiles of specified persistor type in persistor file
			PROFILE_COMMAND_SHOW		= 3,		// Show details for active profile of
													//	specified persistor type in persistor file
			PROFILE_COMMAND_SET			= 4,		// Set profile with given Device ID (of specified
													//	persistor type in persistor file) as active
			PROFILE_COMMAND_CONVERT		= 5,		// Convert profile with given Device ID or All profiles
													//	of specified persistor type in persistor file
													//	to target persistor
			PROFILE_COMMAND_DELETE		= 6			// Delete profile with given Device ID of
													//	specified persistor type in persistor file
		};

		const char *const profileCommandName[7] = {
			"no action",
			"create",
			"list",
			"show",
			"set",
			"convert",
			"delete"
		};

		const char *const profileCommandDescription[7] = {
			"No Action",
			"Create a new profile",
			"List profiles",
			"Show active profile",
			"Set profile as active",
			"Convert profile(s)",
			"Delete a profile"
		};

		const char *const quietModeString[2] = {
			"Interactive Mode",
			"Quiet Mode"
		};

		const int MAX_VERBOSITY			= 2;
		const char *const verboseLevelString[3] = {
			"Error Only",
			"Basic application logging",
			"App plus Ionic SDK Info level"
		};

		const char *const LINE_LEAD								= " -  ";
		const char *const COLON_SPACE							= ": ";

		const char *const PROFILE_OPTION_CONFIG					= "config";
		const char *const PROFILE_OPTION_PERSISTOR				= "persistor";
		const char *const PROFILE_OPTION_PERSISTOR_PATH			= "persistor-path";
		const char *const PROFILE_OPTION_PERSISTOR_PASSWORD		= "persistor-password";
		const char *const PROFILE_OPTION_PERSISTOR_AESGCM_KEY	= "persistor-aesgcm-key";
		const char *const PROFILE_OPTION_PERSISTOR_AESGCM_ADATA	= "persistor-aesgcm-adata";
		const char *const PROFILE_OPTION_PERSISTOR_VERSION		= "persistor-version";
		const char *const PROFILE_OPTION_VERBOSE				= "verbose";
		const char *const PROFILE_OPTION_QUIET					= "quiet";
		const char *const PROFILE_OPTION_HELP					= "help";

		const char *const HIDDEN_PROFILE_OPTION_PROFILE_COMMAND	= "profile-command";

		const char *const PLATFORM_LINUX			=	"linux";
		const char *const PLATFORM_OSX				=	"osx";
		const char *const PLATFORM_WINDOWS			=	"windows";

		const char *const PERSISTOR_TYPE_PLAINTEXT	= "plaintext";
		const char *const PERSISTOR_TYPE_PASSWORD	= "password";
		const char *const PERSISTOR_TYPE_AESGCM		= "aesgcm";
		const char *const PERSISTOR_TYPE_DEFAULT	= "default";

		const char *const IONIC_PROFILES_NAME	= "ionic-profiles";
		const char *const CONFIG_PATH_USAGE		= "[--config <PATH>]";
		const char *const VERBOSE_USAGE			= "[--verbose <LEVEL>]";
		const char *const QUIET_USAGE			= "[--quiet]";
		const char *const HELP_USAGE			= "[--help]";

		const char *const PROFILES_USAGE_COMMANDS_STRING		=
			"[[create] | list  | show | set | convert | delete]";
		const char *const PROFILES_USAGE_PERSISTOR_LINE1		=
			"[--persistor <PERSISTOR>] [--persistor-path <PATH>] [--persistor-password <PASSWORD>]";
		const char *const PROFILES_USAGE_PERSISTOR_LINE2		=
			"[--persistor-aesgcm-key <KEY>] [--persistor-aesgcm-adata <AUTHDATA>]";
		const char *const PROFILES_USAGE_PERSISTOR_LINE3		=
			"[--persistor-version <VERSION>]";
		const char *const PROFILES_USAGE_MISCELLANEOUS_STRING	=
			"[--verbose <LEVEL>] [--quiet] [--help]";

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
		        \n\t\tsee ionic-profiles delete --help for options\n";


		struct Persistor {
			string	sType;					// Persistor type - plaintext, password, aesgcm, or default (Windows)
			string	sPath;					// File path where profile will be/is stored
			string	sPassword;				// Password for profile of persistor password type
			string	sAesGcmKey;				// AesGcm Key for profile of persistor aesgcm type
			string	sAesGcmAdata;			// AesGcm Data for profile of persistory aesgcm type
			string	sVersion;				// Persistor Version (Windows)
		} leadPersistor;


		ISDevCliConfig(int action = PROFILE_COMMAND_NONE, int verbosity = 0 ) :
			nProfileCommand{action},
			nVerbose{verbosity},
			bQuiet{false},
			sPlatform{PLATFORM},
			leadPersistor{"default"}
		{
			if (nVerbose > MAX_VERBOSITY) {
				nVerbose = MAX_VERBOSITY;
			} else if (nVerbose < 0) {
				nVerbose = 0;
			}
			if (nProfileCommand > PROFILE_COMMAND_DELETE) {
				nProfileCommand = PROFILE_COMMAND_DELETE;
			} else if (nProfileCommand < PROFILE_COMMAND_NONE) {
				nProfileCommand = PROFILE_COMMAND_NONE;
			}
		};

		virtual ~ISDevCliConfig(){};

		void printConfig();

		virtual void printConfigHeader();
		virtual void printConfigBody();
		virtual void printConfigEnd();

		void parseConfigFile(string sConfigFilePath);
		virtual void getConfigFromFile();

		virtual void getConfigFromCommandLine();
		void parseConfig(const int argc, const char** argv);
		void getConfig(const int argc, const char** argv, ISAgent *agent);

		void validatePersistor(Persistor *persistor);

		virtual void validateConfig();

		void getProfilesConfig(boost::program_options::variables_map vm,
				ISAgent *agent, ProfileCommand profileCommandAction);

		void printUsage() {
			printUsageHeader();
			printUsagePersistor();
			printUsageEnd();
		}

		virtual void printUsageHeader();

		virtual void printUsagePersistor();

		virtual void printUsageEnd();

		virtual void buildOptions();

		virtual void buildOptionsList();

		virtual void invokeAction(ISAgent *pAgent);

		ISAgentDeviceProfilePersistor * initWithPersistor(ISAgent *pAgent, Persistor persistor);

//	private:

		int		nProfileCommand;			// Action to be executed on profile
											//	- Create (DEFAULT), List, Show, Set, Delete, or Convert
		int		nVerbose;					// Control level of logging output
		bool	bQuiet;						// Enable non-interactive behavior
		string	sPlatform;					// OS Platform application is running on

		string	sConfigFilePath;			// path and filename for config file

		boost::property_tree::ptree jsonConfig;

		po::variables_map vm;

		po::positional_options_description profile_command;

		po::options_description usage;
		po::options_description super_usage;

		po::options_description config_options_list;
		po::options_description persistor_options_list;
		po::options_description miscellaneous_options_list;
		po::options_description profile_command_options_list;

};

#endif // __IONIC_ISDEVCLICONFIG_H
