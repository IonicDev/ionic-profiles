/* Copyright 2017-2019 Ionic Security Inc. All Rights Reserved.
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


#if defined(_WIN32) || defined(_WIN64)
#include "ISAgentDeviceProfilePersistorWindows.h"
#endif


class ISDevCliConfig {
	public:

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
		const char *const PROFILE_OPTION_APP_VERSION			= "version";

		const char *const HIDDEN_PROFILE_OPTION_PROFILE_COMMAND	= "profile-command";

		const char *const PLATFORM_LINUX			=	"linux";
		const char *const PLATFORM_OSX				=	"osx";
		const char *const PLATFORM_WINDOWS			=	"windows";
#if defined(__linux__)
		const char *const PLATFORM = PLATFORM_LINUX;
#elif defined(_WIN32) || defined(_WIN64)
		const char *const PLATFORM = PLATFORM_WINDOWS;
#elif defined(__APPLE__)
		const char *const PLATFORM = PLATFORM_OSX;
#endif

		const char *const PERSISTOR_TYPE_PLAINTEXT	= "plaintext";
		const char *const PERSISTOR_TYPE_PASSWORD	= "password";
		const char *const PERSISTOR_TYPE_AESGCM		= "aesgcm";
		const char *const PERSISTOR_TYPE_DEFAULT	= "default";

		const char *const IONIC_PROFILES_NAME	= "ionic-profiles";
		const char *const CONFIG_PATH_USAGE		= "[--config <PATH>]";
		const char *const VERBOSE_USAGE			= "[--verbose <LEVEL>]";
		const char *const QUIET_USAGE			= "[--quiet]";
		const char *const HELP_USAGE			= "[--help]";
		const char *const APP_VERSION_USAGE		= "[--version]";


		struct Persistor {
			string	sType;					// Persistor type - plaintext, password, aesgcm, or default (Windows)
			string	sPath;					// File path where profile will be/is stored
			string	sPassword;				// Password for profile of persistor password type
			string	sAesGcmKey;				// AesGcm Key for profile of persistor aesgcm type
			string	sAesGcmAdata;			// AesGcm Data for profile of persistory aesgcm type
			string	sVersion;				// Persistor Version (Windows)
		} leadPersistor;


		ISDevCliConfig(int verbosity = 0 ) :
			sCommandName{""},
			sCommandDescription{"No action"},
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
		};

		void setCommandNameAndDescription(const string& sName, const string& sDescription) {
			sCommandName = sName;
			sCommandDescription = sDescription;
		}

		const string& getCommandName() {
			return sCommandName;
		}

		const string& getCommandDescription() {
			return sCommandDescription;
		}

		bool isNoActionCommand() {
			return sCommandName.empty();
		}

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

		virtual void validatePersistor(Persistor *persistor);

		virtual void validateConfig();

		void printAppVersion();

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

		std::unique_ptr<ISAgentDeviceProfilePersistor> initWithPersistor(ISAgent *pAgent, Persistor persistor);

//	private:

		int		argCount;
		string sCommandName;				// Action to be executed on profile -- set with setCommandNameAndDescription()
											//	- create (DEFAULT), list, show, set, delete, convert, or validate-assertion
		string sCommandDescription;			// Also set with setCommandNameAndDescription
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
