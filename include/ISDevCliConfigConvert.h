/* Copyright 2018-2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_ISDEVCLICONFIG_CONVERT_H
#define __IONIC_ISDEVCLICONFIG_CONVERT_H

#include "ISDevCliConfigSet.h"

class ISDevCliConfigConvert : public ISDevCliConfigSet {
	public:

		const char *const PROFILE_OPTION_TARGET_CONFIG					= "target-config";
		const char *const PROFILE_OPTION_TARGET_PERSISTOR				= "target-persistor";
		const char *const PROFILE_OPTION_TARGET_PERSISTOR_PATH			= "target-persistor-path";
		const char *const PROFILE_OPTION_TARGET_PERSISTOR_PASSWORD		= "target-persistor-password";
		const char *const PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_KEY	= "target-persistor-aesgcm-key";
		const char *const PROFILE_OPTION_TARGET_PERSISTOR_AESGCM_ADATA	= "target-persistor-aesgcm-adata";

		const char *const PROFILES_USAGE_TARGET_PERSISTOR_LINE1			= "[--target-persistor <PERSISTOR>] [--target-persistor-path <PATH>] [--target-persistor-password <PASSWORD>]";
		const char *const PROFILES_USAGE_TARGET_PERSISTOR_LINE2			= "[--target-persistor-aesgcm-key <KEY>] [--target-persistor-aesgcm-adata <AUTHDATA>]";

		const char *const PROFILES_CONVERT_DESCRIPTION					= "Convert profile from one persistor type to another";

		const char *const TARGET_CONFIG_PATH_USAGE						= "[--target-config <PATH>]";


		ISDevCliConfigConvert(int verbosity = 0 ) :
			targetPersistor{PERSISTOR_TYPE_DEFAULT},
			ISDevCliConfigSet(verbosity) {
		}

		~ISDevCliConfigConvert() {}

		void printConfigBody();

		void getConfigFromFile();

		void getConfigFromCommandLine();

		void printUsageHeader();

		void printUsagePersistor();

		void buildOptions();

		void buildOptionsList();

		void validateConfig();

		void invokeAction(ISAgent *pAgent);

		void convertProfiles(ISAgent *pAgent);

		void persistorPathFixer();

		void convertHelper(vector<ISAgentDeviceProfile>& vecProfilesOut,
					string sActiveDeviceIdOut);

//	private:

		Persistor	targetPersistor;

		po::options_description target_config_options_list;
		po::options_description target_persistor_options_list;

};

#endif // __IONIC_ISDEVCLICONFIG_CONVERT_H
