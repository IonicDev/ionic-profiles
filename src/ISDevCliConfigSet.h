/* Copyright 2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_ISDEVCLICONFIG_SET_H
#define __IONIC_ISDEVCLICONFIG_SET_H

#include "ISDevCliConfig.h"

class ISDevCliConfigSet : public ISDevCliConfig {
	public:

		const char *const PROFILE_OPTION_DEVICE_ID	= "device-id";

		const char *const PROFILES_SET_DESCRIPTION	= "Set a profile";

		const char *const DEVICE_ID_USAGE			= "--device-id <DEVICE_ID>";


		ISDevCliConfigSet(int action = PROFILE_COMMAND_SET, int verbosity = 0 ) :
				ISDevCliConfig( action, verbosity ) {
		}

		~ISDevCliConfigSet() {}

		void printConfigBody();

		void getConfigFromCommandLine();

		void printUsageHeader();

		void printUsagePersistor();

		void buildOptions();

		void buildOptionsList();

		void validateConfig();

		void invokeAction(ISAgent *pAgent);

		void setActiveProfile(ISAgent *pAgent);

//	private:
		string	sDeviceId;					// Device ID for profile being manipulated (Set, Delete, Convert)

		po::options_description device_id_options_list;

};

#endif // __IONIC_ISDEVCLICONFIG_SET_H
