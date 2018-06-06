/* Copyright 2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_ISDEVCLICONFIG_LIST_H
#define __IONIC_ISDEVCLICONFIG_LIST_H

#include "ISDevCliConfig.h"

class ISDevCliConfigList : public ISDevCliConfig {
	public:

		const char *const PROFILES_LIST_DESCRIPTION	= "Display a list of profiles";


		ISDevCliConfigList(int action = PROFILE_COMMAND_LIST, int verbosity = 0) :
			ISDevCliConfig( action, verbosity )
			{}

		~ISDevCliConfigList() {}

		void printUsageHeader();

		void invokeAction(ISAgent *pAgent);

		void listAllProfiles();

		vector<ISAgentDeviceProfile> getVector();

//	private:

};

#endif // __IONIC_ISDEVCLICONFIG_LIST_H
