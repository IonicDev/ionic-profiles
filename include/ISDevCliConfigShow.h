/* Copyright 2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_ISDEVCLICONFIG_SHOW_H
#define __IONIC_ISDEVCLICONFIG_SHOW_H

#include "ISDevCliConfig.h"


class ISDevCliConfigShow : public ISDevCliConfig {
	public:

		const char *const PROFILES_SHOW_DESCRIPTION	= "Show active profile";


		ISDevCliConfigShow(int verbosity = 0 ) :
				ISDevCliConfig(verbosity) {
		}

		~ISDevCliConfigShow() {}

		void printUsageHeader();

		void invokeAction(ISAgent *pAgent);

		void showActiveProfile(ISAgent *pAgent);
//	private:

};

#endif // __IONIC_ISDEVCLICONFIG_SHOW_H
