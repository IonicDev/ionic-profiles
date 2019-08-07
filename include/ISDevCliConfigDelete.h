/* Copyright 2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_ISDEVCLICONFIG_DELETE_H
#define __IONIC_ISDEVCLICONFIG_DELETE_H

#include "ISDevCliConfigSet.h"

class ISDevCliConfigDelete : public ISDevCliConfigSet {
	public:

		const char *const PROFILES_DELETE_DESCRIPTION	= "Delete a profile";
		const char *const PROFILES_DELETE_USAGE_LINE	= "ionic-profiles delete  [--config <path>]";

		const char *const PROFILES_DELETE_USAGE_STRING	=
			"\tDelete a profile \
		        \n\n\tionic-profiles delete  [--config <path>]  --device-id <DEVICE_ID> \
		        \n\t\t[--persistor <PERSISTOR>] [--persistor-path <path>] [--persistor-password <PASSWORD>] \
		        \n\t\t[--persistor-aesgcm-key <KEY>] [--persistor-aesgcm-adata <AUTHDATA>] \
		        \n\t\t[--persistor-version <VERSION>] [--verbose <LEVEL>] \
		        \n\t\t[--quiet] [--help]";


		ISDevCliConfigDelete(int verbosity = 0 ) :
				ISDevCliConfigSet(verbosity) {
		}

		~ISDevCliConfigDelete() {}

		void printUsageHeader();

		void printUsagePersistor();

		void validateConfig();

		void invokeAction(ISAgent *pAgent);

		void removeProfile(ISAgent *pAgent);


//	private:

};

#endif // __IONIC_ISDEVCLICONFIG_DELETE_H
