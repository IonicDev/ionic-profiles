/* Copyright 2017-2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>

#include "ISEnrollmentError.h"

#include "ISDevCliConfig.h"
#include "ISDevCliConfigList.h"
#include "ISDevCliConfigShow.h"
#include "ISDevCliConfigSet.h"
#include "ISDevCliConfigDelete.h"
#include "ISDevCliConfigCreate.h"
#include "ISDevCliConfigConvert.h"


int main(const int argc, const char** argv)
{
    // initialize ionic
	ISAgent* pAgent = new ISAgent();

	string sArg1;
	if ((argc <= 1) ||
		(strcmp(argv[1],"--help")==0) ) {
		// No args: parse will fail and global usage will be displayed
		// or 1st arg is --help go straight to global usage
		ISDevCliConfig config;
		config.getConfig(argc, argv, pAgent);

	} else {
		sArg1=argv[1];
		if (sArg1.compare("list")==0) {
			// get config and handle List command
			ISDevCliConfigList config;
			config.getConfig(argc, argv, pAgent);
		} else if (sArg1.compare("show")==0) {
			// get config and handle Show command
			ISDevCliConfigShow config;
			config.getConfig(argc, argv, pAgent);
		} else if (sArg1.compare("set")==0) {
			// get config and handle Set command
			ISDevCliConfigSet config;
			config.getConfig(argc, argv, pAgent);
		} else if (sArg1.compare("convert")==0) {
			// get config and handle Convert command
			ISDevCliConfigConvert config;
			config.getConfig(argc, argv, pAgent);
		} else if (sArg1.compare("delete")==0) {
			// get config and handle Delete command
			ISDevCliConfigDelete config;
			config.getConfig(argc, argv, pAgent);
		} else {
			// Defaults to CREATE
			// get config and handle Create command
			ISDevCliConfigCreate config;
			config.getConfig(argc, argv, pAgent);
		}
	}

	delete(pAgent);

    return ISSET_SUCCESS;
}
