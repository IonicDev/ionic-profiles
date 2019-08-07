/* Copyright 2017-2019 Ionic Security Inc. All Rights Reserved.
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
#include "ISDevCliConfigValidateAssertion.h"

using namespace std;


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
		if (sArg1.compare("create")==0) {
			// get config and handle Create command
			ISDevCliConfigCreate config;
			config.setCommandNameAndDescription(
				"create", "Create a new profile");
			config.getConfig(argc, argv, pAgent);
		} else if (sArg1.compare("list")==0) {
			// get config and handle List command
			ISDevCliConfigList config;
			config.setCommandNameAndDescription(
				sArg1, "List profiles");
			config.getConfig(argc, argv, pAgent);
		} else if (sArg1.compare("show")==0) {
			// get config and handle Show command
			ISDevCliConfigShow config;
			config.setCommandNameAndDescription(
				sArg1, "Show active profile");
			config.getConfig(argc, argv, pAgent);
		} else if (sArg1.compare("set")==0) {
			// get config and handle Set command
			ISDevCliConfigSet config;
			config.setCommandNameAndDescription(
				sArg1, "Set profile as active");
			config.getConfig(argc, argv, pAgent);
		} else if (sArg1.compare("convert")==0) {
			// get config and handle Convert command
			ISDevCliConfigConvert config;
			config.setCommandNameAndDescription(
				sArg1, "Convert profile(s)");
			config.getConfig(argc, argv, pAgent);
		} else if (sArg1.compare("delete")==0) {
			// get config and handle Delete command
			ISDevCliConfigDelete config;
			config.setCommandNameAndDescription(
				sArg1, "Delete a profile");
			config.getConfig(argc, argv, pAgent);
		} else if (sArg1.compare("validate-assertion")==0) {
			// get config and handle Validate-Assertion command
			ISDevCliConfigValidateAssertion config;
			config.setCommandNameAndDescription(
				sArg1, "Validate an assertion file");
			config.getConfig(argc, argv, pAgent);
		} else if (sArg1.rfind("--", 0) != 0) {
			// Since sArg1 did not start with a verb or
			// "--", this is an invalid command line.
			// parseConfig() handles argc == 1 by
			// displaying usage.
			ISDevCliConfig config;
			config.getConfig(1, argv, pAgent);
		} else {
			// Defaults to CREATE
			// get config and handle Create command
			ISDevCliConfigCreate config;
			config.setCommandNameAndDescription(
				"create", "Create a new profile");
			config.getConfig(argc, argv, pAgent);
		}
	}

    return ISSET_SUCCESS;
}
