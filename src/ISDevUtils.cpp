/* Copyright 2017-2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>

#include "boost/property_tree/xml_parser.hpp"
namespace pt = boost::property_tree;

#include "boost/date_time/posix_time/posix_time.hpp"
namespace posix_time = boost::posix_time;

#include "ISLog.h"

#include "ISDevUtils.h"
#include "ISEnrollmentError.h"

using namespace std;

namespace {
	posix_time::ptime timeFromTZstr(string sDateTime) {
		// remove the 'Z' at the end
		if (!sDateTime.empty() && (sDateTime.back() == 'Z')) {
			sDateTime.pop_back();
		}

		// replace the 'T' between date and time with a space
		size_t nTPos = sDateTime.find('T');
		if (nTPos != string::npos) {
			sDateTime.replace(nTPos, 1, " ");
		}

		return posix_time::time_from_string(sDateTime);
	}

	void readAssertionFile(const string& sAssertionFilePath, pt::ptree& oAssertionTree) {
		try {
			pt::read_xml(sAssertionFilePath, oAssertionTree);
		} catch(...) {
			fatal(ISSET_ERROR_ASSERTIONFILE_LOAD_FAILED,
					"Failed to load assertion data from " + sAssertionFilePath);
		}

	}

	void readEsUrlFromAssertionTree(const pt::ptree& oAssertionTree, string& sEsUrlFromAssertion) {
		try {
			sEsUrlFromAssertion = oAssertionTree.get<string>("Response.<xmlattr>.Destination");
		} catch(...) {
			sEsUrlFromAssertion = "";
		}
	}
}

namespace ISDevUtils {
	void fatal(const int nErr, const std::string& sMessage)
	{
		std::cout << "[ERROR] " << sMessage << " (" << nErr << ")" << std::endl;
		exit(nErr);
	}

	void passOrDie(const int nErr, const std::string& sMessage)
	{
		if (nErr != 0) {
			fatal(nErr, sMessage);
		}
	}

	void initIonicLogging(int nVerbose)
	{
		if (nVerbose <= 0) {
			return;
		}
		
		ISLogWriterConsole * pConsoleWriter = new ISLogWriterConsole();
		ISLogFilterSeverity * pConsoleFilter;
		
		if (nVerbose > 1) {
			pConsoleFilter = new ISLogFilterSeverity(SEV_DEBUG);
		} else {
			// nVerbose == 1
			pConsoleFilter = new ISLogFilterSeverity(SEV_ERROR);
		}
		
		pConsoleWriter->setFilter(pConsoleFilter);
		ISLogSink * pSink = new ISLogSink();
		pSink->registerChannelName("*");
		pSink->registerWriter(pConsoleWriter);
		ISLogImpl * pLogger = new ISLogImpl(true);
		pLogger->registerSink(pSink);
		ISLog::setSingleton(pLogger);
	}

	void readEsUrlFromAssertionFile(const string& sAssertionFilePath, string& sEsUrlFromAssertion) {
		pt::ptree oAssertionTree;
		readAssertionFile(sAssertionFilePath, oAssertionTree);
		readEsUrlFromAssertionTree(oAssertionTree, sEsUrlFromAssertion);
	}

	void validateAssertion(const string& sAssertionFilePath, const string& sEsGenAssnUrl, string& sEsUrlFromAssertion) {
		pt::ptree oAssertionTree;
		readAssertionFile(sAssertionFilePath, oAssertionTree);
		readEsUrlFromAssertionTree(oAssertionTree, sEsUrlFromAssertion);

		if (sEsUrlFromAssertion.empty()) {
			fatal(ISSET_ERROR_INVALID_ES_URL,
					"Failed to read " + string(PROFILE_OPTION_ES_URL) +
					" from assertion file " + sAssertionFilePath);
		}

		if (!sEsGenAssnUrl.empty() && (sEsUrlFromAssertion != sEsGenAssnUrl)) {
			fatal(ISSET_ERROR_INVALID_ES_URL,
					"Invalid: " + string(PROFILE_OPTION_ES_URL) +
					"='" + sEsGenAssnUrl +
					"' did not match value ('" + sEsUrlFromAssertion + "') found in " + sAssertionFilePath);
		}

		posix_time::ptime tNotOnOrAfter, tNotBefore;
		posix_time::ptime tNow = posix_time::second_clock::universal_time();
		try {
			posix_time::ptime tNotOnOrAfter = timeFromTZstr(oAssertionTree.get<string>("Response.Assertion.Conditions.<xmlattr>.NotOnOrAfter"));
			if (tNow >= tNotOnOrAfter) {
				fatal(ISSET_ERROR_LATE_WITH_ASSERTION,
						"Current time of " + posix_time::to_simple_string(tNow) + " (UTC) is after NotOnOrAfter time of " +
							posix_time::to_simple_string(tNotOnOrAfter) + " (UTC) in " + sAssertionFilePath);
			}
		} catch(...) {
			fatal(ISSET_ERROR_ASSERTIONFILE_LOAD_FAILED,
					"Could not parse NotOnOrAfter condition in " + sAssertionFilePath);
		}
		try {
			tNotBefore = timeFromTZstr(oAssertionTree.get<string>("Response.Assertion.Conditions.<xmlattr>.NotBefore"));
			if (tNow < tNotBefore) {
				fatal(ISSET_ERROR_EARLY_WITH_ASSERTION,
						"Current time of " + posix_time::to_simple_string(tNow) + " (UTC) is before NotBefore time of " +
							posix_time::to_simple_string(tNotBefore) + "(UTC) in " + sAssertionFilePath);
			}
		} catch(...) {
			fatal(ISSET_ERROR_ASSERTIONFILE_LOAD_FAILED,
					"Could not parse NotBefore condition in " + sAssertionFilePath);
		}
	}
}
