/* Copyright 2018 - 2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include "ISDevRest.h"
#include "ISHTTP.h"
#include "ISCrossPlatform.h"
#include "boost/property_tree/json_parser.hpp"
#include "boost/lexical_cast.hpp"
#include <utility>

bool getPropertyTree(
  const std::unique_ptr<ISHTTP>& pHttp,
  const std::string& url,
  boost::property_tree::ptree& ptreeRoot,
  std::string& errorMessage
) {
	// Send request with timeout of 10 seconds
	pHttp->setTimeoutSecs(10);
	ISHTTPRequest request(HTTP_GET, url);
	ISHTTPResponse response;
	int responseCode = pHttp->send(request, response);

	// Check the response code
	if (responseCode != ISHTTP_OK) {
		if (responseCode == ISHTTP_TIMEOUT) {
			errorMessage.assign("Timeout on GET request to " + url);
		}
		else if (responseCode == ISHTTP_NO_SECURE_CONNECTION) {
			errorMessage.assign("Could not establish secure connection to " + url);
		}
		else {
			errorMessage.assign(std::string("Unknown error ") +
			  boost::lexical_cast<std::string>(responseCode) + " connecting to " + url);
		}
		return false;
	}

	// Load the JSON file in this property tree
	std::string responseBodyString((char*)response.getBody().getData(), response.getBody().getLen());
	std::istringstream responseBodyStream(responseBodyString);
	try {
		boost::property_tree::read_json(responseBodyStream, ptreeRoot);
	}
	catch (const boost::property_tree::json_parser::json_parser_error& e) {
		errorMessage.assign(
		  "Encountered an error parsing response from URL [" + url +
                  "]: [" + std::string(e.what()) +
                  "]; response was: [" + responseBodyString + "]"
		);
		return false;
	}
	return true;
}

// Public utility for reading an enrollment URL from a kns endpoint
//
// Example: curl https://api.ionic.com/v2.4/kns/keyspaces/MFyg
//
// Response from curl call:
// {
//   "keyspace":"MFyg",
//   "fqdn":"0.a.c.5.0.3.ks.kns.ionic.com",
//   "ttlSeconds":3600,
//   "answers": {
//     "enroll": [ "https://mastereng-enrollment.in.ionicsecurity.com/keyspace/MFyg/register" ],
//     "tenantid": ["55d34e428e66393e53551c75"],
//     "url": [ "https://api.mastereng.ionic.engineering" ]
//   }
// }
//
// Contents of string enrollmentURL returned by calling
// getEnrollmentURL("MFyg", enrollmentURL, ...):
// "https://mastereng-enrollment.in.ionicsecurity.com/keyspace/MFyg/register"

bool getEnrollmentURL(
  const std::string& keySpace,
  std::string& keyspaceURL,
  std::string& enrollmentURL,
  std::string& errorMessage
) {
	// Create default HTTP instance, which will be the native impl
	std::unique_ptr<ISHTTP> pHttp(ISHTTPFactory::getInstance().createDefault());

	// Create a string for keyspace URL
	keyspaceURL.assign("https://api.ionic.com/v2.4/kns/keyspaces/" + keySpace);

	// Read the property tree from keyspaceURL
	boost::property_tree::ptree ptreeRoot;
	if (!getPropertyTree(pHttp, keyspaceURL, ptreeRoot, errorMessage)) {
		return false;
	}

	// Get the enrollment URL under key "answers"
	boost::optional<boost::property_tree::ptree&> answers = ptreeRoot.get_child_optional("answers");
	if (!answers.is_initialized()) {
		errorMessage.assign("Could not find key \"answers\" in response from [" + keyspaceURL + "]");
		return false;
	}
	boost::optional<boost::property_tree::ptree&> enroll = answers.get().get_child_optional("enroll");
	if (!enroll.is_initialized()) {
		errorMessage.assign("Could not find key \"enroll\", under key \"answers\", in response from [" + keyspaceURL + "]");
		return false;
	}
	for (const std::pair<std::string, boost::property_tree::ptree>& urlNode : enroll.get()) {
		std::string urlStr;
		try {
			urlStr.assign(urlNode.second.get_value<std::string>());
		}
		catch (const boost::property_tree::ptree_bad_data& e) {
			errorMessage.assign(
			  "Encountered error getting value for key \"enroll\": [" + std::string(e.what()) +
			  "] found under key \"answers\" in response from [" + keyspaceURL + "]"
			);
			return false;
		}
		std::string shouldBeHttp(urlStr.substr(0, std::min<size_t>(4, urlStr.length())));
		if (shouldBeHttp != "http") {
			errorMessage.assign(
			  "Value of key \"enroll\", [" + urlStr + "], found under key \"answers\" in response from [" +
			  keyspaceURL + "] is not an http or https URL"
			);
			return false;
		}
		enrollmentURL.assign(urlStr);
		return true;
	}

	// Though the "enroll" keyword was found, nothing was under it.
	errorMessage.assign("Could not find any entries under key \"enroll\", under key \"answers\", in response from [" + keyspaceURL + "]");
	return false;
}

// Private utility implementing a method of value extraction used
// repeatedly in getRegisterURLs()
//
template <typename T>
static bool extractValueUnderIdentitySourceType(
  const std::string&                                         key,
  const std::string&                                         identitySourceType,
  const std::string&                                         identitySourceURL,
  std::pair<const std::string, boost::property_tree::ptree> &identitySourceNode,
  T&                                                         output,
  std::string&                                               errorMessage
) {
	boost::optional<boost::property_tree::ptree&> childNode = identitySourceNode.second.get_child_optional(key);
	if (!childNode.is_initialized()) {
		errorMessage.assign(
		  "Could not find key \"" + key + "\", under key \"" + identitySourceType +
		  "\", under key \"identitySources\", in response from [" + identitySourceURL + "]"
		);
		return false;
	}
	try {
		output = childNode.get().get_value<T>();
	}
	catch (const boost::property_tree::ptree_bad_data& e) {
		errorMessage.assign(
		  "Encountered error getting value for key \"name\": [" + std::string(e.what()) +
		  "] found under key \"identitySources\", in response from [" + identitySourceURL + "]"
		);
		return false;
	}
	return true;
}

// Public utility for reading a map of (name, uri) pairs from an
// /identify_sources endpoint
//
// Example: curl https://preview-enrollment.ionic.com/keyspace/CqN0/identity_sources
//
// Response from curl call:
// {
//   "identitySources": {
//     "SAML": [
//       {
//         "name": "default",
//         "tenantId": "56f164d8f8ab7b15a9e8f194",
//         "listName": "Corporate SSO",
//         "listIcon": "https://image.spreadshirtmedia.com/image-server/v1/mp/designs/1001569093,width=178,height=178/initech-logo.png",
//         "hidden": false,
//         "isGlobalDefault": true,
//         "isDefault": true,
//         "jsEnrollEnabled": false,
//         "uri": "https://preview-enrollment.ionic.com/keyspace/CqN0/sp/56f164d8f8ab7b15a9e8f194/default/register"
//       },
//       {
//         "name": "headless",
//         "tenantId": "56f164d8f8ab7b15a9e8f194",
//         "listName": "Machine Auth",
//         "listIcon": "",
//         "hidden": false,
//         "isGlobalDefault": false,
//         "isDefault": false,
//         "jsEnrollEnabled": false,
//         "uri": "https://preview-enrollment.ionic.com/keyspace/CqN0/sp/56f164d8f8ab7b15a9e8f194/headless/register"
//       }
//     ],
//     "OAUTH": [
//       ...
//     ],
//     ...
//   }
// }
//
// Contents of map registerURLs returned by calling
// getRegisterURLs("https://preview-enrollment.ionic.com/keyspace/CqN0/identity_sources", "SAML", registerURLs, ...):
// "default"  -> "https://preview-enrollment.ionic.com/keyspace/CqN0/sp/56f164d8f8ab7b15a9e8f194/default/register"
// "headless" -> "https://preview-enrollment.ionic.com/keyspace/CqN0/sp/56f164d8f8ab7b15a9e8f194/headless/register"

bool getRegisterURLs(
  const std::string&                  identitySourceURL,
  const std::string&                  identitySourceType,
  std::map<std::string, std::string>& registerURLs,
  std::string&                        defaultName,
  std::string&                        globalDefaultName,
  std::string&                        errorMessage
) {
	// Create default HTTP instance, which will be the native impl
	std::unique_ptr<ISHTTP> pHttp(ISHTTPFactory::getInstance().createDefault());

	// Read the property tree from identitySourceURL
	boost::property_tree::ptree ptreeRoot;
	if (!getPropertyTree(pHttp, identitySourceURL, ptreeRoot, errorMessage)) {
		return false;
	}

	// Get the names and /register URLs under key "identitySources"
	boost::optional<boost::property_tree::ptree&> identitySources = ptreeRoot.get_child_optional("identitySources");
	if (!identitySources.is_initialized()) {
		errorMessage.assign("Could not find key \"identitySources\" in response from [" + identitySourceURL + "]");
		return false;
	}
	boost::optional<boost::property_tree::ptree&> identitySourceArray = identitySources.get().get_child_optional(identitySourceType);
	if (!identitySourceArray.is_initialized()) {
		errorMessage.assign("Could not find key \"" + identitySourceType + "\", under key \"identitySources\", in response from [" + identitySourceURL + "]");
		return false;
	}

	// Get names / uri pairs ...
	for (std::pair<const std::string, boost::property_tree::ptree> &identitySourceNode : identitySourceArray.get()) {
		// Extract the value for the key, "name"
		std::string nameStr;
		if (!extractValueUnderIdentitySourceType<std::string>("name", identitySourceType, identitySourceURL, identitySourceNode, nameStr, errorMessage)) {
			return false;
		}

		// Extract the value for the key, "uri", and make a
		// rudimentary check that it is an http address.
		std::string uriStr;
		if (!extractValueUnderIdentitySourceType<std::string>("uri", identitySourceType, identitySourceURL, identitySourceNode, uriStr, errorMessage)) {
			return false;
		}
		std::string shouldBeHttp(uriStr.substr(0, std::min<size_t>(4, uriStr.length())));
		if (shouldBeHttp != "http") {
			errorMessage.assign(
			  "Value of key \"uri\", [" + uriStr + "], found under key \"" +
			  identitySourceType + "\", under key \"identitySources\" in response from [" +
			  identitySourceURL + "] is not an http or https URL"
			);
			return false;
		}

		// Extract the values for the keys, "isDefault" and
		// "isGlobalDefault" and use them to assign
		// defaultName and globalDefaultName
		bool isDefault = false;
		if (!extractValueUnderIdentitySourceType<bool>("isDefault", identitySourceType, identitySourceURL, identitySourceNode, isDefault, errorMessage)) {
			return false;
		}
		if (isDefault) {
			defaultName.assign(nameStr);
		}
		bool isGlobalDefault = false;
		if (!extractValueUnderIdentitySourceType<bool>("isGlobalDefault", identitySourceType, identitySourceURL, identitySourceNode, isGlobalDefault, errorMessage)) {
			return false;
		}
		if (isGlobalDefault) {
			globalDefaultName.assign(nameStr);
		}

		// Push a (name, uri) pair onto the map
		registerURLs[nameStr] = uriStr;
	}

	// The keyword matching identitySourceType was found. But if
	// nothing was under it, return false with an error message.
	if (registerURLs.size() == 0) {
		errorMessage.assign(
		  "Could not find any entries under key \"" + identitySourceType +
		  "\", under key \"identitySources\", in response from [" + identitySourceURL + "]"
		);
		return false;
	}

	// At least one registerURL was retrieved; return true
	return true;
}
