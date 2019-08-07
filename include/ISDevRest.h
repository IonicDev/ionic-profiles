/* Copyright 2018 - 2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#ifndef __IONIC_DEVREST_H
#define __IONIC_DEVREST_H

#include <string>
#include <map>

bool getEnrollmentURL(
  const std::string& keySpace,
  std::string& keyspaceURL,
  std::string& enrollmentURL,
  std::string& errorMessage
);

bool getRegisterURLs(
  const std::string&                  identitySourceURL,
  const std::string&                  identitySourceType,
  std::map<std::string, std::string>& registerURLs,
  std::string&                        defaultName,
  std::string&                        globalDefaultName,
  std::string&                        errorMessage
);

#endif // __IONIC_DEVREST_H
