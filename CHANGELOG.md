# IonicTools Changelog

## Version 2.3.0

#### Added
   Add support for kns during enrollment
   Add support for Ionic Authentication enrollment

#### Updated
   Edit docker build scripts for use with GitHub ionic-profiles repository
   Move .h files from src to new include directory
   Verify/create folder for default persistor type (Windows, MacOS)

## Version 2.2.1

#### Fixed
PI-1402 ionic-profiles hangs waiting for a token when given a bad path
PI-1403 ionic-profiles fails to write persistor or throw an error given a bad destination path
  Verify folder path for default persistor, on Windows system, exists, or create if it doesn't

## Version 2.2

