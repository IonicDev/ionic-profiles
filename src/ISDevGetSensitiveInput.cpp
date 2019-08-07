/* Copyright 2018 - 2019 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include "ISDevGetSensitiveInput.h"
#include <iostream>

using namespace std;

#if defined (_WIN32) || defined (_WIN64)

#include <windows.h>
#include <strsafe.h>

void setErrorMessage(string & errorMessage) {
	DWORD lastError = GetLastError();
	if (lastError == 0) {
		return;
	}
	LPVOID msgBuf = NULL;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		lastError,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &msgBuf,
		0,
		NULL
	);
	errorMessage.assign((char *)msgBuf);
	LocalFree(msgBuf);
}

bool getSensitiveInput(const string& prompt, string& sensitiveInput, string& errorMessage) {
	// Change console mode
	errorMessage.resize(0);
	DWORD       consoleMode;
	const DWORD numChToRead = 1;
	DWORD       numChRead;
	HANDLE      inputHandle = GetStdHandle(STD_INPUT_HANDLE);
	if (!GetConsoleMode(inputHandle, &consoleMode)) {
		// errorMessage is set based on failure of
		// ReadConsole, before the coming
		// SetConsoleMode resets the error.
		setErrorMessage(errorMessage);
		return false;
	}
	if (!SetConsoleMode(inputHandle, consoleMode & (~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT)))) {
		// To prevent sensitive input from being echoed,
		// return false to fall back to another technique.
		setErrorMessage(errorMessage);
		return false;
	}

	// Prompt for sensitive information, then process it one character at a time
	cout << prompt << ": ";
	const char    backspaceCh = 8;  // \b
	const char    enterKeyCh  = 13; // \r
	char          inputCh     = 0;
	sensitiveInput.resize(0);
	while (true) {
		// Read one character from the console
		numChRead = 0; // Tests that ReadConsole did something
		bool status = ReadConsole(inputHandle, &inputCh, numChToRead, &numChRead, NULL);

		// Handle failure of ReadConsole, such as the terminal
		// being the wrong type.
		if (!status || (numChRead != numChToRead)) {
			// errorMessage is set based on failure of
			// ReadConsole, before the coming
			// SetConsoleMode resets the error.
			setErrorMessage(errorMessage);

			// The terminal probably doesn't support
			// SetConsoleMode(), but set the console mode
			// back anyway.
			SetConsoleMode(inputHandle, consoleMode);
			return false;
		}

		// Handle <Enter> key
		if (inputCh == enterKeyCh) {
			SetConsoleMode(inputHandle, consoleMode);
			return true;
		}

		// Handle input up to the <Enter> key. Ignore any
		// backspaces that try to erase an empty input.
		if (inputCh != backspaceCh) {
			sensitiveInput.append(1, inputCh);
		}
		else if (sensitiveInput.size() != 0) {
			sensitiveInput.resize(sensitiveInput.size() - 1);
		}
	}
}

#else

#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

bool getSensitiveInput(const string& prompt, string& sensitiveInput, string& errorMessage) {
	// Change console mode
	errorMessage.resize(0);
	struct termios oldTermios, newTermios;
	errno = 0;
	if (tcgetattr(STDIN_FILENO, &oldTermios) == -1) {
		// Later calls to getchar() should work whether or not
		// tcgetattr works. To prevent sensitive input from
		// being echoed, return false to fall back to another
		// technique.
		errorMessage.assign("tcgetattr() failed with error " + string(strerror(errno)));
		return false;
	}
	newTermios = oldTermios;
	newTermios.c_lflag &= ~(ICANON | ECHO);
	errno = 0;
	if (tcsetattr(STDIN_FILENO, TCSANOW, &newTermios) == -1) {
		// Later calls to getchar() should work whether or not
		// tcsetattr works. To prevent sensitive input from
		// being echoed, return false to fall back to another
		// technique.
		errorMessage.assign("First call to tcsetattr() failed with error " + string(strerror(errno)));
		return false;
	}

	// Prompt for sensitive information, then process it one character at a time
	cout << prompt << ": ";
	const int     backspace = 8;  // \b
	const int     enterKey  = 10; // \n
	int           input     = 0;
	sensitiveInput.resize(0);
	while (true) {
		// Read one character from the console
		input = getchar();

		// Handle EOF (Ctrl-D) and <Enter> key
		if ((input == EOF) || (input == enterKey)) {
			errno = 0;
			if (tcsetattr(STDIN_FILENO, TCSANOW, &oldTermios) == -1) {
				// Input has been gathered, so return
				// drop down to where true is returned
				errorMessage.assign("Second call to tcsetattr() failed with error " + string(strerror(errno)));
			}
			return true;
		}

		// Handle input up to EOF or the <Enter> key. Ignore
		// any backspaces that try to erase an empty input.
		if (input != backspace) {
			sensitiveInput.append(1, (char)input);
		}
		else if (sensitiveInput.size() != 0) {
			sensitiveInput.resize(sensitiveInput.size() - 1);
		}
	}
}
#endif
