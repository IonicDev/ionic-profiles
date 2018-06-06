/* Copyright 2017-2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>
#include "ISLog.h"


void fatal(const int nErr, const std::string sMessage)
{
    std::cout << "[ERROR] " << sMessage << " (" << nErr << ")" << std::endl;
    exit(nErr);
}

void passOrDie(const int nErr, const std::string sMessage)
{
    if (nErr != 0)
        fatal(nErr, sMessage);
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
