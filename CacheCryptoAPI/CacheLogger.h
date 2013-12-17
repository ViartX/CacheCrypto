#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <wchar.h>
#include <time.h>
#include <Windows.h>
#include <WinCrypt.h>

// Constants define the level of details in logs
#define LOGLEVELNONE	0			// no logs
#define LOGLEVELERR		1			// errors only
#define LOGLEVELALL		2			// log everithing

#define LOGLEVELDEFAULT LOGLEVELALL
#define LOGFILENAME L"C:\\CacheCrypto.log"

// Constants define destination of program output
#define LOGTARGETFILE 1				// logfile
#define LOGTARGETCONSOLE 2			// console

// Basic class, provides logging functions
class CacheLogger
{

private:
	wchar_t * LogFileName;					// name of log file
	int LogLevel;							// level of details in log messages, used with constants LOGLEVELNONE, LOGLEVELERR, LOGLEVELALL
	int LogSourceLocation;					// shows what file and line in file initiated call, for debugging purposes
	int LogTargets;							// defines destination of logging actions: to file with LOGTARGETFILE or(and) to console LOGTARGETCONSOLE

public:
	CacheLogger(void);						// basic class constructor
	~CacheLogger(void);						// basic class destructor

void logMessage(wchar_t* msg, int level, char* FFUNCTION, char* FFILE, int FLINE);		// function log messages, applies all options in parameters. Used via macros LogMessage(msg)
void logMessage(wchar_t* msg);															// function log messages

int setLogFileName(wchar_t* fn);			// set value to LogFileName
int setLogTargets(int targets);				// set value to LogTargets
int setLogLevel(int logLevel);				// set value to LogLevel
int setLogSourceLocation(int flag);			// set value to LogSourceLocation

void logMessageToFile(wchar_t* msg);		// output message to file
void logMessageToConsole(wchar_t* msg);		// output message to console windpe as it is, checking the LogTargets
void consoleMessage(wchar_t * msg);			// output message to console windpe as it is, anyway

wchar_t* getLastErrorCode();				// write code of last occured error
wchar_t* getLastErrorMsg();					// write text of last error
void logLastError();						// write both code and last error text
void logError(wchar_t * msg);

};

