/*
 * demo.c
 *
 *  Created on: Nov 5, 2017
 *      Author: Miguel Pardal
 */

#include "demo.h"

// if running on a graphical terminal,
// call default application to open file according to its type
void demo_open_file(const char* filePath) {
	// if file path is null or has length 0, ignore
	if (filePath == NULL)
		return;
	const int filePathLen = strlen(filePath);
	if (filePathLen < 1)
		return;

	// check terminal type
	const char* xdg = getenv("XDG_CURRENT_DESKTOP");
	if (xdg == NULL || strlen(xdg) == 0) {
		// text terminal
		const char *fileCmd = "file";
		const int fileCmdLen = strlen(fileCmd);

		const int cmdLen = fileCmdLen + 1 + filePathLen + 1;
		char *cmd = (char*) malloc(cmdLen);
		sprintf(cmd, "%s %s\n", fileCmd, filePath);

		// execute command
		system(cmd);

		free(cmd);
	} else {
		// graphical terminal
		const char *openCmd = "xdg-open";
		const int openCmdLen = strlen(openCmd);

		const char *reDirAllOut = "> /dev/null 2>&1";
		const int reDirAllOutLen = strlen(reDirAllOut);

		const int cmdLen = openCmdLen + 1 + filePathLen + 1 + reDirAllOutLen
				+ 1;
		char *cmd = (char*) malloc(cmdLen);
		sprintf(cmd, "%s %s %s\n", openCmd, filePath, reDirAllOut);

		// execute command
		system(cmd);

		free(cmd);
	}
}

// credits: https://stackoverflow.com/a/5309508/129497
const char *get_filename_ext(const char *filename) {
	const char *dot = strrchr(filename, '.');
	if (!dot || dot == filename)
		return "";
	return dot + 1;
}
