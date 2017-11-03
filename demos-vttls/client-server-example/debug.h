/*
 * debug.h
 *
 *  Created on: Nov 3, 2017
 *      Author: Miguel Pardal
 */

#ifndef DEMOS_VTTLS_DEBUG_H_
#define DEMOS_VTTLS_DEBUG_H_

#include <stdio.h>

//
// Debug macros
//

// credits: https://stackoverflow.com/questions/1644868/c-define-macro-for-debug-printing

// master flag: 0 debug off, 1 debug on
#define DEBUG 1

#define debug_print(text) \
            do { if (DEBUG) fprintf(stderr, "%s", text); } while (0)

#define debug_println(line) \
            do { if (DEBUG) fprintf(stderr, "%s\n", line); } while (0)

#define debug_printf(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)


#endif /* DEMOS_VTTLS_DEBUG_H_ */
