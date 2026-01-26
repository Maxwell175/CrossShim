/**
 * Helper program for exec tests
 * This gets executed by the exec test to verify execve works correctly.
 *
 * Behavior depends on first argument:
 *   "echo_args"  - Print all arguments and exit 0
 *   "echo_env"   - Print specified env vars and exit 0
 *   "exit_code"  - Exit with the code given in arg2
 *   (default)    - Print "EXEC_HELPER_OK" and exit 0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[], char *envp[]) {
    if (argc >= 2 && strcmp(argv[1], "echo_args") == 0) {
        /* Print all arguments */
        printf("ARGC=%d\n", argc);
        for (int i = 0; i < argc; i++) {
            printf("ARGV[%d]=%s\n", i, argv[i]);
        }
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], "echo_env") == 0) {
        /* Print environment variables that start with TEST_ */
        for (char **env = envp; *env != NULL; env++) {
            if (strncmp(*env, "TEST_", 5) == 0) {
                printf("ENV: %s\n", *env);
            }
        }
        return 0;
    }

    if (argc >= 3 && strcmp(argv[1], "exit_code") == 0) {
        /* Exit with specified code */
        int code = atoi(argv[2]);
        return code;
    }

    /* Default: print marker and exit success */
    printf("EXEC_HELPER_OK\n");
    return 0;
}
