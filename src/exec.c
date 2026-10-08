#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "exec.h"

/*
 * Runs one command through /bin/sh -c. Returns its exit status, or -1 when
 * it could not be started or did not exit normally.
 */
static int run_line(const char *cmd, int quiet)
{
    pid_t pid;
    int status;

    fflush(stdout);
    fflush(stderr);
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (quiet) {
            int fd = open("/dev/null", O_WRONLY);

            if (fd >= 0) {
                dup2(fd, STDERR_FILENO);
                close(fd);
            }
        }
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

int bw_exec_run(const char *script, int flags, FILE *dry_out)
{
    const char *p = script;

    while (*p != '\0') {
        const char *eol = strchr(p, '\n');
        size_t len = eol != NULL ? (size_t)(eol - p) : strlen(p);
        char *line;
        int rc;

        if (len == 0) {
            p++;
            continue;
        }
        line = malloc(len + 1);
        if (line == NULL) {
            fprintf(stderr, "bwopt: out of memory\n");
            return -1;
        }
        memcpy(line, p, len);
        line[len] = '\0';
        p += len + (eol != NULL);

        if (flags & BW_EXEC_DRY_RUN) {
            fprintf(dry_out, "%s\n", line);
            free(line);
            continue;
        }

        rc = run_line(line, flags & BW_EXEC_IGNORE_ERRORS);
        if (rc != 0 && !(flags & BW_EXEC_IGNORE_ERRORS)) {
            if (rc > 0)
                fprintf(stderr, "bwopt: command failed (exit %d): %s\n", rc, line);
            else
                fprintf(stderr, "bwopt: command failed: %s\n", line);
            free(line);
            return rc;
        }
        free(line);
    }
    if ((flags & BW_EXEC_DRY_RUN) && ferror(dry_out))
        return -1;
    return 0;
}
