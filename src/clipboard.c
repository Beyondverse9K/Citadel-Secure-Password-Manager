#include "clipboard.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

void clipboard_copy_and_clear(const char* text, int timeout_seconds) {
    signal(SIGCHLD, SIG_IGN);
    FILE* pipe = popen("xclip -selection clipboard", "w");
    if (!pipe) {
        perror("Fatal: popen failed to run xclip");
        return;
    }
    fprintf(pipe, "%s", text);
    pclose(pipe);
    printf("Password copied to clipboard. It will be cleared in %d seconds.\n", timeout_seconds);
    pid_t pid = fork();
    if (pid == -1) {
        perror("Fatal: fork failed");
        return;
    }
    if (pid == 0) {
        sleep(timeout_seconds);
        system("echo -n '' | xclip -selection clipboard > /dev/null 2>&1");
        exit(EXIT_SUCCESS);
    }
}