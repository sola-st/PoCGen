#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *file_path = "/.executed";

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "reset") == 0) {
        if (unlink(file_path) == 0) {
            printf("File %s has been removed.\n", file_path);
        } else {
            perror("Error removing the file");
        }
    } else {
        FILE *file = fopen(file_path, "w");
        if (file) {
            fclose(file);
            printf("File %s has been created.\n", file_path);
        } else {
            perror("Error creating the file");
        }
    }
    return 0;
}
