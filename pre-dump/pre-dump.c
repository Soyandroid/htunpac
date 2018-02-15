#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <windows.h>

#include "util/fs.h"
#include "util/str.h"

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage: %s <htpac'd exe>\n", argv[0]);
        return -1;
    }

    char* filename = argv[1];
    char* backup_filename = util_str_dup(argv[1]);
    size_t len = strlen(backup_filename);

    if (len < 4) {
        printf("Input file (%s) must have .exe extension\n", backup_filename);
        return -1;
    }

    memcpy(backup_filename + len - 3, "bak", 3);

    if (file_exists(backup_filename)) {
        free(backup_filename);
        printf("Backup file already exists, skip patching\n");
        return 0;
    }

    if (!CopyFileA(filename, backup_filename, TRUE)) {
        printf("Creating backup of original file failed: %ld\n", 
            GetLastError());
        free(backup_filename);
        return -1;
    }

    free(backup_filename);

    void* buffer;
    size_t size; 

    if (!file_load(filename, &buffer, &size, false)) {
        printf("Loading input file %s failed\n", filename);
        return -1;
    }

    const char* str_lib = "KeRnEl32.dLl";
    size_t str_lib_len = strlen(str_lib);
    bool found = false;

    for (size_t i = 0; i < size; i++) {
        if (!memcmp(buffer + i, str_lib, str_lib_len)) {
            printf("Found %s string at 0x%X, patching\n", str_lib, i);
            found = true;

            memcpy(buffer + i, "kernal32.dll", str_lib_len);

            break;
        }
    }

    if (!found) {
        free(buffer);
        printf("File %s doesn't seem to be a htpac'd executable\n", filename);

        return -1;
    }

    if (!file_save(filename, buffer, size)) {
        free(buffer);
        printf("Writing output file %s failed\n", filename);
        return -1;
    }

    free(buffer);

    printf("Prepared for dumping\n");
    
    return 0;
}