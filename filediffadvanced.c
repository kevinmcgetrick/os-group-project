/*
* filediffadvanced.c
*
* Compares two files either:
* 1) as text, line by line (default)
* 2) as binary, byte by byte using mmap() (-b option)
*
* Features:
* - getopt() argument parsing
* - line-by-line difference reporting
* - binary comparison with mmap()
* - execution time measurement
* - optional limit on number of printed differences
*
* Compile:
* gcc filediffadvanced.c -o filediffadvanced
*
* Usage:
* ./filediffadvanced file1.txt file2.txt
* ./filediffadvanced -m 5 file1.txt file2.txt
* ./filediffadvanced -b file1.bin file2.bin
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <errno.h>

#define MAX_LINE_LEN 4096

typedef struct {
long total_differences;
long printed_differences;
double elapsed_ms;
} DiffResult;

/* Return current time in milliseconds */
static double current_time_ms(void) {
struct timespec ts;
if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
perror("clock_gettime");
return 0.0;
}
return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

static void print_usage(const char *progname) {
fprintf(stderr,
"Usage: %s [-b] [-m max_diffs] <file1> <file2>\n"
" -b Compare files in binary mode using mmap()\n"
" -m max_diffs Maximum number of differences to print (default: all)\n",
progname
);
}

/* ---------------- TEXT MODE COMPARISON ---------------- */
static int compare_text_files(const char *file1, const char *file2, long max_print, DiffResult *result) {
FILE *fp1 = fopen(file1, "r");
FILE *fp2 = fopen(file2, "r");

if (!fp1) {
perror("fopen file1");
return -1;
}
if (!fp2) {
perror("fopen file2");
fclose(fp1);
return -1;
}

char line1[MAX_LINE_LEN];
char line2[MAX_LINE_LEN];
long line_num = 1;

double start = current_time_ms();

while (1) {
char *r1 = fgets(line1, sizeof(line1), fp1);
char *r2 = fgets(line2, sizeof(line2), fp2);

if (r1 == NULL && r2 == NULL) {
break; /* both files ended */
}

if (r1 == NULL || r2 == NULL) {
result->total_differences++;

if (max_print < 0 || result->printed_differences < max_print) {
printf("Difference at line %ld:\n", line_num);
printf(" %s: %s", file1, (r1 ? line1 : "[EOF]\n"));
printf(" %s: %s", file2, (r2 ? line2 : "[EOF]\n"));
printf("\n");
result->printed_differences++;
}

line_num++;
continue;
}

if (strcmp(line1, line2) != 0) {
result->total_differences++;

if (max_print < 0 || result->printed_differences < max_print) {
printf("Difference at line %ld:\n", line_num);
printf(" %s: %s", file1, line1);
if (line1[strlen(line1) - 1] != '\n') printf("\n");
printf(" %s: %s", file2, line2);
if (line2[strlen(line2) - 1] != '\n') printf("\n");
printf("\n");
result->printed_differences++;
}
}

line_num++;
}

double end = current_time_ms();
result->elapsed_ms = end - start;

fclose(fp1);
fclose(fp2);
return 0;
}

/* ---------------- BINARY MODE COMPARISON USING MMAP ---------------- */
static int compare_binary_files(const char *file1, const char *file2, long max_print, DiffResult *result) {
int fd1 = -1, fd2 = -1;
struct stat st1, st2;
unsigned char *map1 = NULL;
unsigned char *map2 = NULL;

fd1 = open(file1, O_RDONLY);
if (fd1 < 0) {
perror("open file1");
return -1;
}

fd2 = open(file2, O_RDONLY);
if (fd2 < 0) {
perror("open file2");
close(fd1);
return -1;
}

if (fstat(fd1, &st1) < 0) {
perror("fstat file1");
close(fd1);
close(fd2);
return -1;
}

if (fstat(fd2, &st2) < 0) {
perror("fstat file2");
close(fd1);
close(fd2);
return -1;
}

double start = current_time_ms();

if (st1.st_size > 0) {
map1 = mmap(NULL, st1.st_size, PROT_READ, MAP_PRIVATE, fd1, 0);
if (map1 == MAP_FAILED) {
perror("mmap file1");
close(fd1);
close(fd2);
return -1;
}
}

if (st2.st_size > 0) {
map2 = mmap(NULL, st2.st_size, PROT_READ, MAP_PRIVATE, fd2, 0);
if (map2 == MAP_FAILED) {
perror("mmap file2");
if (map1 && map1 != MAP_FAILED) munmap(map1, st1.st_size);
close(fd1);
close(fd2);
return -1;
}
}

off_t min_size = (st1.st_size < st2.st_size) ? st1.st_size : st2.st_size;

for (off_t i = 0; i < min_size; i++) {
if (map1[i] != map2[i]) {
result->total_differences++;

if (max_print < 0 || result->printed_differences < max_print) {
printf("Byte difference at offset %lld: 0x%02X vs 0x%02X\n",
(long long)i, map1[i], map2[i]);
result->printed_differences++;
}
}
}

if (st1.st_size != st2.st_size) {
off_t extra = llabs((long long)(st1.st_size - st2.st_size));
result->total_differences += extra;

if (max_print < 0 || result->printed_differences < max_print) {
printf("Files differ in size: %s=%lld bytes, %s=%lld bytes\n",
file1, (long long)st1.st_size,
file2, (long long)st2.st_size);
}
}

double end = current_time_ms();
result->elapsed_ms = end - start;

if (map1 && map1 != MAP_FAILED && st1.st_size > 0) {
munmap(map1, st1.st_size);
}
if (map2 && map2 != MAP_FAILED && st2.st_size > 0) {
munmap(map2, st2.st_size);
}

close(fd1);
close(fd2);
return 0;
}

int main(int argc, char *argv[]) {
int opt;
int binary_mode = 0;
long max_print = -1; /* default: print all */
DiffResult result = {0, 0, 0.0};

while ((opt = getopt(argc, argv, "bm:")) != -1) {
switch (opt) {
case 'b':
binary_mode = 1;
break;
case 'm': {
char *endptr = NULL;
errno = 0;
max_print = strtol(optarg, &endptr, 10);

if (errno != 0 || endptr == optarg || *endptr != '\0' || max_print < 0) {
fprintf(stderr, "Invalid value for -m: %s\n", optarg);
return EXIT_FAILURE;
}
break;
}
default:
print_usage(argv[0]);
return EXIT_FAILURE;
}
}

if (argc - optind != 2) {
print_usage(argv[0]);
return EXIT_FAILURE;
}

const char *file1 = argv[optind];
const char *file2 = argv[optind + 1];

int rc;
if (binary_mode) {
printf("Mode: binary comparison (mmap)\n");
rc = compare_binary_files(file1, file2, max_print, &result);
} else {
printf("Mode: text comparison (line by line)\n");
rc = compare_text_files(file1, file2, max_print, &result);
}

if (rc != 0) {
return EXIT_FAILURE;
}

printf("--------------------------------------------------\n");
printf("Total differences: %ld\n", result.total_differences);
printf("Printed differences: %ld\n", result.printed_differences);
printf("Execution time: %.3f ms\n", result.elapsed_ms);

if (result.total_differences == 0) {
printf("Result: files are identical\n");
} else {
printf("Result: files are different\n");
}

return EXIT_SUCCESS;
}