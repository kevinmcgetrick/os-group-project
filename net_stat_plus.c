#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>

#define MAX_INTERFACES 64 // max number of interfaces to track
#define NAME_SIZE 32 // max interface name length

//Xia Jie Ou

typedef struct {
    char name[NAME_SIZE]; // interface name
    unsigned long long rx_bytes; // total received bytes
    unsigned long long tx_bytes; // total transmitted bytes
} InterfaceData;

volatile sig_atomic_t keep_running = 1; // control flag for main loop

void handle_signal(int sig) {
    sig = sig; // avoid unused warning
    keep_running = 0; // stop program loop
} // end signal handler

void print_usage(char *program_name) {
    printf("Usage: %s [-i interface] [-t seconds] [-n samples]\n", program_name);
    printf("  -i <interface>   monitor only one interface\n");
    printf("  -t <seconds>     refresh interval in seconds (default: 1)\n");
    printf("  -n <samples>     stop after this many samples (default: unlimited)\n");
    printf("  -h               show help\n");
} // end print_usage

int read_network_stats(InterfaceData interfaces[], int max_interfaces, char *wanted_interface) {
    FILE *file; // file pointer for /proc/net/dev
    char line[512]; // line buffer
    int count = 0; // number of interfaces stored

    file = fopen("/proc/net/dev", "r"); // open Linux network stats file
    if (file == NULL) { // check open failure
        printf("Error opening /proc/net/dev\n"); // print error message
        return -1; // stop read function
    } // end file check

    fgets(line, sizeof(line), file); // skip header line 1
    fgets(line, sizeof(line), file); // skip header line 2

    while (fgets(line, sizeof(line), file) != NULL && count < max_interfaces) { // read each interface line
        char *colon; // pointer to colon separator
        char *start_ptr; // pointer to first character in interface name
        char interface_name[NAME_SIZE]; // temporary interface name
        size_t name_length; // interface name length

        unsigned long long rx_bytes; // receive bytes
        unsigned long long rx_packets; // receive packets
        unsigned long long rx_errors; // receive errors
        unsigned long long rx_drop; // receive drops
        unsigned long long rx_fifo; // receive fifo count
        unsigned long long rx_frame; // receive frame count
        unsigned long long rx_compressed; // receive compressed count
        unsigned long long rx_multicast; // receive multicast count

        unsigned long long tx_bytes; // transmit bytes
        unsigned long long tx_packets; // transmit packets
        unsigned long long tx_errors; // transmit errors
        unsigned long long tx_drop; // transmit drops
        unsigned long long tx_fifo; // transmit fifo count
        unsigned long long tx_colls; // collision count
        unsigned long long tx_carrier; // carrier count
        unsigned long long tx_compressed; // transmit compressed count

        colon = strchr(line, ':'); // find colon in current line
        if (colon == NULL) { // bad line format
            continue; // skip bad line
        } // end format check

        *colon = '\0'; // split interface name from data
        start_ptr = line; // point to start of line

        while (isspace((unsigned char)*start_ptr)) { // skip leading spaces
            start_ptr++; // move forward
        } // end while

        name_length = strcspn(start_ptr, " \t\n"); // find end of name
        if (name_length >= NAME_SIZE) { // prevent overflow
            name_length = NAME_SIZE - 1; // trim name
        } // end if

        memcpy(interface_name, start_ptr, name_length); // copy interface name
        interface_name[name_length] = '\0'; // add string terminator

        if (wanted_interface != NULL && strcmp(interface_name, wanted_interface) != 0) { // filter by chosen interface
            continue; // skip unmatched interface
        } // end filter check

        if (sscanf(colon + 1,
                   " %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                   &rx_bytes, &rx_packets, &rx_errors, &rx_drop, &rx_fifo, &rx_frame, &rx_compressed, &rx_multicast,
                   &tx_bytes, &tx_packets, &tx_errors, &tx_drop, &tx_fifo, &tx_colls, &tx_carrier, &tx_compressed) == 16) { // parse stats
            strcpy(interfaces[count].name, interface_name); // save interface name
            interfaces[count].rx_bytes = rx_bytes; // save rx bytes
            interfaces[count].tx_bytes = tx_bytes; // save tx bytes
            count++; // move to next slot
        } // end parse check
    } // end read loop

    fclose(file); // close stats file
    return count; // return number of interfaces read
} // end read_network_stats

void print_results(InterfaceData previous[], int previous_count, InterfaceData current[], int current_count, int interval, int sample_number) {
    int i; // loop counter for current interfaces

    printf("\nSample %d\n", sample_number); // print current sample number
    printf("%-12s %-15s %-15s %-15s %-15s\n", "Interface", "RX Bytes", "TX Bytes", "RX B/s", "TX B/s"); // table header

    for (i = 0; i < current_count; i++) { // go through each current interface
        int j; // loop counter for previous interfaces
        unsigned long long rx_rate = 0; // receive bytes per second
        unsigned long long tx_rate = 0; // transmit bytes per second

        for (j = 0; j < previous_count; j++) { // find matching old interface
            if (strcmp(current[i].name, previous[j].name) == 0) { // same interface found
                rx_rate = (current[i].rx_bytes - previous[j].rx_bytes) / (unsigned long long)interval; // compute rx rate
                tx_rate = (current[i].tx_bytes - previous[j].tx_bytes) / (unsigned long long)interval; // compute tx rate
                break; // stop searching
            } // end if
        } // end inner loop

        printf("%-12s %-15llu %-15llu %-15llu %-15llu\n",
               current[i].name,
               current[i].rx_bytes,
               current[i].tx_bytes,
               rx_rate,
               tx_rate); // print one interface row
    } // end outer loop
} // end print_results

int main(int argc, char *argv[]) {
    InterfaceData previous_stats[MAX_INTERFACES]; // previous snapshot
    InterfaceData current_stats[MAX_INTERFACES]; // current snapshot
    struct sigaction action; // signal action structure
    struct pollfd input_fd; // poll structure for stdin
    char *selected_interface = NULL; // interface filter
    int interval = 1; // refresh interval
    int sample_limit = -1; // number of samples, -1 means unlimited
    int previous_count; // interfaces in previous snapshot
    int current_count; // interfaces in current snapshot
    int sample_number = 0; // current sample count
    int option; // getopt result

    while ((option = getopt(argc, argv, "hi:t:n:")) != -1) { // parse command line arguments
        if (option == 'h') { // help option
            print_usage(argv[0]); // show help text
            return 0; // normal exit
        } else if (option == 'i') { // interface option
            selected_interface = optarg; // save interface name
        } else if (option == 't') { // time option
            interval = atoi(optarg); // convert to int
        } else if (option == 'n') { // sample option
            sample_limit = atoi(optarg); // convert to int
        } else { // invalid option
            print_usage(argv[0]); // show help for bad input
            return 1; // exit with error
        } // end option checks
    } // end getopt loop

    if (interval <= 0 || sample_limit == 0) { // validate numeric input
        printf("Invalid arguments\n"); // print error message
        return 1; // stop program
    } // end validation

    memset(&action, 0, sizeof(action)); // clear structure
    action.sa_handler = handle_signal; // set signal handler
    sigaction(SIGINT, &action, NULL); // handle Ctrl+C
    sigaction(SIGTERM, &action, NULL); // handle termination signal

    previous_count = read_network_stats(previous_stats, MAX_INTERFACES, selected_interface); // read first snapshot
    if (previous_count < 0) { // file read failed
        return 1; // stop program
    } // end read check

    if (previous_count == 0) { // no interfaces found
        printf("No matching interface found\n"); // print error message
        return 1; // stop program
    } // end interface check

    input_fd.fd = STDIN_FILENO; // watch keyboard input
    input_fd.events = POLLIN; // wait for readable input

    printf("netstatplus started. Press q then Enter to quit.\n"); // startup message

    while (keep_running && (sample_limit < 0 || sample_number < sample_limit)) { // keep monitoring until stop condition
        int poll_result; // result from poll

        poll_result = poll(&input_fd, 1, interval * 1000); // wait for timeout or user input
        if (poll_result < 0) { // check poll failure
            if (errno == EINTR) { // interrupted by signal
                continue; // continue safely
            } // end EINTR check

            printf("poll error\n"); // print poll error
            return 1; // stop program
        } // end poll check

        if (poll_result > 0 && (input_fd.revents & POLLIN)) { // user typed something
            char buffer[32]; // input buffer

            if (fgets(buffer, sizeof(buffer), stdin) != NULL) { // read user input
                if (buffer[0] == 'q') { // quit command
                    break; // leave loop
                } // end quit check
            } // end read check
        } // end input handling

        current_count = read_network_stats(current_stats, MAX_INTERFACES, selected_interface); // read next snapshot
        if (current_count < 0) { // read failed
            return 1; // stop program
        } // end loop read check

        sample_number++; // move to next sample
        print_results(previous_stats, previous_count, current_stats, current_count, interval, sample_number); // print current results

        memcpy(previous_stats, current_stats, sizeof(current_stats)); // copy current snapshot into previous snapshot
        previous_count = current_count; // update interface count
    } // end monitor loop

    printf("\nnetstatplus stopped.\n"); // closing message
    return 0; // successful end
} // end main
