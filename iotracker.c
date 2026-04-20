#define _GNU_SOURCE //required 

#include <stdbool.h> //booleans
#include <dirent.h> //directory scanning
#include <getopt.h>
#include <poll.h> //for regular intervals
#include <stdio.h>
#include <errno.h> //error handling
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h> // file existence & file type checks
#include <unistd.h>

#define MAX_PATH_LEN 100
#define MAX_NAME_LEN 100
#define INOTIFY_BUF_LEN (32 * (sizeof(struct inotify_event) + MAX_NAME_LEN + 1))
#define MAX_EVENTS 32

void print_help(char *program_name)
{
	printf("SUMMARY\n");
	printf("    %s -p <pid> -w <dir>\n", program_name);
	printf("    %s -h\n\n", program_name);
	printf("DESCRIPTION\n");
	printf("    Watches filesystem events under <dir> and prints attributed\n");
	printf("    READ/WRITE paths each tick. Also prints lifetime read_bytes and\n");
	printf("    write_bytes from /proc/<pid>/io.\n\n");
	printf("OPTIONS\n");
	printf("    -p <pid>   target process id to attribute activity\n");
	printf("    -w <dir>   directory root to watch\n");
	printf("    -h         show this help and exit\n\n");
	printf("EXAMPLES\n");
	printf("    %s -p 12345 -w /home/user/data\n", program_name);
	printf("    %s -h\n", program_name);
}

int parse_args(int argc, char **argv, int *process_id, char **watch_directory)
{
	int option; //p w
	int has_pid = 0;
	int has_watch_dir = 0;

	opterr = 0;
	while ((option = getopt(argc, argv, "hp:w:")) != -1) {
		switch (option) {
		case 'h':
			print_help(argv[0]);
			return 1;
		case 'p':
			*process_id = atoi(optarg); //argv provides everything in ascii
			has_pid = 1;
			break;
		case 'w':
			*watch_directory = optarg;
			has_watch_dir = 1;
			break;
		default:
			fprintf(stderr, "invalid arguments\n\n");
			print_help(argv[0]);
			return -1;
		}
	}
	if (!has_pid || !has_watch_dir) {
		fprintf(stderr, "missing required arguments\n\n");
		print_help(argv[0]);
		return -1;
	}
	return 0;
}

//iotracker: cumulative disk bytes
struct io_counts {
	unsigned long read_bytes;
	unsigned long write_bytes;
	int read_successful;
};

int read_proc_io(int process_id, struct io_counts *io_snapshot)
{
	char proc_io_path[MAX_PATH_LEN];
	FILE *proc_file; // /proc/ is a virtual filesystem created by the Linux kernel that exposes system and process information as files you can read
	char line[256];   //example line from /proc/<pid>/io: read_bytes: 319815680
	char key[64]; // key would be read_bytes in the prev example
	unsigned long value; // value would be 319815680 in the prev example
	int path_len;

	io_snapshot->read_successful = 0;
	io_snapshot->read_bytes = io_snapshot->write_bytes = 0;

	path_len = snprintf(proc_io_path, sizeof(proc_io_path), "/proc/%d/io",
	                    process_id);
	if (path_len < 0 || path_len >= (int)sizeof(proc_io_path)) {
		fprintf(stderr, "path too long\n");
		return -1;
	}

	proc_file = fopen(proc_io_path, "r");
	if (proc_file == NULL) {
		fprintf(stderr, "cannot open %s: %s\n", proc_io_path,
		        strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), proc_file)) {
		if (sscanf(line, "%63[^:]: %lu", key, &value) == 2) {
			if (strcmp(key, "read_bytes") == 0) {
				io_snapshot->read_bytes = value;
			} else if (strcmp(key, "write_bytes") == 0) {
				io_snapshot->write_bytes = value;
			}
		}
	}
	if (ferror(proc_file)) {
		fprintf(stderr, "read error %s\n", proc_io_path);
		fclose(proc_file);
		return -1;
	}
	fclose(proc_file);
	io_snapshot->read_successful = 1;
	return 0;
}

//determines which files a pid has open
int pid_has_path_open(int process_id, const char *absolute_path)
{
	DIR *fd_directory;
	struct dirent *fd_entry;
	char fd_directory_path[MAX_PATH_LEN];
	char fd_link_path[MAX_PATH_LEN];
	char fd_target_path[MAX_PATH_LEN];
	int build_length;
	int link_length;
	char *parse_end;

	//build the path to the fd directory & check if its too long at the same time
	build_length = snprintf(fd_directory_path, sizeof(fd_directory_path), "/proc/%d/fd",
	                        process_id);
	if (build_length >= (int)sizeof(fd_directory_path)) {
		return 0; //path too long for the path array
	}
	fd_directory = opendir(fd_directory_path);
	if (fd_directory == NULL) {
		return 0; //failed to open the fd directory
	}
	while ((fd_entry = readdir(fd_directory)) != NULL) {
		if (strcmp(fd_entry->d_name, ".") == 0 ||
		        strcmp(fd_entry->d_name, "..") == 0) {
			continue;
		}// ignore some dirs


		errno = 0;
		(void)strtol(fd_entry->d_name, &parse_end, 10);
		if (errno != 0 || parse_end == fd_entry->d_name || *parse_end != '\0') {
			continue;
		}
		build_length = snprintf(fd_link_path, sizeof(fd_link_path), "%s/%s",
		                        fd_directory_path, fd_entry->d_name);
		if (build_length < 0 || build_length >= (int)sizeof(fd_link_path)) {
			continue;
		}
		link_length = (int)readlink(fd_link_path, fd_target_path,// read symbolic links
		                            sizeof(fd_target_path) - 1);// -1 for the null terminator
		if (link_length < 0) {
			continue; // if symbolic link leads nowhere, then its invalid, we continue to the next iteration
		}
		fd_target_path[link_length] = '\0';
		if (strcmp(fd_target_path, absolute_path) == 0) { // compare watched path user provided with the symbolic link
			closedir(fd_directory);
			return 1;
		}


		// manage unlinked-but-open files or open files that have been deleted but not yet closed
		{
			int absolute_path_length = (int)strlen(absolute_path);
			if (strncmp(fd_target_path, absolute_path, absolute_path_length) == 0 &&
			        strcmp(fd_target_path + absolute_path_length, " (deleted)") == 0) {
				closedir(fd_directory);
				return 1;
			}
		}
	}
	closedir(fd_directory);
	return 0;
}


// A shell wrapper often does I/O through child processes
// Check direct children too so -p <shell-pid> can still attribute paths

int pid_or_child_has_path_open(int process_id, const char *absolute_path)
{
	char children_file_path[MAX_PATH_LEN];
	FILE *children_file;
	int path_length;
	int child_process_id;

	if (pid_has_path_open(process_id, absolute_path)) {
		return 1;
	}
	path_length = snprintf(children_file_path, sizeof(children_file_path),
	                       "/proc/%d/task/%d/children", process_id, process_id);
	if (path_length < 0 || path_length >= (int)sizeof(children_file_path)) {
		return 0;
	}
	children_file = fopen(children_file_path, "r");
	if (children_file == NULL) {
		return 0;
	}
	while (fscanf(children_file, "%d", &child_process_id) == 1) {
		if (pid_has_path_open(child_process_id, absolute_path)) {
			fclose(children_file);
			return 1;
		}
	}
	fclose(children_file);
	return 0;
}

// one line like WRITE /home/caili/iotest/a.txt
struct event_row {
	char operation[6];
	char path[MAX_PATH_LEN];
};

// per-tick event list
struct events_buf {
	struct event_row entries[MAX_EVENTS]; // would show as many as possible but simple array needs compile time size
	int event_count;
};

//  bitmask used to identify specific filesystem events to monitor or to describe events that have occurred
const char *access_rw_label(unsigned int mask)
{
	if ((mask & (IN_MODIFY | IN_CLOSE_WRITE)) != 0)
		return "WRITE";
	return "READ";
}

void event_add(struct events_buf *events_buffer, const char *operation_label,
               const char *path)
{
	int write_length;

	if (events_buffer->event_count >= MAX_EVENTS) {
		return;
	}
	// copy the operation (read or write) and path into another slot to batch print per tick
	write_length = snprintf(events_buffer->entries[events_buffer->event_count].operation,
	                        sizeof(events_buffer->entries[events_buffer->event_count].operation),
	                        "%s", operation_label);
	write_length = snprintf(events_buffer->entries[events_buffer->event_count].path,
	                        MAX_PATH_LEN, "%s", path);
	if (write_length < 0 || write_length >= MAX_PATH_LEN) {
		snprintf(events_buffer->entries[events_buffer->event_count].path, MAX_PATH_LEN, "%s",
		         "(path too long)");
	}
	events_buffer->event_count++;
}

void readall_inotify(int inotify_fd, const char *watch_dir_abs, int pid,
                     struct events_buf *events)
{
	unsigned char buf[INOTIFY_BUF_LEN];
	int bytes_read;
	int offset;
	const struct inotify_event *event;
	char file_path[MAX_PATH_LEN];
	int event_size;
	int path_len;

	while (true) {
		bytes_read = (int)read(inotify_fd, buf, sizeof(buf));
		if (bytes_read < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN) {
				break;  //EAGAIN means queue is fully read for now
			}
			perror("read inotify");
			break;
		}
		if (bytes_read == 0) {
			break;
		}
		// inotify events are packed into a group, so we need to separate each chunk into 1 each
		offset = 0;
		while (offset + (int)sizeof(*event) <= bytes_read) {
			event = (const struct inotify_event *)(buf + offset);
			event_size = (int)sizeof(*event) + (int)event->len; //preventing overflow
			if (event->len > 0) {
				path_len = snprintf(file_path, sizeof(file_path), "%s/%s", // "/home/caili/iotest" + "/" + "big.bin"
				                    watch_dir_abs, event->name);
			} else {
				path_len = snprintf(file_path, sizeof(file_path), "%s",
				                    watch_dir_abs);
			}
			offset += event_size;
			if (path_len < 0 || path_len >= (int)sizeof(file_path)) {
				continue;
			}
			//Only keep path events tied to the target process tree
			if (pid_or_child_has_path_open(pid, file_path)) {
				event_add(events, access_rw_label(event->mask), file_path);
			}
		}
	}
}


void print_tick(int process_id, struct events_buf *events_buffer,
                struct io_counts *io_snapshot)
{
	int event_index;

	printf("pid %d\n", process_id);

	// Per-tick activity lines in READ/WRITE + path format. For example: READ /home/caili/iotest/a.txt
	if (events_buffer->event_count == 0) {
		printf("  (no attributed events this tick)\n");
	} else {
		for (event_index = 0; event_index < events_buffer->event_count;
		        event_index++) {
			printf("%s  %s\n",
			       events_buffer->entries[event_index].operation,
			       events_buffer->entries[event_index].path);
		}
	}

	// Disk read/write statistics: kernel cumulative counters
	if (io_snapshot->read_successful) {
		printf("  read_bytes=%lu write_bytes=%lu\n", io_snapshot->read_bytes,
		       io_snapshot->write_bytes);
	} else {
		printf("  (could not read /proc/%d/io)\n", process_id);
	}
	fflush(stdout);
}

int main(int argc, char **argv)
{
	int target_pid = 0;
	char *watch_dir = NULL;
	char watch_dir_abs[MAX_PATH_LEN];
	int inotify_fd, watch_descriptor;
	struct pollfd poll_fd;
	struct events_buf events;
	struct io_counts current_io, previous_io;
	int poll_result;
	int parse_result;

	//inital commandline arguments check
	parse_result = parse_args(argc, argv, &target_pid, &watch_dir);
	if (parse_result > 0) {
		return 0;
	}
	if (parse_result < 0) {
		return 1;
	}

	//verifies target process exists right now before entering loop
	if (snprintf(watch_dir_abs, sizeof(watch_dir_abs), "/proc/%d", target_pid) >=
	        (int)sizeof(watch_dir_abs)) {
		fprintf(stderr, "pid path too long\n");
		return 1;
	}
	{
		struct stat st;
	}

	if (realpath(watch_dir, watch_dir_abs) == NULL) {
		fprintf(stderr, "realpath %s: %s\n", watch_dir, strerror(errno));
		return 1;
	}

	inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	//watch descriptor tells system which directory and event types to monitor
	watch_descriptor = inotify_add_watch(inotify_fd, watch_dir_abs,
	                                     IN_ACCESS | IN_MODIFY | IN_OPEN |
	                                     IN_CLOSE_WRITE | IN_CLOSE_NOWRITE);
	if (watch_descriptor < 0) {
		fprintf(stderr, "inotify_add_watch: %s\n", strerror(errno));
		close(inotify_fd);
		return 1;
	}

	poll_fd.fd = inotify_fd;
	poll_fd.events = POLLIN;
	previous_io = (struct io_counts) {
		0
	};
	(void)read_proc_io(target_pid, &previous_io);

	printf("watching %s for pid %d (Ctrl+C to quit)\n", watch_dir_abs, target_pid);
	fflush(stdout);

	// Event-driven poll: wait indefinitely for filesystem activity
	while (true) {
		events = (struct events_buf) {
			0
		};
		poll_result = poll(&poll_fd, 1, -1);
		if (poll_result < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("poll");
			break;
		}
		if ((poll_fd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
			fprintf(stderr, "poll: fd problem\n");
			break;
		}
		if ((poll_fd.revents & POLLIN) != 0) {
			readall_inotify(inotify_fd, watch_dir_abs, target_pid, &events);
		}
		if (read_proc_io(target_pid, &current_io) != 0) {
			current_io.read_successful = 0;
		}
		print_tick(target_pid, &events, &current_io);
		previous_io = current_io;
	}

	inotify_rm_watch(inotify_fd, watch_descriptor);
	close(inotify_fd);
	printf("done.\n");
	return 0;
}
