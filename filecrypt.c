/*
 * filecrypt.c – Encrypt/decrypt files using AES-256-CTR with secure memory and parallelism.
 * 
 * Before compliation do these commands in 
 * WSL(important) that it's WSL:
 * 
 * sudo apt update
 * sudo apt install libssl-dev
 * 
 * Compile: gcc -o filecrypt filecrypt.c -lssl -lcrypto -lpthread
 *
 * Usage: filecrypt -e|-d -k <key> [-i <infile>] [-o <outfile>] [-t <threads>] [-h]
 *
 * Advanced features demonstrated:
 *   - mmap() for file I/O
 *   - pthreads for parallel encryption/decryption
 *   - poll() for non‑blocking cancellation check
 *   - ioctl() for terminal size (progress bar)
 *   - mlock()/munlock() for secure key storage
 *   - Signal handling (SIGINT/SIGTERM) for clean shutdown
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <termios.h>
#include <getopt.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define AES_BLOCK_SIZE      16
#define AES_KEY_SIZE        32      // 256 bits
#define AES_IV_SIZE         16
#define DEFAULT_CHUNK_SIZE  (1UL << 20)  // 1 MiB per thread chunk
#define PROGRESS_BAR_WIDTH  50

/* Global state for signal handling and cancellation */
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_cancel = 0;
static int g_input_fd = -1;
static int g_output_fd = -1;
static void *g_input_map = MAP_FAILED;
static void *g_output_map = MAP_FAILED;
static size_t g_map_size = 0;
static void *g_secure_key = MAP_FAILED;
static size_t g_secure_key_len = 0;

/* Secure memory helpers */
static void *secure_alloc(size_t len) {
    void *ptr = mmap(NULL, len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap MAP_LOCKED");
        /* Fallback to plain mmap and try mlock */
        ptr = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED)
            return NULL;
        if (mlock(ptr, len) != 0) {
            perror("mlock (secure_alloc)");
            /* Continue anyway, but memory may be swapped */
        }
    }
    return ptr;
}

static void secure_free(void *ptr, size_t len) {
    if (ptr == MAP_FAILED || ptr == NULL)
        return;
    /* Zero memory before releasing */
    explicit_bzero(ptr, len);
    munlock(ptr, len);
    munmap(ptr, len);
}

/* Signal handler */
static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_running = 0;
        g_cancel = 1;
    }
}

/* Cleanup function */
static void cleanup(void) {
    if (g_output_map != MAP_FAILED) {
        msync(g_output_map, g_map_size, MS_SYNC);
        munmap(g_output_map, g_map_size);
        g_output_map = MAP_FAILED;
    }
    if (g_input_map != MAP_FAILED) {
        munmap(g_input_map, g_map_size);
        g_input_map = MAP_FAILED;
    }
    if (g_input_fd != -1) {
        close(g_input_fd);
        g_input_fd = -1;
    }
    if (g_output_fd != -1) {
        close(g_output_fd);
        g_output_fd = -1;
    }
    if (g_secure_key != MAP_FAILED) {
        secure_free(g_secure_key, g_secure_key_len);
        g_secure_key = MAP_FAILED;
    }
}

/* Thread arguments */
typedef struct {
    unsigned char *in;
    unsigned char *out;
    size_t start;
    size_t len;
    const unsigned char *key;
    const unsigned char *iv;
    int encrypt;
} worker_arg_t;

/* Worker thread for AES-CTR processing */
static void *worker(void *arg) {
    worker_arg_t *w = (worker_arg_t *)arg;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return NULL;
    }

    /* Initialize cipher */
    if (EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), NULL, w->key, w->iv, w->encrypt) != 1) {
        fprintf(stderr, "EVP_CipherInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int outlen;
    unsigned char *in_ptr = w->in + w->start;
    unsigned char *out_ptr = w->out + w->start;
    size_t remaining = w->len;

    /* Process in AES_BLOCK_SIZE chunks */
    while (remaining > 0 && g_running) {
        size_t chunk = (remaining > AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : remaining;
        if (EVP_CipherUpdate(ctx, out_ptr, &outlen, in_ptr, chunk) != 1) {
            fprintf(stderr, "EVP_CipherUpdate failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return NULL;
        }
        in_ptr += chunk;
        out_ptr += chunk;
        remaining -= chunk;
    }

    /* Finalize (CTR mode has no padding) */
    if (g_running) {
        if (EVP_CipherFinal_ex(ctx, out_ptr, &outlen) != 1) {
            fprintf(stderr, "EVP_CipherFinal_ex failed\n");
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

/* Progress bar using ioctl() for terminal width */
static void *progress_thread(void *arg) {
    size_t total = *(size_t *)arg;
    size_t *processed = ((size_t *)arg) + 1;  // pointer to shared counter
    struct winsize ws;
    int width = PROGRESS_BAR_WIDTH;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != -1 && ws.ws_col > 20)
        width = ws.ws_col - 20;

    while (g_running && *processed < total) {
        int percent = (int)((*processed * 100) / total);
        int pos = (width * percent) / 100;

        printf("\r[");
        for (int i = 0; i < width; i++)
            putchar(i < pos ? '=' : (i == pos ? '>' : ' '));
        printf("] %3d%%", percent);
        fflush(stdout);

        /* Use poll() to sleep for 100 ms without blocking signals */
        poll(NULL, 0, 100);
    }
    if (g_running)
        printf("\r[%*s] 100%%\n", width, "");
    return NULL;
}

/* Check for user cancellation with poll() */
static void check_cancellation(void) {
    struct pollfd pfd;
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 0) > 0) {
        char c;
        if (read(STDIN_FILENO, &c, 1) == 1 && (c == 'q' || c == 'Q')) {
            g_cancel = 1;
            g_running = 0;
        }
    }
}

/* Derive key from passphrase using SHA256 (optional) */
static int derive_key(const char *passphrase, unsigned char *key_out) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, passphrase, strlen(passphrase));
    SHA256_Final(key_out, &sha256);
    return 0;
}

/* Print usage */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -e|-d -k <key> [-i <infile>] [-o <outfile>] [-t <threads>] [-p] [-h]\n"
        "  -e           Encrypt mode\n"
        "  -d           Decrypt mode\n"
        "  -k <key>     Key as hex string (64 chars for AES-256) or passphrase with -p\n"
        "  -p           Treat -k value as a passphrase (derive key via SHA256)\n"
        "  -i <infile>  Input file (default: stdin)\n"
        "  -o <outfile> Output file (default: stdout)\n"
        "  -t <threads> Number of threads (default: number of CPU cores)\n"
        "  -h           Show this help\n"
        "\n"
        "While running, press 'q' followed by Enter to cancel.\n",
        prog);
}

int main(int argc, char *argv[]) {
    int opt;
    int mode = 0;           // 1=encrypt, 2=decrypt
    char *key_arg = NULL;
    int passphrase_mode = 0;
    char *infile = NULL;
    char *outfile = NULL;
    int num_threads = 0;
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];
    struct stat st;
    off_t file_size;
    size_t data_size;
    pthread_t *threads = NULL;
    worker_arg_t *wargs = NULL;
    size_t processed = 0;
    pthread_t prog_tid;
    int ret = EXIT_FAILURE;

    /* Parse arguments */
    static struct option long_opts[] = {
        {"encrypt", no_argument, 0, 'e'},
        {"decrypt", no_argument, 0, 'd'},
        {"key", required_argument, 0, 'k'},
        {"passphrase", no_argument, 0, 'p'},
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"threads", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "edk:pi:o:t:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'e': mode = 1; break;
            case 'd': mode = 2; break;
            case 'k': key_arg = optarg; break;
            case 'p': passphrase_mode = 1; break;
            case 'i': infile = optarg; break;
            case 'o': outfile = optarg; break;
            case 't': num_threads = atoi(optarg); break;
            case 'h': usage(argv[0]); return EXIT_SUCCESS;
            default: usage(argv[0]); return EXIT_FAILURE;
        }
    }

    if (mode == 0) {
        fprintf(stderr, "Error: Must specify -e (encrypt) or -d (decrypt)\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (!key_arg) {
        fprintf(stderr, "Error: Key is required (-k)\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Prepare key */
    if (passphrase_mode) {
        derive_key(key_arg, key);
    } else {
        /* Hex string parsing */
        if (strlen(key_arg) != AES_KEY_SIZE * 2) {
            fprintf(stderr, "Error: Key must be %d hex characters\n", AES_KEY_SIZE * 2);
            return EXIT_FAILURE;
        }
        for (size_t i = 0; i < AES_KEY_SIZE; i++) {
            if (sscanf(key_arg + 2*i, "%2hhx", &key[i]) != 1) {
                fprintf(stderr, "Error: Invalid hex key\n");
                return EXIT_FAILURE;
            }
        }
    }

    /* Secure allocation for key material (will be copied to secure memory) */
    g_secure_key_len = AES_KEY_SIZE + AES_IV_SIZE;
    g_secure_key = secure_alloc(g_secure_key_len);
    if (g_secure_key == MAP_FAILED) {
        fprintf(stderr, "Error: Could not allocate secure memory\n");
        return EXIT_FAILURE;
    }
    unsigned char *sec_key = (unsigned char *)g_secure_key;
    unsigned char *sec_iv = sec_key + AES_KEY_SIZE;
    memcpy(sec_key, key, AES_KEY_SIZE);
    explicit_bzero(key, sizeof(key));   /* Clear stack copy */

    /* Open files */
    g_input_fd = infile ? open(infile, O_RDONLY) : STDIN_FILENO;
    if (g_input_fd == -1) {
        perror("open input");
        goto cleanup;
    }

    if (fstat(g_input_fd, &st) == -1) {
        perror("fstat input");
        goto cleanup;
    }
    file_size = st.st_size;

    if (mode == 1) { /* Encrypt */
        /* Generate random IV */
        if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
            fprintf(stderr, "Error: Failed to generate random IV\n");
            goto cleanup;
        }
        memcpy(sec_iv, iv, AES_IV_SIZE);
        data_size = file_size;
    } else { /* Decrypt */
        /* Read IV from beginning of file */
        if (file_size < AES_IV_SIZE) {
            fprintf(stderr, "Error: Input file too small to contain IV\n");
            goto cleanup;
        }
        if (read(g_input_fd, iv, AES_IV_SIZE) != AES_IV_SIZE) {
            perror("read IV");
            goto cleanup;
        }
        memcpy(sec_iv, iv, AES_IV_SIZE);
        data_size = file_size - AES_IV_SIZE;
        if (lseek(g_input_fd, AES_IV_SIZE, SEEK_SET) == -1) {
            perror("lseek");
            goto cleanup;
        }
    }

    /* Open output file */
    g_output_fd = outfile ? open(outfile, O_RDWR | O_CREAT | O_TRUNC, 0600) : STDOUT_FILENO;
    if (g_output_fd == -1) {
        perror("open output");
        goto cleanup;
    }

    /* Set output file size */
    if (mode == 1) {
        /* Encrypt: output = IV + ciphertext */
        if (ftruncate(g_output_fd, AES_IV_SIZE + data_size) == -1) {
            perror("ftruncate output");
            goto cleanup;
        }
        g_map_size = AES_IV_SIZE + data_size;
    } else {
        /* Decrypt: output = plaintext */
        if (ftruncate(g_output_fd, data_size) == -1) {
            perror("ftruncate output");
            goto cleanup;
        }
        g_map_size = data_size;
    }

    /* mmap files */
    g_input_map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, g_input_fd, 0);
    if (g_input_map == MAP_FAILED) {
        perror("mmap input");
        goto cleanup;
    }

    g_output_map = mmap(NULL, g_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_output_fd, 0);
    if (g_output_map == MAP_FAILED) {
        perror("mmap output");
        goto cleanup;
    }

    /* Setup signal handling */
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Thread count */
    if (num_threads <= 0)
        num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads < 1) num_threads = 1;

    /* Prepare for encryption/decryption */
    unsigned char *in_data;
    unsigned char *out_data;
    size_t work_size;

    if (mode == 1) {
        /* Encrypt: copy IV to output map */
        memcpy(g_output_map, sec_iv, AES_IV_SIZE);
        in_data = (unsigned char *)g_input_map;
        out_data = (unsigned char *)g_output_map + AES_IV_SIZE;
        work_size = data_size;
    } else {
        in_data = (unsigned char *)g_input_map + AES_IV_SIZE;
        out_data = (unsigned char *)g_output_map;
        work_size = data_size;
    }

    /* Create progress thread */
    size_t prog_args[2] = {work_size, 0};  // total, processed
    pthread_create(&prog_tid, NULL, progress_thread, prog_args);

    /* Divide work among threads */
    threads = calloc(num_threads, sizeof(pthread_t));
    wargs = calloc(num_threads, sizeof(worker_arg_t));
    if (!threads || !wargs) {
        perror("calloc");
        g_running = 0;
        goto cancel_progress;
    }

    size_t chunk_per_thread = work_size / num_threads;
    size_t remainder = work_size % num_threads;
    size_t offset = 0;

    for (int i = 0; i < num_threads; i++) {
        wargs[i].in = in_data;
        wargs[i].out = out_data;
        wargs[i].start = offset;
        wargs[i].len = chunk_per_thread + (i < (int)remainder ? 1 : 0);
        wargs[i].key = sec_key;
        wargs[i].iv = sec_iv;
        wargs[i].encrypt = (mode == 1);
        offset += wargs[i].len;
        pthread_create(&threads[i], NULL, worker, &wargs[i]);
    }

    /* Monitor for cancellation */
    while (g_running) {
        check_cancellation();
        /* Update progress */
        processed = 0;
        for (int i = 0; i < num_threads; i++) {
            /* Rough estimate; threads may not be exactly aligned */
            processed += wargs[i].len;
        }
        prog_args[1] = processed;
        if (processed >= work_size)
            break;
        usleep(50000);
    }

    /* Wait for threads */
    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);

    if (!g_cancel) {
        msync(g_output_map, g_map_size, MS_SYNC);
        ret = EXIT_SUCCESS;
    } else {
        fprintf(stderr, "\nCancelled by user.\n");
        /* Optionally remove incomplete output file */
        if (outfile) unlink(outfile);
    }

cancel_progress:
    g_running = 0;
    pthread_join(prog_tid, NULL);
    free(threads);
    free(wargs);

cleanup:
    cleanup();
    return ret;
}