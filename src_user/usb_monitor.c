/*
 * usb_monitor.c — User-Space Application: USB Transfer Monitor
 *
 * This C program communicates with the usb_audit kernel module through
 * the /dev/usb_audit character device.  It provides:
 *   - An interactive terminal-based dashboard.
 *   - Real-time display of file transfer logs and aggregate statistics.
 *   - The ability to inject file events into the kernel audit trail
 *     (for testing / demonstration purposes).
 *   - Mass-copy anomaly detection based on event frequency.
 *
 * Build:   gcc -Wall -Wextra -o usb_monitor usb_monitor.c
 * Run:     sudo ./usb_monitor
 *
 * Project:  Group 10 — USB File Transfer Activity Driver (Project 15)
 * Course:   CSC1107 — Operating Systems
 * Target:   Raspberry Pi 4, Raspbian 64-bit
 */

#define _GNU_SOURCE            /* for asprintf() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

#include "../include/usb_tracker.h"

/* -------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */
#define DEVICE_PATH         "/dev/usb_audit"
#define MENU_REFRESH_SEC    2        /* seconds between dashboard refreshes */
#define MAX_LINE_LEN        512

/* Mass-copy anomaly detection thresholds (mirrors kernel logic). */
#define ANOMALY_THRESHOLD   5        /* max file ops allowed in window      */
#define ANOMALY_WINDOW_SEC  3.0      /* sliding time window (seconds)       */

/* -------------------------------------------------------------------------
 * Global State
 * ------------------------------------------------------------------------- */
static volatile sig_atomic_t keep_running = 1;  /* set to 0 on SIGINT / SIGTERM */

/* -------------------------------------------------------------------------
 * Signal Handler — graceful shutdown
 * ------------------------------------------------------------------------- */
static void signal_handler(int signum)
{
    (void)signum;
    keep_running = 0;
}

/* -------------------------------------------------------------------------
 * Helper: Convert a nanosecond timestamp to a human-readable string
 * ------------------------------------------------------------------------- */
static const char *format_time(__u64 ns)
{
    static char buf[64];
    time_t sec  = (time_t)(ns / 1000000000ULL);
    struct tm tm_info;

    localtime_r(&sec, &tm_info);
    strftime(buf, sizeof(buf), "%H:%M:%S", &tm_info);
    return buf;
}

/* -------------------------------------------------------------------------
 * Helper: Map event type enum to a readable label
 * ------------------------------------------------------------------------- */
static const char *event_label(__u8 type)
{
    switch (type) {
    case USB_AUDIT_EVENT_DEVICE_IN:    return "DEVICE_IN ";
    case USB_AUDIT_EVENT_DEVICE_OUT:   return "DEVICE_OUT";
    case USB_AUDIT_EVENT_FILE_CREATE:  return "FILE_CREATE";
    case USB_AUDIT_EVENT_FILE_MODIFY:  return "FILE_MODIFY";
    case USB_AUDIT_EVENT_FILE_DELETE:  return "FILE_DELETE";
    case USB_AUDIT_EVENT_ALERT:        return "*** ALERT ***";
    default:                           return "UNKNOWN    ";
    }
}

/* -------------------------------------------------------------------------
 * Helper: Write an event string to the kernel driver
 *
 * The kernel driver's write handler parses the first character as the
 * event code (C=create, M=modify, D=delete, A=alert) and the remainder
 * (after whitespace) as the file path.
 * ------------------------------------------------------------------------- */
static int send_event(int fd, char code, const char *path, __u64 size)
{
    char line[MAX_LINE_LEN];
    int  n;

    n = snprintf(line, sizeof(line), "%c %s (%llu bytes)\n", code, path,
                 (unsigned long long)size);
    if (n < 0 || (size_t)n >= sizeof(line))
        return -1;

    if (write(fd, line, (size_t)n) < 0) {
        perror("write to device");
        return -1;
    }

    printf("  → Sent event: %s", line);
    return 0;
}

/* -------------------------------------------------------------------------
 * Subroutine: Print the interactive dashboard header
 * ------------------------------------------------------------------------- */
static void print_header(void)
{
    printf("\033[2J\033[H");   /* clear screen, move cursor home            */
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║   USB File Transfer Activity Monitor — Group 10         ║\n");
    printf("║   Driver: /dev/usb_audit   |   CSC1107 Project 15       ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
}

/* -------------------------------------------------------------------------
 * Subroutine: Check and display kernel-side anomaly status
 * -------------------------------------------------------------------------
 * Queries the kernel module for the current burst count and whether an
 * automatic alert has been triggered.  Prints a prominent warning if so.
 */
static void check_anomaly_status(int fd)
{
    usb_audit_anomaly_t anom;

    memset(&anom, 0, sizeof(anom));

    if (ioctl(fd, USB_AUDIT_GET_ANOMALY, &anom) < 0) {
        /* GET_ANOMALY may not be supported by older module versions. */
        return;
    }

    if (anom.alert_triggered) {
        printf("\n");
        printf("  ╔══════════════════════════════════════════════════════╗\n");
        printf("  ║  *** SECURITY ALERT ***                              ║\n");
        printf("  ║  Mass-copy behaviour detected by kernel driver!      ║\n");
        printf("  ║  Burst: %u file ops in %u ms (threshold: %u)         ║\n",
               anom.burst_count, anom.window_ms, anom.threshold);
        printf("  ╚══════════════════════════════════════════════════════╝\n");
        printf("\n");
    }
}

/* -------------------------------------------------------------------------
 * Subroutine: Set anomaly detection thresholds via ioctl
 * ------------------------------------------------------------------------- */
static void set_anomaly_thresholds(int fd, __u32 threshold, __u32 window_ms)
{
    usb_audit_anomaly_t anom;

    memset(&anom, 0, sizeof(anom));
    anom.threshold = threshold;
    anom.window_ms = window_ms;

    if (ioctl(fd, USB_AUDIT_SET_ANOMALY, &anom) < 0) {
        perror("ioctl(SET_ANOMALY)");
        return;
    }

    printf("  Anomaly config updated: threshold=%u ops, window=%u ms\n",
           threshold, window_ms);
}

/* -------------------------------------------------------------------------
 * Subroutine: Fetch and print aggregate statistics
 * ------------------------------------------------------------------------- */
static void print_stats(int fd)
{
    usb_audit_stats_t st;

    if (ioctl(fd, USB_AUDIT_GET_STATS, &st) < 0) {
        printf("  [stats] ioctl(GET_STATS) failed: %s\n", strerror(errno));
        return;
    }

    printf("\n┌── Transfer Statistics ─────────────────────────────────┐\n");
    printf("│ Total bytes written : %-12llu                      │\n",
           (unsigned long long)st.total_bytes_written);
    printf("│ Files created       : %-12llu                      │\n",
           (unsigned long long)st.total_files_created);
    printf("│ Files modified      : %-12llu                      │\n",
           (unsigned long long)st.total_files_modified);
    printf("│ Files deleted       : %-12llu                      │\n",
           (unsigned long long)st.total_files_deleted);
    printf("│ Device insertions   : %-12llu                      │\n",
           (unsigned long long)st.device_insertions);
    printf("│ Device removals     : %-12llu                      │\n",
           (unsigned long long)st.device_removals);
    printf("│ Alerts raised       : %-12llu                      │\n",
           (unsigned long long)st.alert_count);
    printf("│ Log entries stored  : %-12u                        │\n",
           st.log_count);
    printf("└───────────────────────────────────────────────────────┘\n");
}

/* -------------------------------------------------------------------------
 * Subroutine: Fetch and print recent log entries
 * ------------------------------------------------------------------------- */
static void print_logs(int fd, int max_display)
{
    usb_audit_logs_t logs;
    int i;

    memset(&logs, 0, sizeof(logs));
    logs.count = (__u32)max_display;

    if (ioctl(fd, USB_AUDIT_GET_LOGS, &logs) < 0) {
        printf("  [logs] ioctl(GET_LOGS) failed: %s\n", strerror(errno));
        return;
    }

    if (logs.count == 0) {
        printf("\n  No log entries recorded yet.\n");
        return;
    }

    printf("\n┌── Recent Transfer Log (last %u entries) "
           "────────────────────┐\n", logs.count);
    printf("│ %-12s %-8s %-12s %s\n",
           "TIME", "TYPE", "PID", "FILE / DEVICE");
    printf("│ %-12s %-8s %-12s %s\n",
           "────", "────", "───", "─────────────");

    for (i = 0; i < (int)logs.count; i++) {
        usb_audit_log_entry_t *e = &logs.entries[i];
        printf("│ %-12s %-8s %-12u %.60s\n",
               format_time(e->timestamp_ns),
               event_label(e->event_type),
               e->pid,
               e->file_name[0] ? e->file_name : "(none)");
    }
    printf("└───────────────────────────────────────────────────────┘\n");
}

/* -------------------------------------------------------------------------
 * Subroutine: Interactive menu loop (test / demo interface)
 * ------------------------------------------------------------------------- */
static void interactive_menu(int fd)
{
    char line[MAX_LINE_LEN];
    char code;

    printf("\n┌── Interactive Test Menu ───────────────────────────────┐\n");
    printf("│  C <path>  — Report file CREATE event                  │\n");
    printf("│  M <path>  — Report file MODIFY event                  │\n");
    printf("│  D <path>  — Report file DELETE event                  │\n");
    printf("│  A         — Manually trigger ALERT                    │\n");
    printf("│  T <n> <ms>— Set anomaly threshold & window            │\n");
    printf("│  S         — Show current stats + anomaly status       │\n");
    printf("│  L         — Show recent logs                          │\n");
    printf("│  R         — Reset statistics                          │\n");
    printf("│  X         — Clear all logs                            │\n");
    printf("│  Q         — Quit application                          │\n");
    printf("└───────────────────────────────────────────────────────┘\n");
    printf("\nCommand → ");

    while (keep_running && fgets(line, sizeof(line), stdin)) {
        /* Skip empty lines. */
        if (line[0] == '\n' || line[0] == '\r') {
            printf("Command → ");
            continue;
        }

        code = line[0];

        switch (code) {
        case 'Q': case 'q':
            keep_running = 0;
            printf("Shutting down...\n");
            break;

        case 'S': case 's':
            print_header();
            print_stats(fd);
            check_anomaly_status(fd);
            print_logs(fd, 10);
            break;

        case 'L': case 'l':
            print_header();
            check_anomaly_status(fd);
            print_logs(fd, 10);
            break;

        case 'R': case 'r':
            if (ioctl(fd, USB_AUDIT_RESET_STATS) < 0)
                perror("ioctl(RESET_STATS)");
            else {
                printf("  Statistics and anomaly ring reset.\n");
                /* Also reset anomaly ring on kernel side — RESET_STATS
                 * now clears the anomaly ring as well.                    */
            }
            break;

        case 'X': case 'x':
            if (ioctl(fd, USB_AUDIT_CLEAR_LOGS) < 0)
                perror("ioctl(CLEAR_LOGS)");
            else
                printf("  Log buffer cleared.\n");
            break;

        case 'C': case 'c':
        case 'M': case 'm':
        case 'D': case 'd': {
            /* Extract the path (skip code + whitespace, strip newline). */
            char *p = line + 1;
            while (*p == ' ' || *p == '\t') p++;
            {
                size_t len = strlen(p);
                while (len > 0 && (p[len - 1] == '\n' ||
                                   p[len - 1] == '\r'))
                    p[--len] = '\0';
            }
            if (*p == '\0') {
                printf("  Usage: %c <file_path>\n", code);
                break;
            }
            send_event(fd, (char)(code == 'C' ? 'C' : code == 'M' ? 'M' : 'D'),
                       p, 1024);
            /* Auto-check: did this event trigger a kernel-side alert? */
            check_anomaly_status(fd);
            break;
        }

        case 'A': case 'a':
            send_event(fd, 'A', "mass_copy_alert", 0);
            printf("  *** SECURITY ALERT TRIGGERED ***\n");
            check_anomaly_status(fd);
            break;

        case 'T': case 't': {
            /* Parse: T <threshold> <window_ms> */
            int thr = 0, win = 0;
            if (sscanf(line + 1, "%d %d", &thr, &win) >= 2) {
                if (thr < 1) {
                    printf("  Error: threshold must be at least 1.\n");
                    break;
                }
                if (win < 100) {
                    printf("  Error: window must be at least 100 ms.\n");
                    break;
                }
                set_anomaly_thresholds(fd, (__u32)thr, (__u32)win);
            } else if (sscanf(line + 1, "%d", &thr) >= 1) {
                if (thr < 1) {
                    printf("  Error: threshold must be at least 1.\n");
                    break;
                }
                /* Only threshold given — keep current window. */
                usb_audit_anomaly_t anom;
                memset(&anom, 0, sizeof(anom));
                if (ioctl(fd, USB_AUDIT_GET_ANOMALY, &anom) == 0)
                    win = (int)anom.window_ms;
                if (win == 0) win = ANOMALY_WINDOW_SEC * 1000;
                set_anomaly_thresholds(fd, (__u32)thr, (__u32)win);
            } else {
                printf("  Usage: T <threshold> [window_ms]\n");
                printf("  Current defaults: threshold=%d, window=%d ms\n",
                       ANOMALY_THRESHOLD, (int)(ANOMALY_WINDOW_SEC * 1000));
                /* Show current kernel-side config too. */
                check_anomaly_status(fd);
            }
            break;
        }

        default:
            printf("  Unknown command '%c'.  Type Q to quit.\n", code);
            break;
        }

        if (keep_running)
            printf("\nCommand → ");
    }
}

/* -------------------------------------------------------------------------
 * Subroutine: Daemon mode — periodic dashboard refresh
 * ------------------------------------------------------------------------- */
static void daemon_mode(int fd)
{
    while (keep_running) {
        print_header();
        print_stats(fd);
        check_anomaly_status(fd);
        print_logs(fd, 8);
        printf("\n  Refreshing every %d s.  Press Ctrl+C to quit.\n",
               MENU_REFRESH_SEC);
        sleep(MENU_REFRESH_SEC);
    }
}

/* -------------------------------------------------------------------------
 * Print usage information
 * ------------------------------------------------------------------------- */
static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTION]\n"
        "USB File Transfer Activity Monitor — Group 10\n"
        "\n"
        "Options:\n"
        "  -i, --interactive      Interactive test menu (default)\n"
        "  -d, --daemon           Periodic dashboard refresh mode\n"
        "  -p, --path <path>      Set monitored USB mount path\n"
        "  -t, --threshold <n>    Anomaly: max file ops before alert\n"
        "  -w, --window <ms>      Anomaly: sliding time window (ms)\n"
        "  -h, --help             Show this help message\n"
        "\n"
        "In interactive mode, commands are:\n"
        "  C <path>     Report file CREATE event\n"
        "  M <path>     Report file MODIFY event\n"
        "  D <path>     Report file DELETE event\n"
        "  A            Manually trigger anomaly ALERT\n"
        "  T <n> <ms>   Set anomaly threshold & window (ms)\n"
        "  S            Show current stats + anomaly status\n"
        "  L            Show recent logs\n"
        "  R            Reset statistics + anomaly ring\n"
        "  X            Clear all logs\n"
        "  Q            Quit\n"
        "\n"
        "Kernel auto-detection fires ALERT when file ops exceed threshold\n"
        "within the sliding time window (default: %d ops / %.0f s).\n",
        prog, ANOMALY_THRESHOLD, ANOMALY_WINDOW_SEC);
}

/* =========================================================================
 * main()
 * ========================================================================= */
int main(int argc, char *argv[])
{
    int  fd;
    int  mode_interactive = 1;   /* 1 = interactive, 0 = daemon            */
    char mount_path[USB_AUDIT_PATH_LEN] = "/media";
    int  anomaly_thr = ANOMALY_THRESHOLD;
    int  anomaly_win = (int)(ANOMALY_WINDOW_SEC * 1000);
    int  i;

    /* -- Parse command-line arguments ---------------------------------- */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-d") == 0 ||
                   strcmp(argv[i], "--daemon") == 0) {
            mode_interactive = 0;
        } else if (strcmp(argv[i], "-i") == 0 ||
                   strcmp(argv[i], "--interactive") == 0) {
            mode_interactive = 1;
        } else if ((strcmp(argv[i], "-p") == 0 ||
                    strcmp(argv[i], "--path") == 0) && i + 1 < argc) {
            strncpy(mount_path, argv[++i], USB_AUDIT_PATH_LEN - 1);
            mount_path[USB_AUDIT_PATH_LEN - 1] = '\\0';
        } else if ((strcmp(argv[i], "-t") == 0 ||
                    strcmp(argv[i], "--threshold") == 0) && i + 1 < argc) {
            anomaly_thr = atoi(argv[++i]);
            if (anomaly_thr < 1) anomaly_thr = 1;
        } else if ((strcmp(argv[i], "-w") == 0 ||
                    strcmp(argv[i], "--window") == 0) && i + 1 < argc) {
            anomaly_win = atoi(argv[++i]);
            if (anomaly_win < 100) anomaly_win = 100;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* -- Install signal handlers for clean shutdown -------------------- */
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    /* -- Open the character device ------------------------------------- */
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("open(" DEVICE_PATH ")");
        fprintf(stderr, "Is the usb_audit kernel module loaded?\n");
        fprintf(stderr, "Try: sudo insmod src_kernel/usb_audit.ko\n");
        return 1;
    }

    printf("[usb_monitor] Connected to %s\n", DEVICE_PATH);

    /* -- Set the monitor path via ioctl -------------------------------- */
    if (ioctl(fd, USB_AUDIT_SET_PATH, mount_path) < 0)
        perror("ioctl(SET_PATH)");
    else
        printf("[usb_monitor] Monitor path set to: %s\n", mount_path);

    /* -- Apply anomaly detection config to kernel module --------------- */
    {
        usb_audit_anomaly_t anom;
        memset(&anom, 0, sizeof(anom));
        anom.threshold = (__u32)anomaly_thr;
        anom.window_ms = (__u32)anomaly_win;
        if (ioctl(fd, USB_AUDIT_SET_ANOMALY, &anom) < 0)
            perror("ioctl(SET_ANOMALY) — kernel may not support anomaly");
        else
            printf("[usb_monitor] Anomaly: threshold=%d ops, window=%d ms\n",
                   anomaly_thr, anomaly_win);
    }

    /* -- Enter the appropriate run mode -------------------------------- */
    if (mode_interactive)
        interactive_menu(fd);
    else
        daemon_mode(fd);

    /* -- Cleanup ------------------------------------------------------- */
    close(fd);
    printf("[usb_monitor] Disconnected.  Goodbye.\n");

    return 0;
}
