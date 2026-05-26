/*
 * usb_tracker.h — Shared header for USB File Transfer Activity Driver
 *
 * This header defines the data structures and ioctl commands shared between
 * the kernel-space driver (usb_audit.c) and the user-space application
 * (usb_monitor.c). Both sides include this file to ensure consistent
 * communication over the /dev/usb_audit character device.
 *
 * Project:  Group 10 — USB File Transfer Activity Driver (Project 15)
 * Course:   CSC1107 — Operating Systems
 * Target:   Raspberry Pi 4, Raspbian 64-bit (Linux kernel 6.x)
 */

#ifndef USB_TRACKER_H
#define USB_TRACKER_H

#include <linux/ioctl.h>   /* _IO, _IOR, _IOW, _IOWR macros */
#include <linux/types.h>   /* __u8, __u32, __u64 fixed-width types */

/* -------------------------------------------------------------------------
 * Magic Number & ioctl Commands
 * -------------------------------------------------------------------------
 * 'U' (0x55) is the magic number for this driver.  All ioctl commands are
 * encoded with this prefix so the kernel can demultiplex them correctly.
 */
#define USB_AUDIT_MAGIC  'U'

/* Retrieve current transfer statistics (fills usb_audit_stats_t). */
#define USB_AUDIT_GET_STATS      _IOR(USB_AUDIT_MAGIC, 1, usb_audit_stats_t)

/* Clear the in-kernel event log buffer. */
#define USB_AUDIT_CLEAR_LOGS     _IO(USB_AUDIT_MAGIC, 2)

/* Set the USB mount-point path the driver should monitor. */
#define USB_AUDIT_SET_PATH       _IOW(USB_AUDIT_MAGIC, 3, char[256])

/* Retrieve the N most recent log entries (fills caller-supplied buffer). */
#define USB_AUDIT_GET_LOGS       _IOWR(USB_AUDIT_MAGIC, 4, usb_audit_logs_t)

/* Reset all statistics counters to zero (logs are preserved). */
#define USB_AUDIT_RESET_STATS    _IO(USB_AUDIT_MAGIC, 5)

/* Configure anomaly detection thresholds. */
#define USB_AUDIT_SET_ANOMALY    _IOW(USB_AUDIT_MAGIC, 6, usb_audit_anomaly_t)

/* Retrieve current anomaly detection status (recent burst count). */
#define USB_AUDIT_GET_ANOMALY    _IOR(USB_AUDIT_MAGIC, 7, usb_audit_anomaly_t)

/* Maximum number of commands supported. */
#define USB_AUDIT_MAX_NR         7

/* -------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */
#define USB_AUDIT_DEVICE_NAME    "usb_audit"   /* /dev node name          */
#define USB_AUDIT_LOG_MAX        128           /* max stored log entries  */
#define USB_AUDIT_PATH_LEN       256           /* max mount-path length   */

/* Default anomaly detection thresholds (can be changed at runtime). */
#define USB_AUDIT_DEFAULT_THRESHOLD  5        /* max file ops in window  */
#define USB_AUDIT_DEFAULT_WINDOW_MS  3000     /* sliding window (ms)     */
#define USB_AUDIT_ANOMALY_COOLDOWN_MS 5000   /* min gap between alerts  */
#define USB_AUDIT_ANOMALY_RING_SIZE  64       /* recent event timestamps */

/* -------------------------------------------------------------------------
 * Log Event Types
 * ------------------------------------------------------------------------- */
enum usb_audit_event_type {
    USB_AUDIT_EVENT_NONE      = 0,  /* unused / padding             */
    USB_AUDIT_EVENT_DEVICE_IN = 1,  /* USB storage device inserted  */
    USB_AUDIT_EVENT_DEVICE_OUT= 2,  /* USB storage device removed   */
    USB_AUDIT_EVENT_FILE_CREATE=3,  /* new file written to device   */
    USB_AUDIT_EVENT_FILE_MODIFY=4,  /* existing file modified       */
    USB_AUDIT_EVENT_FILE_DELETE=5,  /* file removed from device     */
    USB_AUDIT_EVENT_ALERT     = 6,  /* mass-copy / anomaly alert    */
};

/* -------------------------------------------------------------------------
 * Single Log Entry
 * -------------------------------------------------------------------------
 * Each file operation or device event is recorded as one entry in a
 * circular buffer inside the kernel module.  The user-space application
 * reads batches of these entries via USB_AUDIT_GET_LOGS.
 */
typedef struct {
    __u8  event_type;                 /* enum usb_audit_event_type   */
    __u8  reserved[3];                /* explicit padding            */
    __u32 pid;                        /* PID of triggering process   */
    __u64 timestamp_ns;               /* monotonic timestamp (ns)    */
    __u64 file_size;                  /* bytes transferred (if any)  */
    char  file_name[256];             /* affected file / device name */
} usb_audit_log_entry_t;

/* -------------------------------------------------------------------------
 * Aggregate Statistics
 * -------------------------------------------------------------------------
 * Cumulative counters that the kernel module updates on every tracked
 * event.  Retrieved by the user app with USB_AUDIT_GET_STATS.
 */
typedef struct {
    __u64 total_bytes_written;        /* sum of all write sizes      */
    __u64 total_files_created;        /* count of file-create events */
    __u64 total_files_modified;       /* count of file-modify events */
    __u64 total_files_deleted;        /* count of file-delete events */
    __u64 device_insertions;          /* USB plug-in count           */
    __u64 device_removals;            /* USB unplug count            */
    __u64 alert_count;                /* anomaly alerts raised       */
    __u32 log_count;                  /* entries currently stored    */
    __u32 reserved;                   /* align to 8 bytes            */
} usb_audit_stats_t;

/* -------------------------------------------------------------------------
 * Batch Log Retrieval Structure
 * -------------------------------------------------------------------------
 * Passed by the user app to USB_AUDIT_GET_LOGS.  The caller sets
 * `count` to the desired number of entries; the kernel fills `entries[]`
 * and updates `count` with the actual number returned.
 */
typedef struct {
    __u32 count;                                         /* in/out     */
    __u32 reserved;
    usb_audit_log_entry_t entries[USB_AUDIT_LOG_MAX];   /* out        */
} usb_audit_logs_t;

/* -------------------------------------------------------------------------
 * Anomaly Detection Configuration / Status
 * -------------------------------------------------------------------------
 * Used to configure and query the kernel-side mass-copy detection engine.
 * - threshold : max file ops allowed within the time window before alert.
 * - window_ms : sliding window size in milliseconds.
 * - burst_count : (output) current count of recent file ops in window.
 * - alert_triggered : (output) 1 if an alert fired in the last check.
 */
typedef struct {
    __u32 threshold;          /* in: max ops before alert                */
    __u32 window_ms;          /* in: sliding window in milliseconds      */
    __u32 burst_count;        /* out: recent file ops within window      */
    __u32 alert_triggered;    /* out: 1 if alert condition is met        */
} usb_audit_anomaly_t;

#endif /* USB_TRACKER_H */
