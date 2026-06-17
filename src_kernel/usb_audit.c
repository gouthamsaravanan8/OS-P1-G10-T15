/*
 * usb_audit.c — Linux Kernel Module: USB File Transfer Activity Driver
 *
 * This module implements a character device driver that monitors file
 * transfer activity to removable USB storage devices.  It provides:
 *   - A /dev/usb_audit device node for user-space communication.
 *   - ioctl commands to retrieve logs, statistics, and configure monitoring.
 *   - A USB notifier callback to detect device hotplug events.
 *   - A circular ring buffer for storing transfer event logs.
 *   - Automatic mass-copy / burst anomaly detection with configurable
 *     threshold and sliding time window.
 *   - Comprehensive printk() logging for dmesg debugging.
 *
 * Build:   cd src_kernel && make
 * Load:    sudo insmod usb_audit.ko
 * Unload:  sudo rmmod usb_audit
 * Verify:  dmesg | tail -20
 *
 * Project:  Group 10 — USB File Transfer Activity Driver (Project 15)
 * Course:   CSC1107 — Operating Systems
 * Target:   Raspberry Pi 4, Raspbian 64-bit (Linux kernel 6.x)
 */

#include <linux/init.h>           /* __init, __exit macros              */
#include <linux/module.h>         /* MODULE_* macros, module boilerplate */
#include <linux/kernel.h>         /* printk(), KERN_* log levels        */
#include <linux/fs.h>             /* file_operations, alloc_chrdev_region*/
#include <linux/cdev.h>           /* cdev_init, cdev_add, cdev_del      */
#include <linux/device.h>         /* class_create, device_create        */
#include <linux/uaccess.h>        /* copy_to_user, copy_from_user       */
#include <linux/slab.h>           /* kmalloc, kfree                     */
#include <linux/mutex.h>          /* mutex_lock, mutex_unlock           */
#include <linux/usb.h>            /* usb_register_notify, usb_device    */
#include <linux/notifier.h>       /* NOTIFY_DONE, notifier_block        */
#include <linux/blkdev.h>         /* block_device operations            */
#include <linux/timekeeping.h>    /* ktime_get_real_ns                  */
#include <linux/string.h>         /* strncpy, strnlen                   */
#include <linux/ktime.h>          /* ktime_t, ktime_sub, ktime_after    */
#include <linux/version.h>        /* LINUX_VERSION_CODE check           */

#include "../include/usb_tracker.h"

/* =========================================================================
 * Module Metadata
 * ========================================================================= */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Group 10 — CSC1107");
MODULE_DESCRIPTION("USB File Transfer Activity Driver — monitors file "
                   "operations on removable USB storage devices.");
MODULE_VERSION("1.0");

/* =========================================================================
 * Global State
 * ========================================================================= */

static dev_t              usb_audit_devt;          /* major + minor number   */
static struct cdev        usb_audit_cdev;          /* char device struct     */
static struct class       *usb_audit_class = NULL; /* device class for sysfs */
static struct device      *usb_audit_device = NULL;/* /dev node backing dev  */

/* Circular log buffer --------------------------------------------------- */
static usb_audit_log_entry_t  *log_buffer = NULL;  /* ring buffer array      */
static int                     log_head   = 0;     /* write position         */
static int                     log_count  = 0;     /* entries currently held */

/* Aggregate statistics -------------------------------------------------- */
static usb_audit_stats_t stats;

/* Mount path to monitor (set by user app via ioctl) --------------------- */
static char monitored_path[USB_AUDIT_PATH_LEN] = "/media";

/* Synchronisation mutex — protects log_buffer, stats, log_head/count ---- */
static DEFINE_MUTEX(audit_mutex);

/* USB notifier block ---------------------------------------------------- */
static struct notifier_block usb_nb;

/* Anomaly (mass-copy) detection engine ---------------------------------- */
static ktime_t  anomaly_ring[USB_AUDIT_ANOMALY_RING_SIZE]; /* timestamp ring  */
static int      anomaly_ring_idx  = 0;    /* write position in ring           */
static int      anomaly_ring_count= 0;    /* valid entries in ring            */
static __u32    anomaly_threshold = USB_AUDIT_DEFAULT_THRESHOLD; /* max ops   */
static __u32    anomaly_window_ms = USB_AUDIT_DEFAULT_WINDOW_MS; /* window   */
static ktime_t  anomaly_last_alert;       /* timestamp of last alert raised  */

/* =========================================================================
 * Anomaly Detection: Check for mass-copy (burst) behaviour
 * =========================================================================
 * Records the timestamp of every file-create / file-modify event in a
 * ring buffer.  On each call, counts how many events fall within the
 * configured sliding window.  If the count exceeds the threshold and the
 * cooldown period has elapsed, automatically logs an ALERT event and
 * emits a printk() warning.
 *
 * Called from audit_log_event() while audit_mutex is held.
 */
static void anomaly_check_burst(ktime_t now)
{
    int i, burst = 0;
    ktime_t window_start;
    s64 cooldown_ns;

    /* Record the current event timestamp in the ring. */
    anomaly_ring[anomaly_ring_idx] = now;
    anomaly_ring_idx = (anomaly_ring_idx + 1) % USB_AUDIT_ANOMALY_RING_SIZE;
    if (anomaly_ring_count < USB_AUDIT_ANOMALY_RING_SIZE)
        anomaly_ring_count++;

    /* Window start = now minus configured window. */
    window_start = ktime_sub_ns(now, (s64)anomaly_window_ms * 1000000ULL);

    /* Count recent events within the sliding window. */
    for (i = 0; i < anomaly_ring_count; i++) {
        int idx = (anomaly_ring_idx - 1 - i + USB_AUDIT_ANOMALY_RING_SIZE)
                  % USB_AUDIT_ANOMALY_RING_SIZE;
        if (ktime_after(anomaly_ring[idx], window_start))
            burst++;
        else
            break;  /* ring is chronological — stop at first out-of-window */
    }

    /* Cooldown: don't spam alerts. */
    cooldown_ns = (s64)USB_AUDIT_ANOMALY_COOLDOWN_MS * 1000000LL;

    if (burst > (int)anomaly_threshold &&
        ktime_to_ns(ktime_sub(now, anomaly_last_alert)) > cooldown_ns) {

        anomaly_last_alert = now;

        printk(KERN_WARNING
               "[usb_audit] *** SECURITY ALERT *** Mass-copy detected!  "
               "%d file ops within %u ms (threshold=%u)\n",
               burst, anomaly_window_ms, anomaly_threshold);

        /* Record the alert in the log buffer directly (we already hold
         * audit_mutex, so skip the lock re-acquire).                      */
        {
            usb_audit_log_entry_t *entry = &log_buffer[log_head];
            entry->event_type    = USB_AUDIT_EVENT_ALERT;
            entry->pid           = 0;
            entry->timestamp_ns  = ktime_to_ns(now);
            entry->file_size     = 0;
            snprintf(entry->file_name, sizeof(entry->file_name),
                     "mass_copy: %d ops in %ums", burst, anomaly_window_ms);

            log_head = (log_head + 1) % USB_AUDIT_LOG_MAX;
            if (log_count < USB_AUDIT_LOG_MAX)
                log_count++;

            stats.alert_count++;
            stats.log_count = log_count;
        }
    }
}

/* =========================================================================
 * Helper: Record a log entry into the circular buffer
 * ========================================================================= */
static void audit_log_event(enum usb_audit_event_type type,
                            __u32 pid, __u64 size, const char *name)
{
    usb_audit_log_entry_t *entry;

    if (!log_buffer)
        return;

    mutex_lock(&audit_mutex);

    /* Wrap-around: overwrite oldest entry when buffer is full. */
    entry = &log_buffer[log_head];
    entry->event_type    = (__u8)type;
    entry->pid           = pid;
    entry->timestamp_ns  = ktime_get_ns();
    entry->file_size     = size;

    if (name) {
        strncpy(entry->file_name, name, sizeof(entry->file_name) - 1);
        entry->file_name[sizeof(entry->file_name) - 1] = '\0';
    } else {
        entry->file_name[0] = '\0';
    }

    log_head = (log_head + 1) % USB_AUDIT_LOG_MAX;
    if (log_count < USB_AUDIT_LOG_MAX)
        log_count++;

    /* Update cumulative statistics */
    switch (type) {
    case USB_AUDIT_EVENT_DEVICE_IN:
        stats.device_insertions++;
        break;
    case USB_AUDIT_EVENT_DEVICE_OUT:
        stats.device_removals++;
        break;
    case USB_AUDIT_EVENT_FILE_CREATE:
        stats.total_files_created++;
        stats.total_bytes_written += size;
        /* Feed into anomaly detection engine. */
        anomaly_check_burst(entry->timestamp_ns);
        break;
    case USB_AUDIT_EVENT_FILE_MODIFY:
        stats.total_files_modified++;
        stats.total_bytes_written += size;
        /* Feed into anomaly detection engine. */
        anomaly_check_burst(entry->timestamp_ns);
        break;
    case USB_AUDIT_EVENT_FILE_DELETE:
        stats.total_files_deleted++;
        break;
    case USB_AUDIT_EVENT_ALERT:
        stats.alert_count++;
        break;
    default:
        break;
    }

    stats.log_count = log_count;
    mutex_unlock(&audit_mutex);
}

/* =========================================================================
 * USB Notifier Callback
 * =========================================================================
 * Invoked by the USB core whenever a USB device is added or removed.
 * We filter for mass-storage class devices (class 0x08) and log the
 * corresponding hotplug event with a printk() message for dmesg.
 */
static int usb_audit_notify(struct notifier_block *self,
                            unsigned long action, void *dev)
{
    struct usb_device *udev = (struct usb_device *)dev;

    /* Only care about USB mass-storage devices (interface class 0x08). */
    if (udev->descriptor.bDeviceClass != USB_CLASS_MASS_STORAGE &&
        udev->descriptor.bDeviceClass != 0x00)  /* 0x00 = per-interface */
        return NOTIFY_DONE;

    switch (action) {
    case USB_DEVICE_ADD:
        printk(KERN_INFO "[usb_audit] USB storage device INSERTED: "
               "vendor=0x%04x product=0x%04x serial=%s\n",
               udev->descriptor.idVendor,
               udev->descriptor.idProduct,
               udev->serial ? udev->serial : "N/A");

        audit_log_event(USB_AUDIT_EVENT_DEVICE_IN, 0, 0,
                        udev->product ? udev->product : "USB_Storage");
        break;

    case USB_DEVICE_REMOVE:
        printk(KERN_INFO "[usb_audit] USB storage device REMOVED: "
               "vendor=0x%04x product=0x%04x\n",
               udev->descriptor.idVendor,
               udev->descriptor.idProduct);

        audit_log_event(USB_AUDIT_EVENT_DEVICE_OUT, 0, 0,
                        udev->product ? udev->product : "USB_Storage");
        break;

    default:
        break;
    }

    return NOTIFY_OK;
}

/* =========================================================================
 * Character Device — open()
 * =========================================================================
 * Called when a user-space process opens /dev/usb_audit.
 * We simply log the access and return success.
 */
static int usb_audit_open(struct inode *inode, struct file *filp)
{
    printk(KERN_DEBUG "[usb_audit] Device opened by PID %d (%s)\n",
           current->pid, current->comm);
    return 0;
}

/* =========================================================================
 * Character Device — release()
 * =========================================================================
 * Called when the last reference to the open file is closed.
 */
static int usb_audit_release(struct inode *inode, struct file *filp)
{
    printk(KERN_DEBUG "[usb_audit] Device closed by PID %d (%s)\n",
           current->pid, current->comm);
    return 0;
}

/* =========================================================================
 * Character Device — read()
 * =========================================================================
 * Allows user-space to read raw log entries as a byte stream.  Each read
 * returns at most one usb_audit_log_entry_t worth of data.  Returns 0
 * (EOF) when no new entries are available.
 */
static ssize_t usb_audit_read(struct file *filp, char __user *buf,
                              size_t count, loff_t *f_pos)
{
    ssize_t ret = 0;
    int     tail;

    if (count < sizeof(usb_audit_log_entry_t))
        return -EINVAL;

    mutex_lock(&audit_mutex);

    if (log_count == 0) {
        mutex_unlock(&audit_mutex);
        return 0;   /* no data → EOF */
    }

    /* The oldest entry is at (head - count) modulo LOG_MAX. */
    tail = (log_head - log_count + USB_AUDIT_LOG_MAX) % USB_AUDIT_LOG_MAX;

    if (copy_to_user(buf, &log_buffer[tail], sizeof(usb_audit_log_entry_t))) {
        mutex_unlock(&audit_mutex);
        return -EFAULT;
    }

    log_count--;
    stats.log_count = log_count;
    ret = sizeof(usb_audit_log_entry_t);
    *f_pos += ret;

    mutex_unlock(&audit_mutex);
    return ret;
}

/* =========================================================================
 * Character Device — write()
 * =========================================================================
 * User-space sends a file-name string to report a file transfer event.
 * The driver records it as USB_AUDIT_EVENT_FILE_CREATE / FILE_MODIFY
 * depending on context.  This is the primary mechanism for the user app
 * to feed file-level events into the kernel audit trail.
 *
 * Format:  "<event_code> <file_path>"  (event_code: C=create, M=modify,
 *                                        D=delete, A=alert)
 * Example: "C /media/pi/USB/report.pdf"
 */
static ssize_t usb_audit_write(struct file *filp, const char __user *buf,
                               size_t count, loff_t *f_pos)
{
    char kbuf[512];
    char event_code;
    char *file_path;
    enum usb_audit_event_type type;
    unsigned long long parsed_size = 0;
    char *paren;

    if (count == 0)
        return 0;
    if (count > sizeof(kbuf) - 1)
        count = sizeof(kbuf) - 1;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    /* Parse the event code (first character). */
    event_code = kbuf[0];
    switch (event_code) {
    case 'C': case 'c':
        type = USB_AUDIT_EVENT_FILE_CREATE;
        break;
    case 'M': case 'm':
        type = USB_AUDIT_EVENT_FILE_MODIFY;
        break;
    case 'D': case 'd':
        type = USB_AUDIT_EVENT_FILE_DELETE;
        break;
    case 'A': case 'a':
        type = USB_AUDIT_EVENT_ALERT;
        break;
    default:
        printk(KERN_WARNING "[usb_audit] Unknown event code '%c' from PID %d\n",
               event_code, current->pid);
        return -EINVAL;
    }

    /* Skip the event code and whitespace to reach the file path. */
    file_path = kbuf + 1;
    while (*file_path == ' ' || *file_path == '\t')
        file_path++;

    /* Trim trailing newline. */
    {
        size_t len = strnlen(file_path, sizeof(kbuf) - (file_path - kbuf));
        while (len > 0 && (file_path[len - 1] == '\n' ||
                           file_path[len - 1] == '\r'))
            file_path[--len] = '\0';
    }

    /* Parse optional size suffix: " (X bytes)" at the end of the string */
    paren = strrchr(file_path, '(');
    if (paren && paren > file_path) {
        if (sscanf(paren, "(%llu bytes)", &parsed_size) == 1) {
            char *space = paren - 1;
            if (space >= file_path && *space == ' ') {
                *space = '\0';
            } else {
                *paren = '\0';
            }
        }
    }

    printk(KERN_INFO "[usb_audit] Event from PID %d: type=%d path=%s size=%llu\n",
           current->pid, type, file_path, parsed_size);

    /* Record the event with the parsed file size. */
    audit_log_event(type, current->pid, (__u64)parsed_size, file_path);

    return count;
}

/* =========================================================================
 * Character Device — ioctl()
 * =========================================================================
 * The core command dispatcher.  Handles:
 *   USB_AUDIT_GET_STATS   — copy aggregate stats to user-space
 *   USB_AUDIT_CLEAR_LOGS  — reset the circular log buffer
 *   USB_AUDIT_SET_PATH    — set the monitored USB mount path
 *   USB_AUDIT_GET_LOGS    — batch-retrieve log entries
 *   USB_AUDIT_RESET_STATS — zero all counters (preserves logs)
 */
static long usb_audit_ioctl(struct file *filp, unsigned int cmd,
                            unsigned long arg)
{
    int ret = 0;

    /* Validate the magic number. */
    if (_IOC_TYPE(cmd) != USB_AUDIT_MAGIC)
        return -ENOTTY;
    if (_IOC_NR(cmd) > USB_AUDIT_MAX_NR)
        return -ENOTTY;

    switch (cmd) {

    case USB_AUDIT_GET_STATS: {
        usb_audit_stats_t __user *ustats = (usb_audit_stats_t __user *)arg;
        mutex_lock(&audit_mutex);
        if (copy_to_user(ustats, &stats, sizeof(stats)))
            ret = -EFAULT;
        mutex_unlock(&audit_mutex);
        break;
    }

    case USB_AUDIT_CLEAR_LOGS:
        mutex_lock(&audit_mutex);
        log_head  = 0;
        log_count = 0;
        stats.log_count = 0;
        memset(log_buffer, 0,
               USB_AUDIT_LOG_MAX * sizeof(usb_audit_log_entry_t));
        mutex_unlock(&audit_mutex);
        printk(KERN_INFO "[usb_audit] Log buffer cleared by PID %d\n",
               current->pid);
        break;

    case USB_AUDIT_SET_PATH: {
        char __user *upath = (char __user *)arg;
        mutex_lock(&audit_mutex);
        if (copy_from_user(monitored_path, upath, USB_AUDIT_PATH_LEN - 1))
            ret = -EFAULT;
        monitored_path[USB_AUDIT_PATH_LEN - 1] = '\0';
        mutex_unlock(&audit_mutex);
        printk(KERN_INFO "[usb_audit] Monitor path set to: %s (by PID %d)\n",
               monitored_path, current->pid);
        break;
    }

    case USB_AUDIT_GET_LOGS: {
        usb_audit_logs_t __user *ulogs = (usb_audit_logs_t __user *)arg;
        usb_audit_logs_t         klogs;
        __u32                    req_count;
        int                      i, tail;

        if (copy_from_user(&klogs, ulogs, sizeof(__u32) * 2))
            return -EFAULT;

        req_count = klogs.count;
        if (req_count > USB_AUDIT_LOG_MAX)
            req_count = USB_AUDIT_LOG_MAX;

        mutex_lock(&audit_mutex);

        if (req_count > (__u32)log_count)
            req_count = (__u32)log_count;

        /* Copy entries from oldest to newest. */
        tail = (log_head - log_count + USB_AUDIT_LOG_MAX)
               % USB_AUDIT_LOG_MAX;

        for (i = 0; i < (int)req_count; i++) {
            klogs.entries[i] = log_buffer[tail];
            tail = (tail + 1) % USB_AUDIT_LOG_MAX;
        }

        klogs.count = req_count;
        mutex_unlock(&audit_mutex);

        /* Copy the whole structure back (count field is first). */
        if (copy_to_user(ulogs, &klogs, sizeof(klogs)))
            ret = -EFAULT;
        break;
    }

    case USB_AUDIT_RESET_STATS:
        mutex_lock(&audit_mutex);
        memset(&stats, 0, sizeof(stats));
        stats.log_count = log_count;
        anomaly_ring_count = 0;
        anomaly_ring_idx   = 0;
        mutex_unlock(&audit_mutex);
        printk(KERN_INFO "[usb_audit] Statistics reset by PID %d\n",
               current->pid);
        break;

    case USB_AUDIT_SET_ANOMALY: {
        usb_audit_anomaly_t __user *uanom =
            (usb_audit_anomaly_t __user *)arg;
        usb_audit_anomaly_t kanom;

        if (copy_from_user(&kanom, uanom, sizeof(kanom)))
            return -EFAULT;

        mutex_lock(&audit_mutex);
        if (kanom.threshold > 0)
            anomaly_threshold = kanom.threshold;
        if (kanom.window_ms > 0)
            anomaly_window_ms = kanom.window_ms;
        mutex_unlock(&audit_mutex);

        printk(KERN_INFO "[usb_audit] Anomaly config set by PID %d: "
               "threshold=%u window=%ums\n",
               current->pid, anomaly_threshold, anomaly_window_ms);
        break;
    }

    case USB_AUDIT_GET_ANOMALY: {
        usb_audit_anomaly_t __user *uanom =
            (usb_audit_anomaly_t __user *)arg;
        usb_audit_anomaly_t kanom;
        int i, burst = 0;
        ktime_t now, window_start;

        memset(&kanom, 0, sizeof(kanom));
        now = ktime_get();

        mutex_lock(&audit_mutex);
        kanom.threshold = anomaly_threshold;
        kanom.window_ms = anomaly_window_ms;

        /* Count recent file ops within the current window. */
        window_start = ktime_sub_ns(now,
                                    (s64)anomaly_window_ms * 1000000ULL);
        for (i = 0; i < anomaly_ring_count; i++) {
            int idx = (anomaly_ring_idx - 1 - i +
                       USB_AUDIT_ANOMALY_RING_SIZE)
                      % USB_AUDIT_ANOMALY_RING_SIZE;
            if (ktime_after(anomaly_ring[idx], window_start))
                burst++;
            else
                break;
        }
        kanom.burst_count = (__u32)burst;
        kanom.alert_triggered = (burst > (int)anomaly_threshold) ? 1 : 0;
        mutex_unlock(&audit_mutex);

        if (copy_to_user(uanom, &kanom, sizeof(kanom)))
            ret = -EFAULT;
        break;
    }

    default:
        ret = -ENOTTY;
        break;
    }

    return ret;
}

/* =========================================================================
 * File Operations Table
 * ========================================================================= */
static const struct file_operations usb_audit_fops = {
    .owner          = THIS_MODULE,
    .open           = usb_audit_open,
    .release        = usb_audit_release,
    .read           = usb_audit_read,
    .write          = usb_audit_write,
    .unlocked_ioctl = usb_audit_ioctl,
};

/* =========================================================================
 * Module Initialisation
 * ========================================================================= */
static int __init usb_audit_init(void)
{
    int ret;

    printk(KERN_INFO "[usb_audit] Initialising USB File Transfer Activity "
           "Driver (Group 10)\n");

    /* -- 1. Allocate a dynamic major number for the character device -- */
    ret = alloc_chrdev_region(&usb_audit_devt, 0, 1, USB_AUDIT_DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ERR "[usb_audit] Failed to allocate device region: %d\n",
               ret);
        return ret;
    }
    printk(KERN_INFO "[usb_audit] Allocated major %d, minor %d\n",
           MAJOR(usb_audit_devt), MINOR(usb_audit_devt));

    /* -- 2. Initialise and add the cdev to the kernel ----------------- */
    cdev_init(&usb_audit_cdev, &usb_audit_fops);
    usb_audit_cdev.owner = THIS_MODULE;

    ret = cdev_add(&usb_audit_cdev, usb_audit_devt, 1);
    if (ret < 0) {
        printk(KERN_ERR "[usb_audit] cdev_add failed: %d\n", ret);
        goto err_unregister_region;
    }

    /* -- 3. Create device class and populate /dev/usb_audit ----------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    usb_audit_class = class_create(USB_AUDIT_DEVICE_NAME);
#else
    usb_audit_class = class_create(THIS_MODULE, USB_AUDIT_DEVICE_NAME);
#endif
    if (IS_ERR(usb_audit_class)) {
        ret = PTR_ERR(usb_audit_class);
        printk(KERN_ERR "[usb_audit] class_create failed: %d\n", ret);
        goto err_cdev_del;
    }

    usb_audit_device = device_create(usb_audit_class, NULL,
                                     usb_audit_devt, NULL,
                                     USB_AUDIT_DEVICE_NAME);
    if (IS_ERR(usb_audit_device)) {
        ret = PTR_ERR(usb_audit_device);
        printk(KERN_ERR "[usb_audit] device_create failed: %d\n", ret);
        goto err_class_destroy;
    }

    /* -- 4. Allocate the circular log buffer -------------------------- */
    log_buffer = kmalloc_array(USB_AUDIT_LOG_MAX,
                               sizeof(usb_audit_log_entry_t), GFP_KERNEL);
    if (!log_buffer) {
        ret = -ENOMEM;
        printk(KERN_ERR "[usb_audit] Failed to allocate log buffer\n");
        goto err_device_destroy;
    }
    memset(log_buffer, 0,
           USB_AUDIT_LOG_MAX * sizeof(usb_audit_log_entry_t));

    /* -- 5. Initialise statistics and anomaly detection --------------- */
    memset(&stats, 0, sizeof(stats));
    memset(anomaly_ring, 0, sizeof(anomaly_ring));
    anomaly_ring_idx   = 0;
    anomaly_ring_count = 0;
    anomaly_last_alert = ktime_set(0, 0);  /* allow immediate first alert */

    /* -- 6. Register USB hotplug notifier ----------------------------- */
    usb_nb.notifier_call = usb_audit_notify;
    usb_register_notify(&usb_nb);
    printk(KERN_INFO "[usb_audit] USB hotplug notifier registered\n");

    printk(KERN_INFO "[usb_audit] Driver loaded successfully.  "
           "Device node: /dev/%s\n", USB_AUDIT_DEVICE_NAME);

    return 0;

    /* Error unwind path — reverse order of initialisation. */
err_device_destroy:
    device_destroy(usb_audit_class, usb_audit_devt);
err_class_destroy:
    class_destroy(usb_audit_class);
err_cdev_del:
    cdev_del(&usb_audit_cdev);
err_unregister_region:
    unregister_chrdev_region(usb_audit_devt, 1);
    return ret;
}

/* =========================================================================
 * Module Cleanup
 * ========================================================================= */
static void __exit usb_audit_exit(void)
{
    printk(KERN_INFO "[usb_audit] Shutting down USB File Transfer Activity "
           "Driver\n");

    /* Unregister USB notifier first so no new events arrive. */
    usb_unregister_notify(&usb_nb);

    /* Free the log buffer. */
    if (log_buffer) {
        kfree(log_buffer);
        log_buffer = NULL;
    }

    /* Destroy device node, class, cdev, and release major number. */
    device_destroy(usb_audit_class, usb_audit_devt);
    class_destroy(usb_audit_class);
    cdev_del(&usb_audit_cdev);
    unregister_chrdev_region(usb_audit_devt, 1);

    printk(KERN_INFO "[usb_audit] Driver unloaded.  Goodbye.\n");
}

module_init(usb_audit_init);
module_exit(usb_audit_exit);
