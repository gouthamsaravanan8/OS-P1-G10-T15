import os
import sys
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Change this depending on pi & usb name
# Run "lsblk" to check active mount points and change path accordingly
USB_TARGET_PATH = "/media/afifpi/Samsung USB"

# Security config for suspicious behavior and trigger alerts
ALERT_THRESHOLD = 5       # max number of file changes allowed
TIME_WINDOW = 3.0         # within this many seconds

class USBMonitorHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        # Stores timestamps of recent file modifications
        self.modification_history = []

    def send_kernel_event(self, code, path, size):
        try:
            fd = os.open("/dev/usb_audit", os.O_WRONLY)
            event_str = f"{code} {path} ({size} bytes)\n"
            os.write(fd, event_str.encode('utf-8'))
            os.close(fd)
        except Exception as e:
            print(f"[WARN] Failed to write event to /dev/usb_audit: {e}")

    def check_anomaly(self, current_time):
        # Sliding window filter: remove events outside our target time window
        self.modification_history = [
            t for t in self.modification_history 
            if current_time - t <= TIME_WINDOW
        ]
        
        # Trigger alert if event frequency exceeds our threshold
        if len(self.modification_history) > ALERT_THRESHOLD:
            print(f"[SECURITY ALERT] Suspicious mass-copy behavior detected!")
            print(f"                 Rate: {len(self.modification_history)} file ops in < {TIME_WINDOW}s")

    def on_created(self, event):
        if event.is_directory:
            return

        now = time.time()
        self.modification_history.append(now)
        self.check_anomaly(now)

        print(f"[NEW_FILE] Detect: {event.src_path}")
        try:
            size = os.path.getsize(event.src_path)
        except FileNotFoundError:
            size = 0
        self.send_kernel_event('C', event.src_path, size)

    def on_modified(self, event):
        if event.is_directory:
            return
        
        now = time.time()
        self.modification_history.append(now)
        self.check_anomaly(now)

        try:
            current_size = os.path.getsize(event.src_path)
            print(f"[WRITING]  Path: {event.src_path} | Size: {current_size} bytes")
        except FileNotFoundError:
            pass

    def on_closed(self, event):
        if event.is_directory:
            return
        try:
            final_size = os.path.getsize(event.src_path)
            print(f"[SUCCESS]  Sync complete: {event.src_path} ({final_size} bytes)")
            self.send_kernel_event('M', event.src_path, final_size)
        except FileNotFoundError:
            pass

    def on_deleted(self, event):
        if event.is_directory:
            return
        print(f"[DELETED]  Path: {event.src_path}")
        self.send_kernel_event('D', event.src_path, 0)

def main():
    if not os.path.exists(USB_TARGET_PATH):
        print(f"Error: Target mount point '{USB_TARGET_PATH}' is offline or invalid.", file=sys.stderr)
        sys.exit(1)

    print(f"Initializing storage audit daemon on: {USB_TARGET_PATH}")
    print(f"Security policy: Alerts trigger if > {ALERT_THRESHOLD} files change in {TIME_WINDOW}s")
    print("Daemon running. Press Ctrl+C to terminate.")

    handler = USBMonitorHandler()
    observer = Observer()
    observer.schedule(handler, path=USB_TARGET_PATH, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nTerminating daemon process...")
        observer.stop()
    
    observer.join()

if __name__ == "__main__":
    main()