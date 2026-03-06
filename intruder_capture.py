import cv2
import os
import datetime

INTRUDER_DIR = "intruders"
if not os.path.exists(INTRUDER_DIR):
    os.makedirs(INTRUDER_DIR)

# ---------------------- CAPTURE INTRUDER ----------------------
def capture_intruder(reason="Unknown Attempt"):
    cam = cv2.VideoCapture(0)        # CAMERA INDEX (0 = default webcam)
    if not cam.isOpened():
        print("⚠ Camera not accessible!")
        return None

    ret, frame = cam.read()
    cam.release()

    if ret:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{INTRUDER_DIR}/intruder_{timestamp}.jpg"
        cv2.imwrite(filename, frame)

        # Log details
        log_intruder(reason, filename)
        print(f"📸 Intruder Captured → {filename}")
        return filename

    print("⚠ Failed to capture image")
    return None


# ---------------------- LOG ATTEMPT ----------------------
def log_intruder(reason, image_path):
    log_file = "intruder_log.txt"
    time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_file, "a") as f:
        f.write(f"[{time}] {reason} | Image: {image_path}\n")

    print(f"📝 Logged: {reason}")
