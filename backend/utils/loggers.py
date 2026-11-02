from datetime import datetime


def log(message):

    current = datetime.now().strftime("%H:%M:%S")

    print(f"[{current}] {message}")