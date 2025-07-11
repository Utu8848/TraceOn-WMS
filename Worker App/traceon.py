import tkinter as tk
from tkinter import messagebox
from PIL import ImageTk, Image
import sqlite3
import hashlib
import threading
import time
import pyautogui
import pygetwindow as gw
import datetime
import os
import re
from drive_utils import create_or_get_folder, upload_file
import requests
import pytesseract
from pynput import keyboard, mouse

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("TraceOn - Login/Register")
        self.root.state('zoomed')
        self.root.configure(bg="#f0f2f5")  # Light background
        self.last_input_time = time.time()
        self.monitoring = False
        self.user_stopped = False
        self.has_started_once = False


        self.frame = tk.Frame(root, bg="white", bd=2, relief="groove")
        self.frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self.frame.configure(padx=60, pady=40)
        
        try:
            
            logo_img = Image.open("logo.png")
            logo_img = logo_img.resize((180, 130))
            self.logo_img = ImageTk.PhotoImage(logo_img)
            tk.Label(self.frame, image=self.logo_img, bg="white").grid(row=0, column=0, columnspan=2, pady=(20, 10))
        except:
            tk.Label(self.frame, text="TraceOn", font=("Segoe UI", 32, "bold"), bg="white", fg="#333").grid(row=0, column=0, columnspan=2, pady=(20, 10))
        
        self.eye_open_img = ImageTk.PhotoImage(Image.open("eye_open.png").resize((28, 28)))
        self.eye_closed_img = ImageTk.PhotoImage(Image.open("eye_closed.png").resize((28, 28)))

        self.mode = 'login'
        self.build_form()

    def build_form(self):
        self.frame.columnconfigure(0, weight=1)
        self.frame.columnconfigure(1, weight=1)

        for widget in self.frame.winfo_children()[1:]:
            widget.destroy()

        font_label = ("Segoe UI", 14)
        font_entry = ("Segoe UI", 14)
        entry_config = {
            "font": font_entry,
            "width": 30,
            "relief": tk.FLAT,
            "bd": 1,
            "highlightthickness": 1,
            "highlightcolor": "#4CAF50",
            "highlightbackground": "#ccc",
            "bg": "#f9f9f9",
            "insertbackground": "black"
        }

        row_offset = 1
        labels = ["Username", "Worker Code", "Overseer Code"]
        for i, label in enumerate(labels):
            tk.Label(self.frame, text=label, font=font_label, bg="white", anchor="w", fg="#555").grid(
                row=row_offset + i * 2, column=0, columnspan=2, sticky='w', padx=20, pady=(10 if i == 0 else 0, 0))
        
            entry = tk.Entry(self.frame, **entry_config)
            entry.grid(row=row_offset + i * 2 + 1, column=0, columnspan=2, padx=20, pady=6, sticky="ew")
        
            if label == "Username":
                self.username = entry
            elif label == "Worker Code":
                self.worker_code = entry
            elif label == "Overseer Code":
                self.overseer_code = entry

        # Password label
        tk.Label(self.frame, text="Password", font=font_label, bg="white", fg="#555").grid(
            row=row_offset + 6, column=0, columnspan=2, sticky='w', padx=20, pady=(10, 0))

        # Password input with eye icon inside
        pwd_wrapper = tk.Frame(self.frame, bg="white")
        pwd_wrapper.grid(row=row_offset + 7, column=0, columnspan=2, padx=20, pady=6, sticky="ew")
        pwd_wrapper.columnconfigure(0, weight=1)

        self.password = tk.Entry(pwd_wrapper, **entry_config, show="*")
        self.password.grid(row=0, column=0, sticky="ew")

        self.show_pwd = False
        self.eye_icon = tk.Button(
            pwd_wrapper,
            image=self.eye_open_img,
            command=self.toggle_password,
            bg="white",
            activebackground="#f9f9f9",
            font=("Segoe UI", 12),
            bd=0,
            padx=0,
            pady=0,
            relief="flat",
            cursor="hand2",
            height=28,  # match the icon size
            width=28
        )
        self.eye_icon.grid(row=0, column=1, sticky="e", padx=(5, 0))

        # Action button (Login/Register)
        btn_color = "#4CAF50" if self.mode == 'login' else "#2196F3"
        btn_text = "Login" if self.mode == 'login' else "Register"

        action_btn = tk.Button(
            self.frame,
            text=btn_text,
            command=self.login if self.mode == 'login' else self.register,
            font=("Segoe UI", 14, "bold"),
            bg=btn_color, fg="white",
            activebackground="#45a049", activeforeground="white",
            padx=10, pady=5, bd=0, width=28
        )
        action_btn.grid(row=row_offset + 9, column=0, columnspan=2, padx=20, pady=(20, 10), sticky="ew")

        # Toggle login/register mode
        toggle_text = "Go to Register" if self.mode == 'login' else "Go to Login"
        toggle_btn = tk.Button(
            self.frame,
            text=toggle_text,
            command=self.switch_mode,
            font=("Segoe UI", 12),
            bg="white", fg="#0066cc",
            activeforeground="#004c99", bd=0, cursor="hand2"
        )
        toggle_btn.grid(row=row_offset + 10, column=0, columnspan=2, pady=(0, 20))


    def toggle_password(self):
        self.show_pwd = not self.show_pwd
        self.password.config(show="" if self.show_pwd else "*")
        self.eye_icon.config(image=self.eye_closed_img if self.show_pwd else self.eye_open_img)

    def switch_mode(self):
        self.mode = 'register' if self.mode == 'login' else 'login'
        self.build_form()

    def hash_password(self, pwd):
        return hashlib.sha256(pwd.encode()).hexdigest()
    
    def is_valid_inputs(self, uname, wcode, ocode, pwd):
        # Check 4-digit worker and overseer codes
        if not re.fullmatch(r'\d{4}', wcode):
            messagebox.showerror("Invalid Worker Code", "Worker Code must be exactly 4 digits.")
            return False
        if not re.fullmatch(r'\d{4}', ocode):
            messagebox.showerror("Invalid Overseer Code", "Overseer Code must be exactly 4 digits.")
            return False
        
        # Password length
        if len(pwd) <= 8:
            messagebox.showerror("Invalid Password", "Password must be more than 8 characters.")
            return False
        
        # Password complexity
        if not re.search(r'[A-Z]', pwd):
            messagebox.showerror("Invalid Password", "Password must include at least one uppercase letter.")
            return False
        if not re.search(r'[a-z]', pwd):
            messagebox.showerror("Invalid Password", "Password must include at least one lowercase letter.")
            return False
        if not re.search(r'\d', pwd):
            messagebox.showerror("Invalid Password", "Password must include at least one digit.")
            return False
        if not re.search(r'[^\w\s]', pwd):  # symbol check
            messagebox.showerror("Invalid Password", "Password must include at least one symbol.")
            return False

        return True

    def register(self):
        uname = self.username.get().strip()
        wcode = self.worker_code.get().strip()
        ocode = self.overseer_code.get().strip()
        pwd = self.password.get()

        if not all([uname, wcode, ocode, pwd]):
            messagebox.showerror("Error", "All fields are required")
            return
        
        if not self.is_valid_inputs(uname, wcode, ocode, pwd):
            return

        # Step 1: Check if overseer exists via Flask site API
        try:
            response = requests.post("http://127.0.0.1:5000/api/check_overseer",  # Replace with your hosted URL if needed
                                    json={"overseer_code": ocode})
            result = response.json()

            if not result.get("exists"):
                messagebox.showerror("Error", f"Overseer with code '{ocode}' does not exist.")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Could not contact the server. {e}")
            return


        hashed_pwd = self.hash_password(pwd)

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # Check if this worker code + overseer code pair already exists
        cursor.execute("SELECT * FROM users WHERE worker_code=? AND overseer_code=?", (wcode, ocode))
        if cursor.fetchone():
            messagebox.showerror("Error", "User with the same worker code already exists for the overseer")
            conn.close()
            return

        cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (uname, wcode, ocode, hashed_pwd))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Registration Successful!")

        # ✅ Send worker info to manager website via API
        try:
            response = requests.post("http://127.0.0.1:5000/api/register_worker", json={
                "username": uname,
                "worker_code": wcode,
                "overseer_code": ocode
            })
            result = response.json()
            if not result.get("success"):
                print(f"[TraceOn] Failed to sync with manager site: {result.get('error')}")
            else:
                print("[TraceOn] Worker synced to manager site.")
        except Exception as e:
            print(f"[TraceOn] Error syncing with manager site: {e}")

        # Google Drive folder setup
        ROOT_FOLDER_ID = '1O0JY4jHqx3XT4c6n0-awgipjNFdiDziD'  # <-- Replace with your folder ID

        # Create overseer folder
        overseer_folder_id = create_or_get_folder(ocode, parent_id=ROOT_FOLDER_ID)

        # Create worker folder under overseer folder
        worker_folder_name = f"{uname}-{wcode}"
        create_or_get_folder(worker_folder_name, parent_id=overseer_folder_id)

        print(f"[Drive] Created folder for {worker_folder_name} under overseer {ocode}")
        self.switch_mode()

    def login(self):
        uname = self.username.get().strip()
        wcode = self.worker_code.get().strip()
        ocode = self.overseer_code.get().strip()
        pwd = self.password.get()

        if not re.fullmatch(r'\d{4}', wcode) or not re.fullmatch(r'\d{4}', ocode):
            messagebox.showerror("Invalid Input", "Worker and Overseer codes must be exactly 4 digits.")
            return

        hashed_pwd = self.hash_password(pwd)

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND worker_code=? AND overseer_code=? AND password=?",
                       (uname, wcode, ocode, hashed_pwd))
        result = cursor.fetchone()
        conn.close()

        if result:
            messagebox.showinfo("Success", f"Welcome {uname}!")
            self.root.destroy()
            self.open_monitor_window(uname, wcode, ocode)

        else:
            messagebox.showerror("Error", "Invalid credentials")

    def open_monitor_window(self, uname, wcode, ocode):
        monitor_window = tk.Tk()
        monitor_window.title("TraceOn - Monitoring")
        monitor_window.geometry("500x350")
        monitor_window.configure(bg="white")

        self.setup_input_listeners()
        threading.Thread(target=self.auto_pause_check, daemon=True).start()

        monitor_window.grid_rowconfigure(0, weight=1)
        monitor_window.grid_rowconfigure(1, weight=1)
        monitor_window.grid_columnconfigure(0, weight=1)

        # Status label (top right)
        self.status_label = tk.Label(monitor_window, text="Status: OFF", font=("Arial", 12, "bold"), 
                                    fg="red", bg="white", anchor='e')
        self.status_label.place(relx=1.0, rely=0.0, anchor='ne', x=-10, y=10)

        def start_monitoring():
            print(f"[START] Monitoring started for {uname}-{wcode} under overseer {ocode}")
            self.status_label.config(text="Status: ON", fg="green")
            self.monitoring = True
            self.has_started_once = True
            self.user_stopped = False

            self.current_user = uname
            self.current_worker_code = wcode
            self.current_overseer_code = ocode

            threading.Thread(target=self.monitor_and_screenshot, args=(uname, wcode, ocode), daemon=True).start()

        def stop_monitoring():
            print(f"[STOP] Monitoring paused for {uname}-{wcode}")
            self.monitoring = False
            self.user_stopped = True
            self.status_label.config(text="Status: OFF", fg="red")

        start_btn = tk.Button(monitor_window, text="Start", width=20, font=("Arial", 14),
                            command=start_monitoring, bg="#4CAF50", fg="white")
        stop_btn = tk.Button(monitor_window, text="Stop", width=20, font=("Arial", 14),
                            command=stop_monitoring, bg="#f44336", fg="white")

        start_btn.grid(row=0, column=0, pady=10)
        stop_btn.grid(row=1, column=0, pady=10)

        monitor_window.mainloop()

    def capture_and_upload_screenshot(self, uname, wcode, ocode):
        screenshot = pyautogui.screenshot()
        if self.is_private_content(screenshot):
            print("[Filtered] Screenshot contains sensitive content. Not uploaded.")
            return

        date_str = datetime.date.today().strftime("%Y-%m-%d")
        folder_name = f"{ocode}/{uname}-{wcode}/{date_str}"
        local_folder = os.path.join("screenshots", folder_name)
        os.makedirs(local_folder, exist_ok=True)

        timestamp = datetime.datetime.now().strftime("%H-%M-%S")
        filename = f"{timestamp}.png"
        file_path = os.path.join(local_folder, filename)
        screenshot.save(file_path)
        print(f"[Captured] {file_path}")

        # Google Drive Upload
        ROOT_FOLDER_ID = '1O0JY4jHqx3XT4c6n0-awgipjNFdiDziD'
        overseer_folder_id = create_or_get_folder(ocode, parent_id=ROOT_FOLDER_ID)
        worker_folder_id = create_or_get_folder(f"{uname}-{wcode}", parent_id=overseer_folder_id)
        date_folder_id = create_or_get_folder(date_str, parent_id=worker_folder_id)

        upload_file(file_path, date_folder_id)
        print(f"[Uploaded] to Google Drive")

        os.remove(file_path)

    def monitor_and_screenshot(self, uname, wcode, ocode):
        self.monitoring = True
        seen_windows = set()
        known_windows = {win.title for win in gw.getAllWindows() if win.title.strip() != ""}
        last_active_title = None
        last_periodic_time = time.time()

        while self.monitoring:
            try:
                now = time.time()

                # --- Check for new windows (not present during startup) ---
                current_windows = set()
                for win in gw.getAllWindows():
                    if win.title.strip() != "":
                        current_windows.add(win.title)

                # Find genuinely new windows
                new_titles = current_windows - known_windows
                if new_titles:
                    for title in new_titles:
                        print(f"[New] Detected: {title}")
                        self.capture_and_upload_screenshot(uname, wcode, ocode)
                        known_windows.add(title)
                        seen_windows.add(title)  # prevent immediate duplicate capture

                # --- Detect foreground window switch ---
                try:
                    active_window = gw.getActiveWindow()
                    if active_window and active_window.title.strip() != "":
                        current_active_title = active_window.title
                        if current_active_title != last_active_title:
                            if current_active_title in known_windows and current_active_title not in seen_windows:
                                print(f"[Switch] User focused: {current_active_title}")
                                self.capture_and_upload_screenshot(uname, wcode, ocode)
                                seen_windows.add(current_active_title)
                            last_active_title = current_active_title
                except Exception as e:
                    print(f"[ActiveWin Error] {e}")

                # --- Take periodic screenshot every 30 seconds ---
                if now - last_periodic_time >= 10 * 60:
                    print("[Timer] Taking periodic screenshot...")
                    self.capture_and_upload_screenshot(uname, wcode, ocode)
                    last_periodic_time = now

            except Exception as e:
                print(f"[Error] {e}")

            time.sleep(2)

    def is_private_content(self, image):
        """Check if screenshot contains private info using OCR and keyword filter."""
        try:
            text = pytesseract.image_to_string(image).lower()
            sensitive_keywords = ["password", "otp", "pin", "username", "gmail", "inbox", "account number"]
            return any(word in text for word in sensitive_keywords)
        except Exception as e:
            print(f"[OCR Error] {e}")
            return False

    def setup_input_listeners(self):
        def on_input(_):
            self.last_input_time = time.time()
            if not self.monitoring and not self.user_stopped and self.has_started_once:
                self.resume_monitoring()

        keyboard_listener = keyboard.Listener(on_press=on_input)
        mouse_listener = mouse.Listener(on_move=on_input, on_click=on_input, on_scroll=on_input)
        
        keyboard_listener.start()
        mouse_listener.start()

    def auto_pause_check(self):
        while True:
            if self.monitoring and time.time() - self.last_input_time > 30:
                print("[Auto-Pause] No input detected. Pausing monitoring.")
                self.status_label.config(text="Status: OFF", fg="red")
                self.monitoring = False
            time.sleep(5)  # check every 5 seconds

    def resume_monitoring(self):
        print("[Resume] Input detected. Resuming monitoring.")
        self.status_label.config(text="Status: ON", fg="green")

        if not self.monitoring:
            self.monitoring = True
            threading.Thread(target=self.monitor_and_screenshot, args=(self.current_user, self.current_worker_code, self.current_overseer_code), daemon=True).start()

def setup_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT,
            worker_code TEXT,
            overseer_code TEXT,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()


if __name__ == "__main__":
    setup_database()
    root = tk.Tk()
    app = App(root)
    root.mainloop()