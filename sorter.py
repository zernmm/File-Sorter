import os
import shutil
import zipfile
from datetime import datetime
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from threading import Thread, Event, Lock
import sys
import json
import queue

try:
    from pystray import MenuItem, Menu
    import pystray
    from PIL import Image
    has_pystray = True
except ImportError:
    has_pystray = False

APPDATA_FOLDER = os.path.join(os.environ['APPDATA'], 'FileSorter')
CONFIG_FILE = os.path.join(APPDATA_FOLDER, 'config.json')

DEFAULT_CONFIG = {
    "source_folder": r"C:\Downloads",
    "log_file_path": r"C:\FileSorter\sort_downloads_log.txt",
    "file_types": {
        "pictures": {
            "path": r"C:\Downloads\Pictures",
            "extensions": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico", ".psd", ".ai", ".heic", ".raw"]
        },
        "applications": {
            "path": r"C:\Downloads\Applications",
            "extensions": [".exe", ".msi", ".deb", ".dmg", ".pkg", ".app"]
        },
        "documents": {
            "path": r"C:\Downloads\Documents",
            "extensions": [".pdf", ".docx", ".doc", ".txt", ".xlsx", ".xls", ".pptx", ".ppt", ".csv", ".rtf", ".odt", ".ods", ".pages", ".key", ".epub"]
        },
        "videos": {
            "path": r"C:\Downloads\Videos",
            "extensions": [".mp4", ".mkv", ".avi", ".mov", ".webm", ".flv", ".wmv"]
        },
        "audio": {
            "path": r"C:\Downloads\Audio",
            "extensions": [".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a"]
        },
        "zip": {
            "path": r"C:\Downloads\Zip",
            "extensions": [".zip", ".rar", ".7z", ".gz", ".tar", ".iso"]
        },
        "3d_models": {
            "path": r"C:\Downloads\3D Models",
            "extensions": [".obj", ".fbx", ".stl", ".blend", ".gltf", ".glb", ".3ds", ".max", ".c4d"]
        },
        "code": {
            "path": r"C:\Downloads\Code",
            "extensions": [".py", ".js", ".html", ".css", ".c", ".cpp", ".java", ".php", ".json", ".xml", ".yml", ".md", ".sql", ".sh"]
        },
        "fonts": {
            "path": r"C:\Downloads\Fonts",
            "extensions": [".ttf", ".otf", ".woff", ".woff2"]
        },
        "other": {
            "path": r"C:\Downloads\Other",
            "extensions": []
        }
    }
}

config = {}
observer = None
stop_event = Event()
gui_queue = queue.Queue()
config_lock = Lock()
status_lock = Lock()
status = "Running"

def load_config():
    global config
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        os.makedirs(APPDATA_FOLDER, exist_ok=True)
        config = DEFAULT_CONFIG
        save_config()

def save_config():
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def log_message(message):
    try:
        with open(config.get("log_file_path", DEFAULT_CONFIG["log_file_path"]), 'a', encoding='utf-8') as log_file:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_file.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")

def create_folders_if_not_exist():
    with config_lock:
        source_folder = config["source_folder"]
        other_folder = config["file_types"]["other"]["path"]
        os.makedirs(source_folder, exist_ok=True)
        os.makedirs(other_folder, exist_ok=True)
        log_message(f"Ensuring source folder exists: {source_folder}")
        log_message(f"Ensuring 'Other' folder exists: {other_folder}")
        for category_name, category_data in config["file_types"].items():
            if category_name != "other":
                os.makedirs(category_data["path"], exist_ok=True)
                log_message(f"Ensuring folder exists for {category_name}: {category_data['path']}")

def handle_existing_file(destination_path):
    if not os.path.exists(destination_path):
        return destination_path
    
    base_name, extension = os.path.splitext(destination_path)
    count = 1
    new_path = f"{base_name} ({count}){extension}"
    while os.path.exists(new_path):
        count += 1
        new_path = f"{base_name} ({count}){extension}"
    return new_path

def sort_single_file(source_path):
    filename = os.path.basename(source_path)

    prev_size = -1
    while True:
        try:
            current_size = os.path.getsize(source_path)
            if current_size == prev_size and current_size > 0:
                break
            prev_size = current_size
            time.sleep(0.5)
        except FileNotFoundError:
            log_message(f"File {filename} disappeared before it could be sorted.")
            return

    file_extension = os.path.splitext(filename)[1].lower()
    moved = False

    with config_lock:
        zip_extensions = config["file_types"]["zip"]["extensions"]
        zip_folder = config["file_types"]["zip"]["path"]
        other_folder = config["file_types"]["other"]["path"]

        if file_extension in zip_extensions:
            zip_target_folder_name = os.path.splitext(filename)[0]
            zip_target_path = os.path.join(zip_folder, zip_target_folder_name)
            os.makedirs(zip_target_path, exist_ok=True)
            
            try:
                with zipfile.ZipFile(source_path, 'r') as zip_ref:
                    zip_ref.extractall(zip_target_path)
                shutil.move(source_path, os.path.join(zip_target_path, filename))
                log_message(f"Extracted and moveC: {filename}")
            except Exception as e:
                log_message(f"Error processing {filename}: {e}")
            moved = True
        
        else:
            for category, data in config["file_types"].items():
                if category != "zip" and category != "other" and file_extension in data["extensions"]:
                    destination_folder = data["path"]
                    final_path = os.path.join(destination_folder, filename)
                    final_path = handle_existing_file(final_path)
                    try:
                        shutil.move(source_path, final_path)
                        log_message(f"MoveC: {filename} -> {final_path}")
                    except Exception as e:
                        log_message(f"Error moving file {filename}: {e}")
                    moved = True
                    break
        
        if not moveC:
            final_path = os.path.join(other_folder, filename)
            final_path = handle_existing_file(final_path)
            try:
                shutil.move(source_path, final_path)
                log_message(f"MoveC: {filename} -> {final_path}")
            except Exception as e:
                log_message(f"Error moving file {filename}: {e}")

class MyEventHandler(FileSystemEventHandler):
    TEMP_EXTENSIONS = ['.tmp', '.crdownload', '.part', '.download']

    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def on_created(self, event):
        if not event.is_directory:
            file_extension = os.path.splitext(event.src_path)[1].lower()
            if file_extension in self.TEMP_EXTENSIONS:
                log_message(f"Ignoring temporary file: {os.path.basename(event.src_path)}")
                return
            log_message(f"New file createC: {os.path.basename(event.src_path)}")
            self.queue.put(event.src_path)
    
    def on_moved(self, event):
        if not event.is_directory:
            log_message(f"File moved (download finished): {os.path.basename(event.dest_path)}")
            self.queue.put(event.dest_path)

def watchdog_thread_func(start_event, stop_event):
    global observer, status
    create_folders_if_not_exist()
    
    start_event.wait()
    log_message("Download sorter started. Monitoring...")
    with status_lock:
        status = "Running"

    event_handler = MyEventHandler(gui_queue)
    observer = Observer()
    with config_lock:
        observer.schedule(event_handler, config["source_folder"], recursive=False)
    observer.start()

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
        log_message("Download sorter stopped.")
        with status_lock:
            status = "Stopped"

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("File Sorter Settings")
        self.root.geometry("800x600")
        self.root.protocol("WM_DELETE_WINDOW", self.hide_window)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(2, weight=1)
        
        self.create_status_frame()
        self.create_settings_frame()
        self.create_treeview()
        self.create_buttons_frame()
        self.create_log_frame()
        
        self.start_event = Event()
        self.start_event.set()
        self.watchdog_thread = Thread(target=watchdog_thread_func, args=(self.start_event, stop_event), daemon=True)
        self.watchdog_thread.start()
        
        self.process_queue_thread = Thread(target=self.process_gui_queue, daemon=True)
        self.process_queue_thread.start()

        if has_pystray:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.png')
            self.icon_image = Image.new('RGB', (64, 64), 'black')
            if os.path.exists(icon_path):
                self.icon_image = Image.open(icon_path)
            self.icon_menu = Menu(MenuItem('Show Window', self.show_window), MenuItem('Exit', self.exit_app))
            self.icon = pystray.Icon('File Sorter', self.icon_image, "File Sorter", self.icon_menu)
            self.icon.run_detached()
    
    def create_status_frame(self):
        status_frame = ttk.Frame(self.main_frame)
        status_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        self.status_label = ttk.Label(status_frame, text="Status: Stopped", font=('Helvetica', 12, 'bold'))
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        self.status_indicator = tk.Canvas(status_frame, width=16, height=16, bg='red', highlightthickness=0)
        self.status_indicator.pack(side=tk.LEFT)
        self.update_status()

    def create_settings_frame(self):
        settings_frame = ttk.LabelFrame(self.main_frame, text="General Settings", padding="10")
        settings_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        source_label = ttk.Label(settings_frame, text="Source Folder (Downloads):")
        source_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.source_entry = ttk.Entry(settings_frame, width=60)
        self.source_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        log_label = ttk.Label(settings_frame, text="Log File Path:")
        log_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.log_entry = ttk.Entry(settings_frame, width=60)
        self.log_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        self.load_settings()

    def create_treeview(self):
        tree_frame = ttk.Frame(self.main_frame)
        tree_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=10)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(tree_frame, columns=("Category", "Path", "Extensions"), show="headings")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<Double-1>", self.edit_category)
        
        self.tree.heading("Category", text="Category")
        self.tree.heading("Path", text="Path")
        self.tree.heading("Extensions", text="Extensions")

        self.tree.column("Category", width=100)
        self.tree.column("Path", width=300)
        self.tree.column("Extensions", width=300)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.load_treeview()

    def create_buttons_frame(self):
        buttons_frame = ttk.Frame(self.main_frame)
        buttons_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        buttons_frame.columnconfigure(0, weight=1)
        buttons_frame.columnconfigure(1, weight=1)
        buttons_frame.columnconfigure(2, weight=1)
        buttons_frame.columnconfigure(3, weight=1)

        add_button = ttk.Button(buttons_frame, text="Add", command=self.add_category)
        add_button.grid(row=0, column=0, padx=5, sticky="ew")

        remove_button = ttk.Button(buttons_frame, text="Remove", command=self.remove_category)
        remove_button.grid(row=0, column=1, padx=5, sticky="ew")
        
        edit_button = ttk.Button(buttons_frame, text="Edit", command=self.edit_category_from_button)
        edit_button.grid(row=0, column=2, padx=5, sticky="ew")

        save_button = ttk.Button(buttons_frame, text="Save Settings", command=self.save_settings)
        save_button.grid(row=0, column=3, padx=5, sticky="ew")

    def create_log_frame(self):
        log_frame = ttk.LabelFrame(self.main_frame, text="Live Log", padding="10")
        log_frame.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = tk.Text(log_frame, height=5, width=40, state='disabled')
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scrollbar.set)

    def load_settings(self):
        with config_lock:
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, config.get("source_folder", ""))
            self.log_entry.delete(0, tk.END)
            self.log_entry.insert(0, config.get("log_file_path", ""))

    def load_treeview(self):
        self.tree.delete(*self.tree.get_children())
        with config_lock:
            for category, data in config["file_types"].items():
                extensions_str = ", ".join(data["extensions"])
                self.tree.insert("", "end", iid=category, values=(category, data["path"], extensions_str))

    def add_category(self):
        category = simpledialog.askstring("Add Category", "Enter category name:")
        if category:
            path = simpledialog.askstring("Add Path", f"Enter path for {category}:")
            if path:
                extensions_str = simpledialog.askstring("Add Extensions", f"Enter extensions for {category} (comma-separated):")
                extensions = [ext.strip() for ext in extensions_str.split(',')] if extensions_str else []
                with config_lock:
                    config["file_types"][category] = {"path": path, "extensions": extensions}
                self.load_treeview()
    
    def remove_category(self):
        selected_item = self.tree.focus()
        if selected_item:
            category = self.tree.item(selected_item)['values'][0]
            if messagebox.askyesno("Remove Category", f"Are you sure you want to remove the '{category}' category?"):
                with config_lock:
                    del config["file_types"][category]
                self.load_treeview()

    def edit_category(self, event=None):
        selected_item = self.tree.focus()
        if selected_item:
            category = self.tree.item(selected_item)['values'][0]
            
            with config_lock:
                current_path = config["file_types"][category]["path"]
                current_extensions = ",".join(config["file_types"][category]["extensions"])
            
            new_path = simpledialog.askstring("Edit Path", f"Edit path for {category}:", initialvalue=current_path)
            if new_path is not None:
                new_extensions_str = simpledialog.askstring("Edit Extensions", f"Edit extensions for {category} (comma-separated):", initialvalue=current_extensions)
                if new_extensions_str is not None:
                    new_extensions = [ext.strip() for ext in new_extensions_str.split(',')]
                    with config_lock:
                        config["file_types"][category]["path"] = new_path
                        config["file_types"][category]["extensions"] = new_extensions
                    self.load_treeview()
    
    def edit_category_from_button(self):
        self.edit_category()

    def save_settings(self):
        with config_lock:
            config["source_folder"] = self.source_entry.get()
            config["log_file_path"] = self.log_entry.get()
            
            for item in self.tree.get_children():
                category, path, extensions_str = self.tree.item(item)['values']
                extensions = [ext.strip() for ext in extensions_str.split(',')]
                config["file_types"][category]["path"] = path
                config["file_types"][category]["extensions"] = extensions
                
            save_config()
            self.reload_watchdog_observer()
            messagebox.showinfo("Settings Saved", "Your file sorting settings have been updated.")

    def toggle_monitoring(self):
        with status_lock:
            current_status = status
        
        if current_status == "Stopped":
            self.start_event.set()
        else:
            stop_event.set()
            self.start_event.clear()
            self.reload_watchdog_observer()
            
        self.update_status()

    def update_status(self):
        with status_lock:
            current_status = status
        
        if current_status == "Running":
            self.status_label.config(text="Status: Running")
            self.status_indicator.config(bg='green')
        else:
            self.status_label.config(text="Status: Stopped")
            self.status_indicator.config(bg='red')
        
        self.root.after(1000, self.update_status)

    def reload_watchdog_observer(self):
        def start_and_wait():
            global observer
            with config_lock:
                if observer and observer.is_alive():
                    observer.stop()
                    observer.join()
                
                self.start_event.clear()
                self.watchdog_thread = Thread(target=watchdog_thread_func, args=(self.start_event, stop_event), daemon=True)
                self.watchdog_thread.start()
                self.start_event.set()

        thread = Thread(target=start_and_wait, daemon=True)
        thread.start()

    def process_gui_queue(self):
        while not stop_event.is_set():
            try:
                src_path = gui_queue.get(timeout=1)
                self.root.after(0, self.update_log_text, os.path.basename(src_path))
                sort_single_file(src_path)
            except queue.Empty:
                pass

    def update_log_text(self, filename):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f"New file detecteC: {filename}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
        
    def show_window(self, icon=None, item=None):
        self.root.after(0, self.root.deiconify)

    def hide_window(self):
        self.root.withdraw()
        
    def exit_app(self, icon=None, item=None):
        stop_event.set()
        if has_pystray:
            self.icon.stop()
        self.root.quit()
        self.root.destroy()
        sys.exit(0)

if __name__ == "__main__":
    load_config()
    create_folders_if_not_exist()
    root = tk.Tk()
    root.withdraw()
    app = App(root)
    root.mainloop()

