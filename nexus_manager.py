import tkinter as tk
from tkinter import ttk, messagebox, Menu, simpledialog
import sqlite3
import os
import sys
import webbrowser
import base64
import random
import string
import datetime
import hashlib
import time

# ==========================================
# 1. SECURITY & CONFIG LAYER
# ==========================================
HAS_CRYPTO = False
try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    pass

class SecurityManager:
    def __init__(self, key_path):
        self.key_path = key_path
        self.key = None
        self.cipher = None
        self.load_or_generate_key()

    def load_or_generate_key(self):
        try:
            if HAS_CRYPTO:
                if os.path.exists(self.key_path):
                    with open(self.key_path, "rb") as kf:
                        self.key = kf.read()
                else:
                    self.key = Fernet.generate_key()
                    with open(self.key_path, "wb") as kf:
                        kf.write(self.key)
                self.cipher = Fernet(self.key)
        except Exception as e:
            messagebox.showerror("Security Error", f"Failed to load/generate encryption key:\n{e}")
            sys.exit(1)

    def encrypt(self, text):
        if not text:
            return ""
        try:
            if HAS_CRYPTO and self.cipher:
                return self.cipher.encrypt(text.encode()).decode()
            else:
                return base64.b64encode(text.encode()).decode()
        except Exception:
            return ""

    def decrypt(self, text):
        if not text:
            return ""
        try:
            if HAS_CRYPTO and self.cipher:
                return self.cipher.decrypt(text.encode()).decode()
            else:
                return base64.b64decode(text.encode()).decode()
        except Exception:
            return "[Decryption Error]"
            
    def hash_string(self, text):
        try:
            return hashlib.sha256(text.strip().encode()).hexdigest()
        except Exception:
            return ""

# ==========================================
# 2. DATABASE LAYER
# ==========================================

class Database:
    def __init__(self, db_path):
        self.conn = None
        try:
            self.conn = sqlite3.connect(db_path)
            self.cursor = self.conn.cursor()
            self.init_tables()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Critical DB Failure:\n{e}")
            sys.exit(1)

    def init_tables(self):
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS identities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    color TEXT,
                    description TEXT
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT UNIQUE,
                    identity_id INTEGER,
                    status TEXT, 
                    purpose TEXT,
                    auth_method TEXT DEFAULT 'Email',
                    FOREIGN KEY(identity_id) REFERENCES identities(id)
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    platform TEXT,
                    url TEXT,
                    email_id INTEGER,
                    username TEXT,
                    password_enc TEXT,
                    browser_pref TEXT,
                    notes TEXT,
                    updated_at TEXT,
                    auth_method TEXT,
                    FOREIGN KEY(email_id) REFERENCES emails(id)
                )
            """)
            
            self.cursor.execute("SELECT count(*) FROM identities")
            if self.cursor.fetchone()[0] == 0:
                defaults = [
                    ("Professional", "#2980b9", "Work"),
                    ("Private", "#d35400", "Personal"),
                    ("Enterprise", "#004080", "Admin"),
                    ("Social", "#c0392b", "Media"),
                    ("Ghost", "#7f8c8d", "Burner")
                ]
                self.cursor.executemany("INSERT INTO identities (name, color, description) VALUES (?,?,?)", defaults)
            
            default_config = {
                'lock_timeout': '0', 
                'last_exit': '0', 
                'failed_attempts': '0', 
                'lock_until': '0', 
                'theme': 'Light'
            }
            for k, v in default_config.items():
                self.cursor.execute("SELECT value FROM config WHERE key=?", (k,))
                if not self.cursor.fetchone():
                    self.set_config(k, v)
            
            self.conn.commit()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to initialize tables:\n{e}")

    def get_config(self, key):
        try:
            self.cursor.execute("SELECT value FROM config WHERE key=?", (key,))
            res = self.cursor.fetchone()
            return res[0] if res else None
        except sqlite3.Error:
            return None

    def set_config(self, key, value):
        try:
            self.cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, str(value)))
            self.conn.commit()
        except sqlite3.Error:
            pass

    def get_identities(self):
        try:
            self.cursor.execute("SELECT id, name, color FROM identities")
            return self.cursor.fetchall()
        except sqlite3.Error:
            return []

    def get_emails(self):
        try:
            self.cursor.execute("""
                SELECT e.id, e.address, i.name, e.status
                FROM emails e JOIN identities i ON e.identity_id = i.id
            """)
            return self.cursor.fetchall()
        except sqlite3.Error:
            return []
    
    def add_email(self, address, identity_id, status):
        try:
            self.cursor.execute("INSERT INTO emails (address, identity_id, status) VALUES (?,?,?)",
                                (address, identity_id, status))
            self.conn.commit()
            return True
        except sqlite3.Error:
            return False

    def upsert_account(self, acc_id, platform, url, email_id, username, password_enc, browser, notes, auth_method):
        date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        try:
            if acc_id:
                if password_enc:
                    self.cursor.execute("""
                        UPDATE accounts SET platform=?, url=?, email_id=?, username=?, password_enc=?, browser_pref=?, notes=?, updated_at=?, auth_method=?
                        WHERE id=?""", (platform, url, email_id, username, password_enc, browser, notes, date, auth_method, acc_id))
                else:
                    self.cursor.execute("""
                        UPDATE accounts SET platform=?, url=?, email_id=?, username=?, browser_pref=?, notes=?, updated_at=?, auth_method=?
                        WHERE id=?""", (platform, url, email_id, username, browser, notes, date, auth_method, acc_id))
            else:
                self.cursor.execute("""
                    INSERT INTO accounts (platform, url, email_id, username, password_enc, browser_pref, notes, updated_at, auth_method)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (platform, url, email_id, username, password_enc, browser, notes, date, auth_method))
            self.conn.commit()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to save account:\n{e}")

    def get_vault_data(self, search_query="", identity_filter="All", browser_filter="All"):
        try:
            query = """
                SELECT a.id, a.platform, e.address, i.name, a.browser_pref, a.username, a.password_enc, a.url, i.color, e.status, a.email_id, a.notes, a.auth_method
                FROM accounts a
                JOIN emails e ON a.email_id = e.id
                JOIN identities i ON e.identity_id = i.id
                WHERE 1=1
            """
            params = []
            if search_query:
                query += " AND (a.platform LIKE ? OR e.address LIKE ?)"
                params.extend([f"%{search_query}%", f"%{search_query}%"])
            if identity_filter != "All":
                query += " AND i.name = ?"
                params.append(identity_filter)
            if browser_filter != "All":
                query += " AND a.browser_pref LIKE ?"
                params.append(f"%{browser_filter}%")
                
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except sqlite3.Error:
            return []

    def delete_account(self, acc_id):
        try:
            self.cursor.execute("DELETE FROM accounts WHERE id=?", (acc_id,))
            self.conn.commit()
        except sqlite3.Error:
            pass

# ==========================================
# 3. GUI APPLICATION
# ==========================================

class NexusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Nexus Manager v1.0")
        
        try:
            self.work_dir = "My_Digital_Nexus"
            if not os.path.exists(self.work_dir):
                os.makedirs(self.work_dir)
                
            self.db = Database(os.path.join(self.work_dir, "nexus_data.db"))
            self.security = SecurityManager(os.path.join(self.work_dir, "security.key"))
        except Exception as e:
            messagebox.showerror("Init Error", f"Failed to initialize application:\n{e}")
            sys.exit(1)

        self.setup_window_geometry()
        
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.apply_theme() 
        
        self.check_session()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.bind("<Button-1>", self.global_click_handler)

    def global_click_handler(self, event):
        try:
            widget = event.widget
            if hasattr(self, 'vault_tree') and str(widget) != str(self.vault_tree):
                if self.vault_tree.selection():
                    self.vault_tree.selection_remove(self.vault_tree.selection())
            if hasattr(self, 'email_tree') and str(widget) != str(self.email_tree):
                if self.email_tree.selection():
                    self.email_tree.selection_remove(self.email_tree.selection())
        except Exception:
            pass

    def setup_window_geometry(self):
        try:
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            width = 1280
            height = 720
            x = (screen_width - width) // 2
            y = (screen_height - height) // 2
            
            self.root.geometry(f"{width}x{height}+{x}+{y}")
            
            if sys.platform == "win32":
                self.root.state('zoomed')
            else:
                self.root.attributes('-zoomed', True)
        except Exception:
            self.root.geometry("1000x600")

    def apply_theme(self, specific_theme=None):
        try:
            theme = specific_theme if specific_theme else self.db.get_config('theme')
            
            if theme == "Dark":
                bg = "#2b2b2b"
                fg = "#ffffff"
                field_bg = "#3c3f41"
                header_fg = "#4a90e2"
                select_bg = "#4a90e2"
            elif theme == "Light":
                bg = "#f4f6f7"
                fg = "#000000"
                field_bg = "#ffffff"
                header_fg = "#2c3e50"
                select_bg = "#2980b9"
            else:
                bg = "#f0f0f0"
                fg = "black"
                field_bg = "white"
                header_fg = "black"
                select_bg = "#0078d7"

            self.root.configure(bg=bg)
            self.style.configure("TFrame", background=bg)
            self.style.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
            self.style.configure("TButton", font=("Segoe UI", 10))
            self.style.configure("TCombobox", fieldbackground=field_bg, background=bg, foreground=fg)
            self.style.configure("TEntry", fieldbackground=field_bg, foreground=fg)
            self.style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"), foreground=header_fg, background=bg)
            self.style.configure("Treeview", background=field_bg, foreground=fg, fieldbackground=field_bg, font=("Segoe UI", 10), rowheight=30)
            self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
            self.style.map("Treeview", background=[("selected", select_bg)])

            for widget in self.root.winfo_children():
                if isinstance(widget, tk.Toplevel):
                    widget.configure(bg=bg)
                    for child in widget.winfo_children():
                        if isinstance(child, tk.Canvas): 
                            child.configure(bg=bg)
        except Exception:
            pass

    def on_close(self):
        try:
            self.db.set_config('last_exit', str(time.time()))
        except:
            pass
        self.root.destroy()

    def check_session(self):
        try:
            setup_done = self.db.get_config('setup_complete')
            if not setup_done:
                self.show_first_time_setup()
                return
            
            lock_until = float(self.db.get_config('lock_until') or 0)
            if time.time() < lock_until:
                self.show_login_screen(locked=True)
                return
            
            last_exit = float(self.db.get_config('last_exit') or 0)
            lock_timeout_min = int(self.db.get_config('lock_timeout') or 0)
            
            current_time = time.time()
            time_diff_min = (current_time - last_exit) / 60
            
            if lock_timeout_min == -1 or (lock_timeout_min > 0 and time_diff_min < lock_timeout_min):
                self.build_main_interface()
            else:
                self.show_login_screen()
        except Exception:
            self.show_login_screen()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    # ------------------------------------
    # FIRST TIME SETUP
    # ------------------------------------
    def show_first_time_setup(self):
        self.clear_screen()
        frame = ttk.Frame(self.root)
        frame.pack(expand=True)
        
        ttk.Label(frame, text="NEXUS SETUP", style="Header.TLabel").pack(pady=20)
        
        def entry_row(txt):
            ttk.Label(frame, text=txt).pack(anchor="w", pady=(5,0))
            e = ttk.Entry(frame, width=35)
            e.pack(pady=2)
            return e
        
        u_entry = entry_row("Username:")
        p_entry = entry_row("Password:")
        p_entry.config(show="*")
        
        ttk.Label(frame, text="Emergency Key:").pack(anchor="w", pady=(15,0))
        ttk.Label(frame, text="⚠ CANNOT BE CHANGED LATER", font=("Segoe UI", 8), foreground="red").pack(anchor="w")
        btc_entry = ttk.Entry(frame, width=35)
        btc_entry.pack(pady=2)
        
        ttk.Label(frame, text="Security Questions").pack(anchor="w", pady=(15,5))
        
        ttk.Label(frame, text="Q1:").pack(anchor="w")
        q1_entry = ttk.Entry(frame, width=35)
        q1_entry.insert(0, "What is you pet name?")
        q1_entry.pack(pady=2)
        a1_entry = entry_row("Answer 1:")
        
        ttk.Label(frame, text="Q2:").pack(anchor="w", pady=(5,0))
        q2_entry = ttk.Entry(frame, width=35)
        q2_entry.insert(0, "In which city you were born?")
        q2_entry.pack(pady=2)
        a2_entry = entry_row("Answer 2:")

        def save_setup():
            if not all([u_entry.get(), p_entry.get(), btc_entry.get(), q1_entry.get(), a1_entry.get(), q2_entry.get(), a2_entry.get()]):
                messagebox.showerror("Error", "All fields mandatory.")
                return
            
            try:
                self.db.set_config('master_user', u_entry.get())
                self.db.set_config('master_pass', self.security.hash_string(p_entry.get()))
                self.db.set_config('btc_key', self.security.hash_string(btc_entry.get()))
                self.db.set_config('sec_q1', q1_entry.get())
                self.db.set_config('sec_a1', self.security.hash_string(a1_entry.get()))
                self.db.set_config('sec_q2', q2_entry.get())
                self.db.set_config('sec_a2', self.security.hash_string(a2_entry.get()))
                self.db.set_config('setup_complete', '1')
                messagebox.showinfo("Success", "System Initialized.")
                self.show_login_screen()
            except Exception as e:
                messagebox.showerror("Error", f"Setup failed: {e}")

        ttk.Button(frame, text="INITIALIZE SYSTEM", command=save_setup).pack(pady=20, fill="x")

    # ------------------------------------
    # LOGIN SCREEN
    # ------------------------------------
    def show_login_screen(self, locked=False):
        self.clear_screen()
        frame = ttk.Frame(self.root)
        frame.pack(expand=True)
        
        if locked:
            lock_until = float(self.db.get_config('lock_until') or 0)
            ttk.Label(frame, text="SECURITY LOCKDOWN", font=("Segoe UI", 24, "bold"), foreground="red").pack(pady=20)
            cd_lbl = ttk.Label(frame, text="", font=("Courier New", 14))
            cd_lbl.pack(pady=10)
            
            def update_timer():
                try:
                    rem = int(lock_until - time.time())
                    if rem <= 0:
                        self.db.set_config('lock_until', '0')
                        self.db.set_config('failed_attempts', '0')
                        self.show_login_screen(locked=False)
                        return
                    m, s = divmod(rem, 60)
                    h, m = divmod(m, 60)
                    cd_lbl.config(text=f"{h:02d}:{m:02d}:{s:02d}")
                    self.root.after(1000, update_timer)
                except:
                    pass
            update_timer()
            
            ttk.Label(frame, text="BTC Bypass Key:").pack(anchor="w", pady=(20,5))
            e_bp = ttk.Entry(frame, width=40)
            e_bp.pack(pady=5)
            
            def bypass():
                try:
                    if self.security.hash_string(e_bp.get()) == self.db.get_config('btc_key'):
                        self.db.set_config('lock_until', '0')
                        self.db.set_config('failed_attempts', '0')
                        messagebox.showinfo("Access", "Protocol Accepted.")
                        self.build_main_interface()
                    else:
                        messagebox.showerror("Denied", "Invalid Key.")
                except Exception:
                    messagebox.showerror("Error", "Validation Error")
                    
            ttk.Button(frame, text="UNLOCK", command=bypass).pack(pady=10, fill="x")
            return
        
        ttk.Label(frame, text="LOGIN", style="Header.TLabel").pack(pady=20)
        ttk.Label(frame, text="Username:").pack(anchor="w")
        u_e = ttk.Entry(frame, width=30)
        u_e.pack(pady=5)
        ttk.Label(frame, text="Password:").pack(anchor="w")
        p_e = ttk.Entry(frame, width=30, show="*")
        p_e.pack(pady=5)
        
        def login(e=None):
            try:
                if u_e.get() == self.db.get_config('master_user') and self.security.hash_string(p_e.get()) == self.db.get_config('master_pass'):
                    self.db.set_config('failed_attempts', '0')
                    self.build_main_interface()
                else:
                    f = int(self.db.get_config('failed_attempts') or 0) + 1
                    self.db.set_config('failed_attempts', str(f))
                    if f >= 3:
                        self.db.set_config('lock_until', str(time.time() + 3600))
                        self.show_login_screen(locked=True)
                    else:
                        messagebox.showerror("Error", f"Failed {f}/3")
            except Exception:
                messagebox.showerror("Error", "Login Process Error")
        
        self.root.bind('<Return>', login)
        ttk.Button(frame, text="ENTER", command=login).pack(pady=10, fill="x")
        ttk.Button(frame, text="Forgot Password?", command=self.forgot_password_logic).pack(pady=5)

    def forgot_password_logic(self):
        try:
            q1 = self.db.get_config('sec_q1') or "Q1"
            q2 = self.db.get_config('sec_q2') or "Q2"
            a1 = simpledialog.askstring("Recovery", q1)
            a2 = simpledialog.askstring("Recovery", q2)
            
            if not a1 or not a2:
                return
                
            if self.security.hash_string(a1) == self.db.get_config('sec_a1') and self.security.hash_string(a2) == self.db.get_config('sec_a2'):
                np = simpledialog.askstring("Reset", "New Password:", show="*")
                if np:
                    self.db.set_config('master_pass', self.security.hash_string(np))
                    self.db.set_config('failed_attempts', '0')
                    messagebox.showinfo("Success", "Updated.")
            else:
                self.db.set_config('lock_until', str(time.time() + 7200))
                messagebox.showerror("ALERT", "Recovery Failed. Locked 2 Hours.")
                self.show_login_screen(locked=True)
        except Exception:
            pass

    # ------------------------------------
    # MAIN UI
    # ------------------------------------
    def build_main_interface(self):
        self.clear_screen()
        self.root.unbind('<Return>')
        
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=10, pady=5)
        ttk.Label(top, text="NEXUS MANAGER", style="Header.TLabel").pack(side="left")
        ttk.Button(top, text="⚙️ SETTINGS", command=self.open_settings).pack(side="right")
        
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(expand=1, fill="both", padx=10, pady=5)
        
        self.tab_vault = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_vault, text="  🔐 VAULT  ")
        self.build_vault_tab()
        
        self.tab_emails = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_emails, text="  📧 INVENTORY  ")
        self.build_email_tab()

    # ------------------------------------
    # SETTINGS
    # ------------------------------------
    def open_settings(self):
        win = tk.Toplevel(self.root)
        win.title("Settings")
        
        # [USER CONFIG] CHANGE SETTINGS WINDOW SIZE HERE (Width x Height)
        win.geometry("500x500")
        
        bg = self.root.cget("bg")
        win.configure(bg=bg)
        
        try:
            canvas = tk.Canvas(win, bg=bg, highlightthickness=0)
            scrollbar = ttk.Scrollbar(win, orient="vertical", command=canvas.yview)
            frame = ttk.Frame(canvas)
            
            frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.create_window((0, 0), window=frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            scrollbar.pack(side="right", fill="y")
            canvas.pack(side="left", fill="both", expand=True)

            ttk.Label(frame, text="Appearance", style="Header.TLabel").pack(anchor="w", padx=20, pady=(20,5))
            ttk.Label(frame, text="Theme:").pack(anchor="w", padx=20)
            theme_var = tk.StringVar(value=self.db.get_config('theme'))
            theme_cb = ttk.Combobox(frame, textvariable=theme_var, values=["System", "Light", "Dark"], state="readonly")
            theme_cb.pack(fill="x", padx=20, pady=5)
            
            def preview_theme(event):
                self.apply_theme(theme_var.get())
                new_bg = self.root.cget("bg")
                win.configure(bg=new_bg)
                canvas.configure(bg=new_bg)
            theme_cb.bind("<<ComboboxSelected>>", preview_theme)

            ttk.Label(frame, text="Behavior", style="Header.TLabel").pack(anchor="w", padx=20, pady=(20,5))
            ttk.Label(frame, text="Auto-Lock Timeout:").pack(anchor="w", padx=20)
            to_var = tk.StringVar()
            cur_to = self.db.get_config('lock_timeout')
            opts = {"0": "Always (On Close)", "1": "1 Minute", "5": "5 Minutes", "30": "30 Minutes", "-1": "Never"}
            rev_opts = {v: k for k, v in opts.items()}
            to_cb = ttk.Combobox(frame, textvariable=to_var, values=list(opts.values()), state="readonly")
            to_cb.pack(fill="x", padx=20, pady=5)
            to_cb.set(opts.get(cur_to, "Always (On Close)"))

            ttk.Label(frame, text="Master Credentials", style="Header.TLabel").pack(anchor="w", padx=20, pady=(20,5))
            ttk.Label(frame, text="New Master Password:").pack(anchor="w", padx=20)
            e_pass = ttk.Entry(frame, show="*")
            e_pass.pack(fill="x", padx=20, pady=5)
            
            ttk.Label(frame, text="Security Questions", style="Header.TLabel").pack(anchor="w", padx=20, pady=(20,5))
            
            ttk.Label(frame, text="Question 1:").pack(anchor="w", padx=20)
            e_q1 = ttk.Entry(frame)
            e_q1.insert(0, self.db.get_config('sec_q1') or "")
            e_q1.pack(fill="x", padx=20, pady=2)
            ttk.Label(frame, text="Answer 1:").pack(anchor="w", padx=20)
            e_a1 = ttk.Entry(frame)
            e_a1.pack(fill="x", padx=20, pady=2)
            
            ttk.Label(frame, text="Question 2:").pack(anchor="w", padx=20, pady=(5,0))
            e_q2 = ttk.Entry(frame)
            e_q2.insert(0, self.db.get_config('sec_q2') or "")
            e_q2.pack(fill="x", padx=20, pady=2)
            ttk.Label(frame, text="Answer 2:").pack(anchor="w", padx=20)
            e_a2 = ttk.Entry(frame)
            e_a2.pack(fill="x", padx=20, pady=2)

            def save_all():
                try:
                    self.db.set_config('theme', theme_var.get())
                    self.apply_theme(theme_var.get())
                    self.db.set_config('lock_timeout', rev_opts.get(to_cb.get(), "0"))
                    
                    if e_pass.get():
                        self.db.set_config('master_pass', self.security.hash_string(e_pass.get()))
                    if e_q1.get():
                        self.db.set_config('sec_q1', e_q1.get())
                    if e_q2.get():
                        self.db.set_config('sec_q2', e_q2.get())
                    if e_a1.get():
                        self.db.set_config('sec_a1', self.security.hash_string(e_a1.get()))
                    if e_a2.get():
                        self.db.set_config('sec_a2', self.security.hash_string(e_a2.get()))
                        
                    messagebox.showinfo("Saved", "Settings Updated.")
                    win.destroy()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save settings: {e}")
                
            ttk.Button(frame, text="SAVE SETTINGS", command=save_all).pack(pady=30, padx=20, fill="x")

            branding = tk.Label(frame, text="Developed by rx76d", font=("Segoe UI", 7), fg="#1a1a1a", bg=bg)
            branding.pack(side="bottom", pady=(0, 20))
        except Exception:
            pass

    # ------------------------------------
    # VAULT TAB
    # ------------------------------------
    def build_vault_tab(self):
        ctrl = ttk.Frame(self.tab_vault)
        ctrl.pack(fill="x", pady=10)
        
        ttk.Button(ctrl, text="+ ADD NEW", command=lambda: self.open_account_modal(None)).pack(side="left", padx=5)
        
        ttk.Label(ctrl, text="Search:").pack(side="left", padx=(15, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda n, i, m: self.refresh_vault())
        ttk.Entry(ctrl, textvariable=self.search_var, width=20).pack(side="left")
        
        ttk.Label(ctrl, text="Identity:").pack(side="left", padx=(15, 5))
        self.filter_id_var = tk.StringVar(value="All")
        ids = ["All"] + [x[1] for x in self.db.get_identities()]
        cb_id = ttk.Combobox(ctrl, textvariable=self.filter_id_var, values=ids, state="readonly", width=12)
        cb_id.pack(side="left")
        cb_id.bind("<<ComboboxSelected>>", lambda e: self.refresh_vault())
        
        ttk.Label(ctrl, text="Browser:").pack(side="left", padx=(15, 5))
        self.filter_br_var = tk.StringVar(value="All")
        browsers = ["All", "Chrome", "Firefox", "Edge", "Opera", "Tor"]
        cb_br = ttk.Combobox(ctrl, textvariable=self.filter_br_var, values=browsers, state="readonly", width=12)
        cb_br.pack(side="left")
        cb_br.bind("<<ComboboxSelected>>", lambda e: self.refresh_vault())

        cols = ("ID", "Platform", "Email", "Identity", "Browser", "Username", "Auth")
        self.vault_tree = ttk.Treeview(self.tab_vault, columns=cols, show="headings")
        self.vault_tree.heading("ID", text="ID"); self.vault_tree.column("ID", width=0, stretch=False)
        self.vault_tree.heading("Platform", text="Platform"); self.vault_tree.column("Platform", width=140)
        self.vault_tree.heading("Email", text="Linked Email"); self.vault_tree.column("Email", width=220)
        self.vault_tree.heading("Identity", text="Identity"); self.vault_tree.column("Identity", width=100)
        self.vault_tree.heading("Browser", text="Logged In"); self.vault_tree.column("Browser", width=140)
        self.vault_tree.heading("Username", text="Username"); self.vault_tree.column("Username", width=140)
        self.vault_tree.heading("Auth", text="Auth Method"); self.vault_tree.column("Auth", width=100)
        self.vault_tree.pack(expand=True, fill="both")
        
        self.vault_tree.bind("<Button-3>", self.on_right_click)
        self.vault_tree.bind("<Double-1>", self.on_double_click)

        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="✏️ Edit", command=self.edit_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🚀 Launch", command=self.launch_url)
        self.context_menu.add_command(label="📋 Copy Password", command=self.copy_password)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🗑 Delete", command=self.delete_entry)

        btn_frame = ttk.Frame(self.tab_vault)
        btn_frame.pack(fill="x", pady=10)
        ttk.Button(btn_frame, text="🚀 LAUNCH SITE", command=self.launch_url).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="📋 COPY PASSWORD", command=self.copy_password).pack(side="left", padx=5)
        
        self.refresh_vault()

    def on_right_click(self, event):
        iid = self.vault_tree.identify_row(event.y)
        if iid: 
            self.vault_tree.selection_set(iid)
            self.context_menu.post(event.x_root, event.y_root)
            
    def on_double_click(self, event):
        self.edit_selected()
        
    def edit_selected(self):
        sel = self.vault_tree.selection()
        if not sel: return
        row_id = self.vault_tree.item(sel[0])['values'][0]
        full_data = self.db.get_vault_data()
        target_row = next((r for r in full_data if r[0] == row_id), None)
        if target_row: 
            self.open_account_modal(target_row)

    # ------------------------------------
    # ADD/EDIT ACCOUNT WITH SCROLL
    # ------------------------------------
    def open_account_modal(self, existing_data=None):
        is_edit = existing_data is not None
        emails = self.db.get_emails()
        if not emails:
            messagebox.showerror("No Emails", "Please add an email first.")
            return

        win = tk.Toplevel(self.root)
        win.title("Edit Account" if is_edit else "Add New Account")
        
        # [USER CONFIG] CHANGE ADD ACCOUNT WINDOW SIZE HERE (Width x Height)
        win.geometry("450x580")
        
        self.apply_theme() 
        bg = self.root.cget("bg")
        win.configure(bg=bg)

        try:
            canvas = tk.Canvas(win, bg=bg, highlightthickness=0)
            scrollbar = ttk.Scrollbar(win, orient="vertical", command=canvas.yview)
            frame = ttk.Frame(canvas)
            
            frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.create_window((0, 0), window=frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            scrollbar.pack(side="right", fill="y")
            canvas.pack(side="left", fill="both", expand=True)

            def lbl(t):
                ttk.Label(frame, text=t).pack(anchor="w", padx=20, pady=(10,0))
                
            def entry():
                e = ttk.Entry(frame, width=45)
                e.pack(padx=20, pady=2)
                return e

            lbl("Platform Name:")
            e_plat = entry()
            if is_edit: e_plat.insert(0, existing_data[1])

            lbl("Login URL:")
            e_url = entry()
            if is_edit: e_url.insert(0, existing_data[7])

            lbl("Username (Optional):")
            e_user = entry()
            if is_edit: e_user.insert(0, existing_data[5])

            lbl("Linked Email:")
            email_map = {e[1]: e[0] for e in emails}
            sv_email = tk.StringVar()
            cb_em = ttk.Combobox(frame, textvariable=sv_email, values=list(email_map.keys()), state="readonly", width=42)
            cb_em.pack(padx=20, pady=2)
            if is_edit:
                sv_email.set(existing_data[2])
            elif emails:
                cb_em.current(0)
            
            lbl("Auth Method:")
            sv_auth = tk.StringVar(value="Password")
            cb_auth = ttk.Combobox(frame, textvariable=sv_auth, values=["Password", "Google OAuth", "Apple ID", "Magic Link", "SSO", "Other"], state="readonly", width=42)
            cb_auth.pack(padx=20, pady=2)
            if is_edit and existing_data[12]:
                sv_auth.set(existing_data[12])

            lbl("Logged In Browsers:")
            browser_cont = ttk.Frame(frame)
            browser_cont.pack(fill="x", padx=20, pady=2)
            browser_combos = []

            def add_br(val=None, btn=None):
                if btn: btn.destroy()
                r = ttk.Frame(browser_cont)
                r.pack(fill="x", pady=2)
                cb = ttk.Combobox(r, values=["Chrome", "Firefox", "Edge", "Opera", "Tor", "Brave"], state="readonly", width=30)
                cb.pack(side="left")
                if val: cb.set(val)
                else: cb.current(0)
                browser_combos.append(cb)
                b = ttk.Button(r, text="+", width=3, command=lambda: add_br(None, b))
                b.pack(side="left", padx=5)

            if is_edit and existing_data[4]:
                br_list = existing_data[4].split(',')
                for i, b in enumerate(br_list):
                    r = ttk.Frame(browser_cont)
                    r.pack(fill="x", pady=2)
                    cb = ttk.Combobox(r, values=["Chrome", "Firefox", "Edge", "Opera", "Tor", "Brave"], state="readonly", width=30)
                    cb.pack(side="left")
                    cb.set(b.strip())
                    browser_combos.append(cb)
                    if i == len(br_list)-1:
                        b = ttk.Button(r, text="+", width=3, command=lambda: add_br(None, b))
                        b.pack(side="left", padx=5)
            else:
                add_br("Chrome")

            lbl("Password:")
            e_pass = ttk.Entry(frame, width=45, show="*")
            e_pass.pack(padx=20, pady=2)
            
            def gen_pass():
                chars = string.ascii_letters + string.digits + "!@#$%"
                pwd = ''.join(random.choice(chars) for i in range(16))
                e_pass.delete(0, tk.END)
                e_pass.insert(0, pwd)
            ttk.Button(frame, text="Generate Random Password", command=gen_pass).pack(pady=2)

            lbl("Notes:")
            e_notes = entry()
            if is_edit: e_notes.insert(0, existing_data[11])

            def save():
                if not e_plat.get() or not sv_email.get():
                    messagebox.showerror("Error", "Required fields missing.")
                    return
                
                sel_br = [c.get() for c in browser_combos if c.get()]
                br_str = ", ".join(list(set(sel_br)))
                raw = e_pass.get()
                enc = self.security.encrypt(raw) if raw else None
                
                if not is_edit and not raw and sv_auth.get() == "Password":
                    messagebox.showerror("Error", "Password required.")
                    return
                
                try:
                    self.db.upsert_account(
                        existing_data[0] if is_edit else None,
                        e_plat.get(),
                        e_url.get(),
                        email_map[sv_email.get()],
                        e_user.get(),
                        enc,
                        br_str,
                        e_notes.get(),
                        sv_auth.get()
                    )
                    self.refresh_vault()
                    win.destroy()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save: {e}")

            ttk.Button(frame, text="SAVE ENTRY", command=save).pack(pady=15, fill="x", padx=20)
        except Exception:
            pass

    def refresh_vault(self):
        for i in self.vault_tree.get_children():
            self.vault_tree.delete(i)
            
        data = self.db.get_vault_data(self.search_var.get(), self.filter_id_var.get(), self.filter_br_var.get())
        
        for row in data:
            status = row[9]
            tags = ()
            if status == "Deprecated": tags = ('deprecated',)
            elif status == "Dormant": tags = ('dormant',)
            self.vault_tree.insert("", "end", values=(row[0], row[1], row[2], row[3], row[4], row[5], row[12]), tags=tags)
            
        self.vault_tree.tag_configure('deprecated', foreground='gray')
        self.vault_tree.tag_configure('dormant', foreground='#d35400')

    def get_selected_row(self):
        sel = self.vault_tree.selection()
        if not sel: return None
        rid = self.vault_tree.item(sel[0])['values'][0]
        data = self.db.get_vault_data()
        for r in data:
            if r[0] == rid: return r
        return None

    def launch_url(self):
        r = self.get_selected_row()
        if not r:
            messagebox.showinfo("Select", "Select a row first.")
            return
        if not r[7]: return
        br = r[4].lower()
        try:
            if "chrome" in br and sys.platform == 'win32': os.system(f"start chrome {r[7]}")
            elif "firefox" in br and sys.platform == 'win32': os.system(f"start firefox {r[7]}")
            elif "edge" in br and sys.platform == 'win32': os.system(f"start msedge {r[7]}")
            else: webbrowser.open(r[7])
        except:
            webbrowser.open(r[7])

    def copy_password(self):
        r = self.get_selected_row()
        if not r:
            messagebox.showinfo("Select", "Select a row first.")
            return
        if not r[6]:
            messagebox.showinfo("Info", "No password stored.")
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.security.decrypt(r[6]))
            messagebox.showinfo("Copied", "Password copied.")
        except Exception:
            messagebox.showerror("Error", "Clipboard access failed")

    def delete_entry(self):
        sel = self.vault_tree.selection()
        if not sel: return
        if messagebox.askyesno("Confirm", "Delete this account?"):
            self.db.delete_account(self.vault_tree.item(sel[0])['values'][0])
            self.refresh_vault()

    def build_email_tab(self):
        f = ttk.LabelFrame(self.tab_emails, text="Register New Email")
        f.pack(fill="x", padx=15, pady=15)
        
        ttk.Label(f, text="Email:").pack(side="left", padx=(10,5), pady=10)
        self.em_addr = ttk.Entry(f, width=30)
        self.em_addr.pack(side="left", padx=5, pady=10)
        
        ttk.Label(f, text="Zone:").pack(side="left", padx=(15,5), pady=10)
        self.em_id_var = tk.StringVar()
        ids = [x[1] for x in self.db.get_identities()]
        cb = ttk.Combobox(f, textvariable=self.em_id_var, values=ids, state="readonly", width=12)
        cb.pack(side="left", padx=5, pady=10)
        if ids: cb.current(0)
        
        ttk.Label(f, text="Status:").pack(side="left", padx=(15,5), pady=10)
        self.em_stat_var = tk.StringVar(value="Active")
        cb_st = ttk.Combobox(f, textvariable=self.em_stat_var, values=["Active", "Dormant", "Deprecated"], state="readonly", width=12)
        cb_st.pack(side="left", padx=5, pady=10)
        
        ttk.Button(f, text="ADD", command=self.add_email, width=10).pack(side="left", padx=20, pady=10)
        
        self.email_tree = ttk.Treeview(self.tab_emails, columns=("Addr", "Id", "Stat"), show="headings")
        self.email_tree.heading("Addr", text="Email Address")
        self.email_tree.heading("Id", text="Identity")
        self.email_tree.heading("Stat", text="Status")
        self.email_tree.pack(expand=True, fill="both", padx=15, pady=10)
        self.refresh_emails()

    def add_email(self):
        val = self.em_addr.get()
        if "@" not in val:
            messagebox.showerror("Error", "Invalid Email.")
            return
        id_name = self.em_id_var.get()
        all_ids = self.db.get_identities()
        rid = next((x[0] for x in all_ids if x[1] == id_name), 1)
        
        if self.db.add_email(val, rid, self.em_stat_var.get()):
            self.em_addr.delete(0, tk.END)
            self.refresh_emails()
        else:
            messagebox.showerror("Error", "Email exists.")

    def refresh_emails(self):
        for i in self.email_tree.get_children():
            self.email_tree.delete(i)
        for r in self.db.get_emails():
            self.email_tree.insert("", "end", values=(r[1], r[2], r[3]))

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = NexusApp(root)
        root.mainloop()
    except Exception as e:
        # Last resort catch for unexpected crashes
        with open("error_log.txt", "w") as f:
            f.write(str(e))

##############################################################################################################################################################################################################################
########     #######    ##        ##    #######    ##            ####       #######     #######     ########            #######   ##    ##        #######      ##   ##     #######      ######      ########                  
##     ##    ##          ##      ##     ##         ##          ##    ##     ##   ##     ##          ##     ##           ##    #   ##    ##        ##   ##       ## ##          ##       ##          ##     ##                 
##     ##    #####        ##    ##      #####      ##         ##      ##    #######     #####       ##     ##           ######       ###          #######        ##           ##        #######     ##     ##                 
##     ##    ##            ##  ##       ##         ##          ##    ##     ##          ##          ##     ##           ##    #     ##            ## ##         ## ##        ##         ##   ##     ##     ##                 
########     #######        ####        #######    ########      ####       ##          #######     ########            ######     ##             ##   ##      ##   ##      ##          #######     ########                  
############################################################################################################################################################################################################################## 