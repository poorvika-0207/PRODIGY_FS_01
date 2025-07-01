#!/usr/bin/env python3
"""
Desktop Authentication System with Role-Based Access Control
A single-file Python application using Tkinter for GUI, with secure password hashing and JSON storage.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import json
import os
from datetime import datetime
from typing import Dict, Optional, Any


class UserDataManager:
    """Handles user data storage and retrieval using JSON file"""
    
    def __init__(self, data_file: str = "users.json"):
        self.data_file = data_file
        self.users_data = self._load_users()
    
    def _load_users(self) -> Dict[str, Any]:
        """Load user data from JSON file"""
        if not os.path.exists(self.data_file):
            return {}
        
        try:
            with open(self.data_file, 'r') as file:
                return json.load(file)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading user data: {e}")
            return {}
    
    def _save_users(self) -> bool:
        """Save user data to JSON file"""
        try:
            with open(self.data_file, 'w') as file:
                json.dump(self.users_data, file, indent=2)
            return True
        except IOError as e:
            print(f"Error saving user data: {e}")
            return False
    
    def user_exists(self, username: str) -> bool:
        """Check if username already exists"""
        return username in self.users_data
    
    def add_user(self, username: str, password_hash: str, role: str) -> bool:
        """Add new user to the database"""
        if self.user_exists(username):
            return False
        
        self.users_data[username] = {
            'password_hash': password_hash,
            'role': role,
            'created_at': datetime.now().isoformat(),
            'last_login': None
        }
        return self._save_users()
    
    def verify_user(self, username: str, password_hash: str) -> Optional[Dict[str, Any]]:
        """Verify user credentials and return user data if valid"""
        if username not in self.users_data:
            return None
        
        user_data = self.users_data[username]
        if user_data['password_hash'] == password_hash:
            # Update last login time
            user_data['last_login'] = datetime.now().isoformat()
            self._save_users()
            return user_data
        return None


class PasswordManager:
    """Handles password hashing and validation"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA256"""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    @staticmethod
    def validate_password(password: str) -> tuple[bool, str]:
        """Validate password strength"""
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"
        if len(password) > 50:
            return False, "Password must be less than 50 characters"
        if password.isspace() or not password.strip():
            return False, "Password cannot be empty or only whitespace"
        return True, "Password is valid"


class RegistrationWindow:
    """Registration window GUI"""
    
    def __init__(self, parent, auth_system):
        self.auth_system = auth_system
        self.window = tk.Toplevel(parent)
        self.window.title("User Registration")
        self.window.geometry("400x350")
        self.window.resizable(False, False)
        self.window.grab_set()  # Make window modal
        
        # Center the window
        self.window.transient(parent)
        self.window.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create and layout registration form widgets"""
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Create New Account", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Username field
        ttk.Label(main_frame, text="Username:").pack(anchor=tk.W, pady=(0, 5))
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(main_frame, textvariable=self.username_var, width=30)
        self.username_entry.pack(pady=(0, 15))
        
        # Password field
        ttk.Label(main_frame, text="Password:").pack(anchor=tk.W, pady=(0, 5))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, 
                                       show="*", width=30)
        self.password_entry.pack(pady=(0, 15))
        
        # Confirm Password field
        ttk.Label(main_frame, text="Confirm Password:").pack(anchor=tk.W, pady=(0, 5))
        self.confirm_password_var = tk.StringVar()
        self.confirm_password_entry = ttk.Entry(main_frame, textvariable=self.confirm_password_var,
                                               show="*", width=30)
        self.confirm_password_entry.pack(pady=(0, 15))
        
        # Role selection
        ttk.Label(main_frame, text="Role:").pack(anchor=tk.W, pady=(0, 5))
        self.role_var = tk.StringVar(value="user")
        role_frame = ttk.Frame(main_frame)
        role_frame.pack(pady=(0, 20))
        
        ttk.Radiobutton(role_frame, text="User", variable=self.role_var, 
                       value="user").pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(role_frame, text="Admin", variable=self.role_var, 
                       value="admin").pack(side=tk.LEFT)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Register", 
                  command=self._handle_registration).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Cancel", 
                  command=self.window.destroy).pack(side=tk.LEFT)
        
        # Bind Enter key to registration
        self.window.bind('<Return>', lambda e: self._handle_registration())
        
        # Focus on username entry
        self.username_entry.focus()
    
    def _handle_registration(self):
        """Handle user registration"""
        username = self.username_var.get().strip()
        password = self.password_var.get()
        confirm_password = self.confirm_password_var.get()
        role = self.role_var.get()
        
        # Validate input
        if not username:
            messagebox.showerror("Error", "Username cannot be empty")
            return
        
        if len(username) < 3:
            messagebox.showerror("Error", "Username must be at least 3 characters long")
            return
        
        if len(username) > 20:
            messagebox.showerror("Error", "Username must be less than 20 characters")
            return
        
        # Validate password
        is_valid, message = PasswordManager.validate_password(password)
        if not is_valid:
            messagebox.showerror("Error", message)
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        # Attempt registration
        success, message = self.auth_system.register_user(username, password, role)
        if success:
            messagebox.showinfo("Success", message)
            self.window.destroy()
        else:
            messagebox.showerror("Error", message)


class LoginWindow:
    """Login window GUI"""
    
    def __init__(self, parent, auth_system):
        self.auth_system = auth_system
        self.window = tk.Toplevel(parent)
        self.window.title("User Login")
        self.window.geometry("350x250")
        self.window.resizable(False, False)
        self.window.grab_set()  # Make window modal
        
        # Center the window
        self.window.transient(parent)
        self.window.geometry("+%d+%d" % (parent.winfo_rootx() + 75, parent.winfo_rooty() + 75))
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create and layout login form widgets"""
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="User Login", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 30))
        
        # Username field
        ttk.Label(main_frame, text="Username:").pack(anchor=tk.W, pady=(0, 5))
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(main_frame, textvariable=self.username_var, width=25)
        self.username_entry.pack(pady=(0, 15))
        
        # Password field
        ttk.Label(main_frame, text="Password:").pack(anchor=tk.W, pady=(0, 5))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, 
                                       show="*", width=25)
        self.password_entry.pack(pady=(0, 20))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Login", 
                  command=self._handle_login).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Cancel", 
                  command=self.window.destroy).pack(side=tk.LEFT)
        
        # Bind Enter key to login
        self.window.bind('<Return>', lambda e: self._handle_login())
        
        # Focus on username entry
        self.username_entry.focus()
    
    def _handle_login(self):
        """Handle user login"""
        username = self.username_var.get().strip()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        success, message = self.auth_system.login_user(username, password)
        if success:
            messagebox.showinfo("Success", message)
            self.window.destroy()
        else:
            messagebox.showerror("Error", message)


class DashboardWindow:
    """Protected dashboard window with role-based access"""
    
    def __init__(self, parent, auth_system, user_data):
        self.auth_system = auth_system
        self.user_data = user_data
        self.window = tk.Toplevel(parent)
        self.window.title(f"Dashboard - {user_data['username']} ({user_data['role'].title()})")
        self.window.geometry("600x400")
        self.window.resizable(True, True)
        
        # Center the window
        self.window.transient(parent)
        self.window.geometry("+%d+%d" % (parent.winfo_rootx() + 25, parent.winfo_rooty() + 25))
        
        self._create_widgets()
        
        # Handle window closing
        self.window.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _create_widgets(self):
        """Create and layout dashboard widgets"""
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = ttk.Label(header_frame, text="Welcome to the Dashboard!", 
                               font=("Arial", 18, "bold"))
        title_label.pack(side=tk.LEFT)
        
        logout_button = ttk.Button(header_frame, text="Logout", 
                                  command=self._handle_logout)
        logout_button.pack(side=tk.RIGHT)
        
        # User info section
        info_frame = ttk.LabelFrame(main_frame, text="User Information", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(info_frame, text=f"Username: {self.user_data['username']}", 
                 font=("Arial", 11)).pack(anchor=tk.W, pady=2)
        ttk.Label(info_frame, text=f"Role: {self.user_data['role'].title()}", 
                 font=("Arial", 11)).pack(anchor=tk.W, pady=2)
        ttk.Label(info_frame, text=f"Account Created: {self._format_datetime(self.user_data['created_at'])}", 
                 font=("Arial", 11)).pack(anchor=tk.W, pady=2)
        
        if self.user_data['last_login']:
            ttk.Label(info_frame, text=f"Last Login: {self._format_datetime(self.user_data['last_login'])}", 
                     font=("Arial", 11)).pack(anchor=tk.W, pady=2)
        
        # Content section based on role
        content_frame = ttk.LabelFrame(main_frame, text="Available Features", padding="10")
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        if self.user_data['role'] == 'admin':
            self._create_admin_content(content_frame)
        else:
            self._create_user_content(content_frame)
    
    def _create_admin_content(self, parent):
        """Create admin-specific content"""
        ttk.Label(parent, text="Administrator Features:", 
                 font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        features = [
            "• View and manage all user accounts",
            "• Access system configuration settings",
            "• Generate user activity reports",
            "• Manage user roles and permissions",
            "• Access to administrative tools"
        ]
        
        for feature in features:
            ttk.Label(parent, text=feature, font=("Arial", 10)).pack(anchor=tk.W, pady=2)
        
        # Admin action buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=(20, 0))
        
        ttk.Button(button_frame, text="View All Users", 
                  command=self._view_all_users).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="System Settings", 
                  command=self._system_settings).pack(side=tk.LEFT)
    
    def _create_user_content(self, parent):
        """Create regular user content"""
        ttk.Label(parent, text="User Features:", 
                 font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        features = [
            "• View personal account information",
            "• Access user-specific content",
            "• Update account preferences",
            "• View activity history"
        ]
        
        for feature in features:
            ttk.Label(parent, text=feature, font=("Arial", 10)).pack(anchor=tk.W, pady=2)
        
        # User action buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=(20, 0))
        
        ttk.Button(button_frame, text="Account Settings", 
                  command=self._account_settings).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="View Profile", 
                  command=self._view_profile).pack(side=tk.LEFT)
    
    def _format_datetime(self, datetime_str: str) -> str:
        """Format datetime string for display"""
        try:
            dt = datetime.fromisoformat(datetime_str)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return datetime_str
    
    def _view_all_users(self):
        """Admin feature: View all users"""
        users = self.auth_system.data_manager.users_data
        user_list = []
        for username, data in users.items():
            user_list.append(f"{username} - {data['role'].title()} - Created: {self._format_datetime(data['created_at'])}")
        
        if user_list:
            messagebox.showinfo("All Users", "\n".join(user_list))
        else:
            messagebox.showinfo("All Users", "No users found in the system.")
    
    def _system_settings(self):
        """Admin feature: System settings placeholder"""
        messagebox.showinfo("System Settings", "System settings panel would be implemented here.\n\nThis is a placeholder for administrative configuration options.")
    
    def _account_settings(self):
        """User feature: Account settings placeholder"""
        messagebox.showinfo("Account Settings", "Account settings panel would be implemented here.\n\nUsers can update their preferences and account information.")
    
    def _view_profile(self):
        """User feature: View profile details"""
        profile_info = f"Username: {self.user_data['username']}\n"
        profile_info += f"Role: {self.user_data['role'].title()}\n"
        profile_info += f"Account Created: {self._format_datetime(self.user_data['created_at'])}\n"
        if self.user_data['last_login']:
            profile_info += f"Last Login: {self._format_datetime(self.user_data['last_login'])}"
        
        messagebox.showinfo("User Profile", profile_info)
    
    def _handle_logout(self):
        """Handle user logout"""
        result = messagebox.askyesno("Logout", "Are you sure you want to logout?")
        if result:
            self.auth_system.logout_user()
            self.window.destroy()
    
    def _on_closing(self):
        """Handle window closing event"""
        self._handle_logout()


class AuthenticationSystem:
    """Main authentication system class"""
    
    def __init__(self):
        self.data_manager = UserDataManager()
        self.password_manager = PasswordManager()
        self.current_user = None
        self.dashboard_window = None
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("Authentication System")
        self.root.geometry("400x300")
        self.root.resizable(False, False)
        
        # Center the window
        self._center_window()
        
        self._create_main_window()
    
    def _center_window(self):
        """Center the main window on screen"""
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.root.winfo_screenheight() // 2) - (300 // 2)
        self.root.geometry(f"400x300+{x}+{y}")
    
    def _create_main_window(self):
        """Create main window widgets"""
        main_frame = ttk.Frame(self.root, padding="30")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Authentication System", 
                               font=("Arial", 20, "bold"))
        title_label.pack(pady=(0, 30))
        
        # Subtitle
        subtitle_label = ttk.Label(main_frame, text="Secure Desktop Application", 
                                  font=("Arial", 12))
        subtitle_label.pack(pady=(0, 40))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=20)
        
        login_button = ttk.Button(button_frame, text="Login", width=15,
                                 command=self._show_login_window)
        login_button.pack(pady=(0, 10))
        
        register_button = ttk.Button(button_frame, text="Register", width=15,
                                    command=self._show_registration_window)
        register_button.pack(pady=(0, 10))
        
        exit_button = ttk.Button(button_frame, text="Exit", width=15,
                                command=self.root.quit)
        exit_button.pack()
        
        # Status label
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var, 
                                     font=("Arial", 10))
        self.status_label.pack(pady=(20, 0))
        
        # Set initial status
        user_count = len(self.data_manager.users_data)
        self.status_var.set(f"Users registered: {user_count}")
    
    def _show_login_window(self):
        """Show login window"""
        LoginWindow(self.root, self)
    
    def _show_registration_window(self):
        """Show registration window"""
        RegistrationWindow(self.root, self)
    
    def register_user(self, username: str, password: str, role: str) -> tuple[bool, str]:
        """Register a new user"""
        try:
            # Check if user already exists
            if self.data_manager.user_exists(username):
                return False, "Username already exists. Please choose a different username."
            
            # Hash password
            password_hash = self.password_manager.hash_password(password)
            
            # Add user to database
            if self.data_manager.add_user(username, password_hash, role):
                # Update status
                user_count = len(self.data_manager.users_data)
                self.status_var.set(f"Users registered: {user_count}")
                return True, f"User '{username}' registered successfully as {role}!"
            else:
                return False, "Failed to save user data. Please try again."
        
        except Exception as e:
            return False, f"Registration failed: {str(e)}"
    
    def login_user(self, username: str, password: str) -> tuple[bool, str]:
        """Authenticate user login"""
        try:
            # Hash provided password
            password_hash = self.password_manager.hash_password(password)
            
            # Verify credentials
            user_data = self.data_manager.verify_user(username, password_hash)
            
            if user_data:
                # Set current user
                self.current_user = {
                    'username': username,
                    'role': user_data['role'],
                    'created_at': user_data['created_at'],
                    'last_login': user_data['last_login']
                }
                
                # Show dashboard
                self._show_dashboard()
                
                return True, f"Welcome back, {username}!"
            else:
                return False, "Invalid username or password. Please try again."
        
        except Exception as e:
            return False, f"Login failed: {str(e)}"
    
    def logout_user(self):
        """Logout current user"""
        self.current_user = None
        if self.dashboard_window:
            self.dashboard_window = None
        
        # Update main window status
        user_count = len(self.data_manager.users_data)
        self.status_var.set(f"Users registered: {user_count}")
    
    def _show_dashboard(self):
        """Show protected dashboard window"""
        if self.current_user:
            self.dashboard_window = DashboardWindow(self.root, self, self.current_user)
    
    def run(self):
        """Start the application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            print("\nApplication terminated by user")
        except Exception as e:
            print(f"Application error: {e}")
            messagebox.showerror("Application Error", f"An unexpected error occurred: {e}")


def main():
    """Main application entry point"""
    try:
        app = AuthenticationSystem()
        app.run()
    except Exception as e:
        print(f"Failed to start application: {e}")


if __name__ == "__main__":
    main()

