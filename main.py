import tkinter as tk
from tkinter import ttk, messagebox
from supabase import create_client, Client
from Crypto.Cipher import AES
import base64
import os
import random
import string
from dotenv import load_dotenv

load_dotenv()

# Replace these with your actual Supabase project URL and API key
SUPABASE_URL = os.getenv('SUPABASE_API_URL')
SUPABASE_KEY = os.getenv('SUPABASE_API_KEY')

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Generate a key for encryption
# In production, securely store and retrieve this key
encryption_key = os.urandom(32)  # 256-bit key

def pad(data):
    pad_length = 16 - (len(data) % 16)
    return data + chr(pad_length) * pad_length

def unpad(data):
    pad_length = ord(data[-1])
    return data[:-pad_length]

def encrypt_data(raw_data):
    raw_padded = pad(raw_data)
    iv = os.urandom(16)  # Initialization vector
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(raw_padded.encode('utf-8'))
    return base64.b64encode(iv + encrypted).decode('utf-8')

def decrypt_data(enc_data):
    enc = base64.b64decode(enc_data)
    iv = enc[:16]
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(enc[16:])
    return unpad(decrypted.decode('utf-8'))

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.user_session = None  # Store user session
        self.setup_login_window()

    def setup_login_window(self):
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Login interface
        self.root.geometry("300x250")
        tk.Label(self.root, text="Login", font=("Helvetica", 16)).pack(pady=10)
        tk.Label(self.root, text="Email").pack()
        self.email_entry = tk.Entry(self.root)
        self.email_entry.pack()
        tk.Label(self.root, text="Password").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=5)
        tk.Button(self.root, text="Login", command=self.login).pack()
        tk.Button(self.root, text="Sign Up", command=self.setup_signup_window).pack(pady=5)

    def login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        try:
            response = supabase.auth.sign_in(email=email, password=password)
            if response.user:
                self.user_session = response
                messagebox.showinfo("Login Successful", "Welcome!")
                self.setup_main_window()
            else:
                messagebox.showerror("Login Failed", "Invalid credentials.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def setup_signup_window(self):
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Signup interface
        self.root.geometry("300x300")
        tk.Label(self.root, text="Sign Up", font=("Helvetica", 16)).pack(pady=10)
        tk.Label(self.root, text="Email").pack()
        self.signup_email_entry = tk.Entry(self.root)
        self.signup_email_entry.pack()
        tk.Label(self.root, text="Password").pack()
        self.signup_password_entry = tk.Entry(self.root, show="*")
        self.signup_password_entry.pack(pady=5)
        tk.Label(self.root, text="Confirm Password").pack()
        self.confirm_password_entry = tk.Entry(self.root, show="*")
        self.confirm_password_entry.pack(pady=5)
        tk.Button(self.root, text="Sign Up", command=self.signup).pack()
        tk.Button(self.root, text="Back to Login", command=self.setup_login_window).pack(pady=5)

    def signup(self):
        email = self.signup_email_entry.get()
        password = self.signup_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        try:
            response = supabase.auth.sign_up(email=email, password=password)
            if response.user:
                messagebox.showinfo("Success", "Account created!")
                self.setup_login_window()
            else:
                messagebox.showerror("Sign Up Failed", "Please try again.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def setup_main_window(self):
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.geometry("600x400")
        tk.Label(self.root, text="Password Manager", font=("Helvetica", 16)).pack(pady=10)

        # Tabs for different functionalities
        tab_control = ttk.Notebook(self.root)
        self.password_tab = ttk.Frame(tab_control)
        self.cards_tab = ttk.Frame(tab_control)
        self.ids_tab = ttk.Frame(tab_control)

        tab_control.add(self.password_tab, text='Passwords')
        tab_control.add(self.cards_tab, text='Credit/Debit Cards')
        tab_control.add(self.ids_tab, text='Identification Cards')
        tab_control.pack(expand=1, fill='both')

        # Add content to each tab
        self.setup_password_tab()
        self.setup_cards_tab()
        self.setup_ids_tab()

        tk.Button(self.root, text="Logout", command=self.logout).pack(pady=5)

    def setup_password_tab(self):
        tk.Button(self.password_tab, text="Add Password", command=self.add_password_window).pack(pady=5)
        tk.Button(self.password_tab, text="View Passwords", command=self.view_passwords_window).pack(pady=5)

    def add_password_window(self):
        add_win = tk.Toplevel(self.root)
        add_win.title("Add Password")
        add_win.geometry("400x500")

        tk.Label(add_win, text="Title").pack()
        title_entry = tk.Entry(add_win)
        title_entry.pack()

        tk.Label(add_win, text="Username/Email").pack()
        username_entry = tk.Entry(add_win)
        username_entry.pack()

        tk.Label(add_win, text="Password").pack()
        password_entry = tk.Entry(add_win)
        password_entry.pack()

        tk.Label(add_win, text="URL").pack()
        url_entry = tk.Entry(add_win)
        url_entry.pack()

        tk.Label(add_win, text="Category").pack()
        category_entry = tk.Entry(add_win)
        category_entry.pack()

        tk.Label(add_win, text="Notes").pack()
        notes_entry = tk.Text(add_win, height=5)
        notes_entry.pack()

        def save_password():
            title = title_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            url = url_entry.get()
            category = category_entry.get()
            notes = notes_entry.get("1.0", tk.END)
            encrypted_password = encrypt_data(password)

            data = {
                'user_id': self.user_session.user.id,
                'title': title,
                'username': username,
                'password': encrypted_password,
                'url': url,
                'category': category,
                'notes': notes
            }

            try:
                supabase.table('passwords').insert(data).execute()
                messagebox.showinfo("Success", "Password saved!")
                add_win.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(add_win, text="Generate Password", command=lambda: self.generate_password(password_entry)).pack(pady=5)
        tk.Button(add_win, text="Save", command=save_password).pack(pady=5)

    def generate_password(self, entry_field):
        length = 16
        characters = string.ascii_letters + string.digits + string.punctuation
        random_password = ''.join(random.choice(characters) for i in range(length))
        entry_field.delete(0, tk.END)
        entry_field.insert(0, random_password)

    def view_passwords_window(self):
        view_win = tk.Toplevel(self.root)
        view_win.title("Your Passwords")
        view_win.geometry("800x400")

        try:
            response = supabase.table('passwords').select('*').eq('user_id', self.user_session.user.id).execute()
            passwords = response.data

            cols = ('Title', 'Username', 'Password', 'URL', 'Category', 'Notes')
            tree = ttk.Treeview(view_win, columns=cols, show='headings')
            for col in cols:
                tree.heading(col, text=col)
            for pwd in passwords:
                decrypted_password = decrypt_data(pwd['password'])
                tree.insert("", tk.END, values=(
                    pwd['title'],
                    pwd['username'],
                    decrypted_password,
                    pwd['url'],
                    pwd['category'],
                    pwd['notes']
                ))
            tree.pack(expand=True, fill='both')

            # Search functionality
            tk.Label(view_win, text="Search").pack()
            search_entry = tk.Entry(view_win)
            search_entry.pack()

            def search_passwords():
                query = search_entry.get().lower()
                for item in tree.get_children():
                    tree.delete(item)
                for pwd in passwords:
                    if query in pwd['title'].lower() or query in pwd['category'].lower():
                        decrypted_password = decrypt_data(pwd['password'])
                        tree.insert("", tk.END, values=(
                            pwd['title'],
                            pwd['username'],
                            decrypted_password,
                            pwd['url'],
                            pwd['category'],
                            pwd['notes']
                        ))

            tk.Button(view_win, text="Search", command=search_passwords).pack(pady=5)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def setup_cards_tab(self):
        tk.Button(self.cards_tab, text="Add Card", command=self.add_card_window).pack(pady=5)
        tk.Button(self.cards_tab, text="View Cards", command=self.view_cards_window).pack(pady=5)

    def add_card_window(self):
        add_card_win = tk.Toplevel(self.root)
        add_card_win.title("Add Credit/Debit Card")
        add_card_win.geometry("400x400")

        tk.Label(add_card_win, text="Cardholder Name").pack()
        name_entry = tk.Entry(add_card_win)
        name_entry.pack()

        tk.Label(add_card_win, text="Card Number").pack()
        number_entry = tk.Entry(add_card_win)
        number_entry.pack()

        tk.Label(add_card_win, text="Expiry Date (MM/YY)").pack()
        expiry_entry = tk.Entry(add_card_win)
        expiry_entry.pack()

        tk.Label(add_card_win, text="CVV").pack()
        cvv_entry = tk.Entry(add_card_win)
        cvv_entry.pack()

        def save_card():
            name = name_entry.get()
            number = number_entry.get()
            expiry = expiry_entry.get()
            cvv = cvv_entry.get()
            encrypted_number = encrypt_data(number)
            encrypted_cvv = encrypt_data(cvv)

            data = {
                'user_id': self.user_session.user.id,
                'cardholder_name': name,
                'card_number': encrypted_number,
                'expiry_date': expiry,
                'cvv': encrypted_cvv
            }

            try:
                supabase.table('credit_cards').insert(data).execute()
                messagebox.showinfo("Success", "Card saved!")
                add_card_win.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(add_card_win, text="Save", command=save_card).pack(pady=5)

    def view_cards_window(self):
        view_cards_win = tk.Toplevel(self.root)
        view_cards_win.title("Your Cards")
        view_cards_win.geometry("800x400")

        try:
            response = supabase.table('credit_cards').select('*').eq('user_id', self.user_session.user.id).execute()
            cards = response.data

            cols = ('Cardholder Name', 'Card Number', 'Expiry Date', 'CVV')
            tree = ttk.Treeview(view_cards_win, columns=cols, show='headings')
            for col in cols:
                tree.heading(col, text=col)
            for card in cards:
                decrypted_number = decrypt_data(card['card_number'])
                decrypted_cvv = decrypt_data(card['cvv'])
                tree.insert("", tk.END, values=(
                    card['cardholder_name'],
                    decrypted_number,
                    card['expiry_date'],
                    decrypted_cvv
                ))
            tree.pack(expand=True, fill='both')
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def setup_ids_tab(self):
        tk.Button(self.ids_tab, text="Add ID", command=self.add_id_window).pack(pady=5)
        tk.Button(self.ids_tab, text="View IDs", command=self.view_ids_window).pack(pady=5)

    def add_id_window(self):
        add_id_win = tk.Toplevel(self.root)
        add_id_win.title("Add Identification Card")
        add_id_win.geometry("400x400")

        tk.Label(add_id_win, text="ID Type").pack()
        id_type_entry = tk.Entry(add_id_win)
        id_type_entry.pack()

        tk.Label(add_id_win, text="ID Number").pack()
        id_number_entry = tk.Entry(add_id_win)
        id_number_entry.pack()

        tk.Label(add_id_win, text="Expiry Date (MM/YY)").pack()
        id_expiry_entry = tk.Entry(add_id_win)
        id_expiry_entry.pack()

        def save_id():
            id_type = id_type_entry.get()
            id_number = id_number_entry.get()
            id_expiry = id_expiry_entry.get()
            encrypted_id_number = encrypt_data(id_number)

            data = {
                'user_id': self.user_session.user.id,
                'id_type': id_type,
                'id_number': encrypted_id_number,
                'expiry_date': id_expiry
            }

            try:
                supabase.table('identification_cards').insert(data).execute()
                messagebox.showinfo("Success", "ID saved!")
                add_id_win.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(add_id_win, text="Save", command=save_id).pack(pady=5)

    def view_ids_window(self):
        view_ids_win = tk.Toplevel(self.root)
        view_ids_win.title("Your Identification Cards")
        view_ids_win.geometry("800x400")

        try:
            response = supabase.table('identification_cards').select('*').eq('user_id', self.user_session.user.id).execute()
            ids = response.data

            cols = ('ID Type', 'ID Number', 'Expiry Date')
            tree = ttk.Treeview(view_ids_win, columns=cols, show='headings')
            for col in cols:
                tree.heading(col, text=col)
            for id_card in ids:
                decrypted_id_number = decrypt_data(id_card['id_number'])
                tree.insert("", tk.END, values=(
                    id_card['id_type'],
                    decrypted_id_number,
                    id_card['expiry_date']
                ))
            tree.pack(expand=True, fill='both')
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def logout(self):
        supabase.auth.sign_out()
        self.user_session = None
        messagebox.showinfo("Logout", "You have been logged out.")
        self.setup_login_window()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
