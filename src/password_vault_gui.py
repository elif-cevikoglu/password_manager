# Updated GUI code aligned with password_vault.py changes

import tkinter as tk
from tkinter import filedialog, Toplevel, Label, messagebox
import os
from cryptography.fernet import Fernet
from password_vault import (
    get_paths, create_master_password, verify_master_password,
    encrypt_and_hide, reveal_and_decrypt, list_services,
    delete_service, load_index, save_index, download_random_cat_image
)
import requests
from PIL import Image, ImageTk
from io import BytesIO
from stegano import lsb

class VaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🐱 Kitty Cat Service")
        self.root.geometry("400x450")
        self.root.minsize(360, 400)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.fernet = None
        self.paths = None
        self.cat_image = None
        self.login_screen()

    def get_config_path(self):
        return os.path.join(os.path.expanduser("~"), "Documents", "where_are_my_kitties.txt")

    def get_saved_folder(self):
        config_path = self.get_config_path()
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                line = f.read()
                if line.startswith("My kitties are at "):
                    return line.replace("My kitties are at ", "").strip()
        return None

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def login_screen(self):
        saved_folder = self.get_saved_folder()
        self.clear()
        frame = tk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        frame.columnconfigure(0, weight=1)

        if not saved_folder:
            tk.Label(frame, text="Set a Master Password:").pack(pady=10)
            self.pw_entry = tk.Entry(frame, show="*")
            self.pw_entry.pack(pady=5, fill="x")
            tk.Button(frame, text="Choose Folder & Set Password", command=self.select_folder_and_set_password).pack(pady=10, fill="x")
            return

        self.paths = get_paths(saved_folder)
        if not os.path.exists(self.paths["meta_image"]) or not os.path.exists(self.paths["meta_key_image"]):
            tk.Label(frame, text="Set a Master Password:").pack(pady=10)
            self.pw_entry = tk.Entry(frame, show="*")
            self.pw_entry.pack(pady=5, fill="x")
            tk.Button(frame, text="Set Password", command=self.set_master_password).pack(pady=5, fill="x")
            return

        tk.Label(frame, text="Whose your favorite kitty? We won't tell :)").pack(pady=10)
        self.pw_entry = tk.Entry(frame, show="*")
        self.pw_entry.pack(pady=5, fill="x")
        tk.Button(frame, text="Submit", command=self.try_login).pack(pady=5, fill="x")

    def select_folder_and_set_password(self):
        folder = filedialog.askdirectory(initialdir=os.path.expanduser("~"), title="Select Folder for Vault")
        if not folder:
            self.toast("Cancelled", "No folder selected.")
            return

        folder = os.path.join(folder, "kitties")
        os.makedirs(folder, exist_ok=True)
        with open(self.get_config_path(), "w") as f:
            f.write(f"My kitties are at {folder}")

        self.paths = get_paths(folder)
        pw = self.pw_entry.get()
        if pw:
            create_master_password(pw, self.paths)
            self.toast("Success", "Master password set.")
            self.login_screen()
        else:
            self.toast("Error", "Password field is empty.")

    def set_master_password(self):
        pw = self.pw_entry.get()
        if pw and self.paths:
            create_master_password(pw, self.paths)
            self.toast("Success", "Master password set.")
            self.login_screen()
        else:
            self.toast("Error", "No folder or password found.")

    def try_login(self):
        pw = self.pw_entry.get()
        valid, key = verify_master_password(pw, self.paths)
        if valid:
            self.fernet = Fernet(key)
            self.toast("Access Granted", "Welcome!")
            self.vault_menu()
        else:
            self.toast("Access Denied", "Invalid password")

    def vault_menu(self):
        self.clear()

        frame = tk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=20, pady=10)
        frame.columnconfigure(0, weight=1)

        self.show_cat_meme(frame)

        buttons = [
            ("I have a new cat", self.add_cred),
            ("Get me my cat", self.get_cred),
            ("I lost my cat :(", self.delete_cred),
            ("Exit", self.root.quit)
        ]

        for text, cmd in buttons:
            tk.Button(frame, text=text, command=cmd).pack(pady=5, fill="x")

    def add_cred(self):
        def submit():
            service = service_entry.get().strip().lower()
            pw = pw_entry.get()
            if service and pw:
                result = encrypt_and_hide(service, pw, self.fernet, self.paths)
                if result == "exists":
                    if messagebox.askyesno("Overwrite", f"Credential for '{service}' exists. Overwrite?"):
                        delete_service(service, self.paths)
                        result = encrypt_and_hide(service, pw, self.fernet, self.paths)
                        if result == "saved":
                            self.toast("Updated", f"Credential for '{service}' updated.")
                        else:
                            self.toast("Error", f"Failed to update '{service}'.")
                    else:
                        self.toast("Cancelled", "Credential not saved.")
                        popup.destroy()
                        return
                elif result == "saved":
                    self.toast("Saved", f"Credential for {service} saved.")
                else:
                    self.toast("Error", "An error occurred.")
                popup.destroy()
            else:
                self.toast("Error", "Both fields are required.")

        popup = Toplevel(self.root)
        popup.title("I have a new cat")
        popup.geometry("300x180")
        popup.grab_set()
        popup.columnconfigure(0, weight=1)

        tk.Label(popup, text="Cat's Name:").grid(pady=5, row=0, column=0)
        service_entry = tk.Entry(popup)
        service_entry.grid(pady=5, row=1, column=0, sticky="ew")
        tk.Label(popup, text="Cat's Age:").grid(pady=5, row=2, column=0)
        pw_entry = tk.Entry(popup, show="*")
        pw_entry.grid(pady=5, row=3, column=0, sticky="ew")
        tk.Button(popup, text="Submit", command=submit).grid(pady=10, row=4, column=0)
        service_entry.focus()

    def get_cred(self):
        service = self.simple_input("Get me my cat", "Enter cat's name:")
        if service:
            service = service.strip().lower()
            decrypted = reveal_and_decrypt(service, self.fernet, self.paths)
            if decrypted:
                messagebox.showinfo("🔐 Found Your Cat", f"Go ahead, we aren't looking 👀: {decrypted}")
                return
            img_path = download_random_cat_image(self.paths)
            if img_path:
                img = Image.open(img_path).resize((250, 200))
                img_tk = ImageTk.PhotoImage(img)
                popup = Toplevel(self.root)
                popup.title("Here's a cat instead!")
                popup.geometry("420x300")
                tk.Label(popup, text=f"We couldn't find your cat '{service}' but here's another kitty for you!").pack(pady=5)
                tk.Label(popup, image=img_tk).pack()
                popup.image = img_tk

    def delete_cred(self):
        service = self.simple_input("I lost my cat :(", "Cat's Name:")
        if service:
            index = load_index(self.paths)
            service = service.strip().lower()
            if service in index:
                if messagebox.askyesno("Confirm Deletion", f"Forget about '{service}'?"):
                    try:
                        os.remove(index[service])
                    except:
                        pass
                    del index[service]
                    save_index(index, self.paths)
                    messagebox.showinfo("Forgotten", f"'{service}' is forgotten.")
            else:
                messagebox.showerror("Error", "Cat not found.")

    def show_cat_meme(self, parent):
        try:
            res = requests.get("https://cataas.com/cat/says/MEOW", timeout=10)
            img = Image.open(BytesIO(res.content)).resize((200, 150))
            self.cat_image = ImageTk.PhotoImage(img)
            tk.Label(parent, image=self.cat_image).pack(pady=10)
        except:
            pass

    def toast(self, title, msg):
        toast = Toplevel(self.root)
        toast.overrideredirect(True)
        toast.geometry(f"300x50+{self.root.winfo_x()+50}+{self.root.winfo_y()+50}")
        toast.configure(bg="black")
        tk.Label(toast, text=msg, fg="white", bg="black").pack(expand=True)
        toast.after(2000, toast.destroy)

    def simple_input(self, title, prompt):
        result = {'value': None}

        def submit():
            result['value'] = entry.get()
            popup.destroy()

        popup = Toplevel(self.root)
        popup.title(title)
        popup.geometry("300x120")
        popup.grab_set()
        popup.columnconfigure(0, weight=1)
        tk.Label(popup, text=prompt).grid(pady=10, row=0, column=0)
        entry = tk.Entry(popup)
        entry.grid(pady=5, row=1, column=0, sticky="ew")
        tk.Button(popup, text="Submit", command=submit).grid(pady=10, row=2, column=0)
        entry.focus()
        self.root.wait_window(popup)
        return result['value']

if __name__ == "__main__":
    root = tk.Tk()
    app = VaultApp(root)
    root.mainloop()