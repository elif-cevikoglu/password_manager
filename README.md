# 🐱 Kitty Cat Service - Secure Password Manager

A fun, secure, and surprisingly stealthy password manager built with Python. It uses **strong encryption**, **steganography**, and a **custom GUI** — all wrapped in a deceptively cute cat-themed disguise.

![icon](assets/cat.ico)

---

## 🚀 Features

- 🔐 **Secure encryption** with PBKDF2-HMAC (200k iterations) and AES (via `Fernet`)
- 🖼️ **Steganography**: passwords are encrypted and hidden inside cat images
- 🐾 **GUI Interface** with feline-themed actions:
  - "I have a new cat" → Add a new password
  - "Get me my cat" → Retrieve a saved password
  - "I lost my cat :(" → Delete a password
- 🤷 If no password is found, a random cat image is shown instead
- 📁 Stores all data locally, with optional folder selection
- 🧪 Downloadable `.exe` — no need to install Python!

---

## 📥 Download

👉 [**Click here to download the latest `.exe`**](https://github.com/elif-cevikoglu/password_manager/releases/latest)

> No Python setup required. Just download and run `Kitty Cat Service.exe`.

---

## 🧠 How It Works

- **Passwords** are stored _inside images_ — hidden with LSB steganography.
- The **master key** is split between user input and a local image key file.
- All encrypted vault data is indexed and managed with integrity in mind.
- The GUI provides a user-friendly way to interact with your “cats.”

---

## 👨‍💻 Author

**Elif Çevikoğlu**  
Creator of cute-but-deadly password security 🐈‍⬛🔐
