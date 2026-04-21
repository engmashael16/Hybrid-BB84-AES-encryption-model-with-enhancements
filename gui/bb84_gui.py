import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText
import base64
import re
import pyperclip
import threading
import time
import json
from fpdf import FPDF
import subprocess

# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


# Extend Python path to allow module imports from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from bb84_backend.logic.controller import encrypt_file_local, decrypt_file_local
from bb84_backend.core.key_vault import create_vault, load_vault, default_vault_path

class BB84App:
    def __init__(self, root):
        # Initialize main GUI window
        self.root = root
        self.root.title("BB84 Quantum Encryption Tool (Simulator)")
        self.root.geometry("750x720")
        self.root.configure(bg="#f4f4f4")

        # Internal state
        self.file_path = None
        self.encrypted_data = None
        self.key_b = None

        # Build GUI components
        self.create_widgets()

    def create_widgets(self):
        # Radio buttons for selecting mode: encryption or decryption
        self.mode_var = tk.StringVar(value="encrypt")

        title = tk.Label(self.root, text="BB84 Quantum Encryption / Decryption", font=("Arial", 16, "bold"), bg="#f4f4f4")
        title.pack(pady=10)

        mode_frame = tk.Frame(self.root, bg="#f4f4f4")
        tk.Radiobutton(mode_frame, text="Encrypt", variable=self.mode_var, value="encrypt", bg="#f4f4f4", command=self.update_mode).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(mode_frame, text="Decrypt", variable=self.mode_var, value="decrypt", bg="#f4f4f4", command=self.update_mode).pack(side=tk.LEFT, padx=10)
        mode_frame.pack(pady=5)

        # File selection button and label
        tk.Button(self.root, text="Select File", command=self.select_file, bg="#d0eaff").pack(pady=5)
        self.file_label = tk.Label(self.root, text="No file selected", bg="#f4f4f4")
        self.file_label.pack(pady=2)

        # Entry field for Key B (only used in decryption mode)
        self.key_frame = tk.Frame(self.root, bg="#f4f4f4")
        self.key_entry = tk.Entry(self.key_frame, width=80)
        self.key_entry.insert(0, "Key B (only for decryption)")
        self.key_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(self.key_frame, text="Import Key File", command=self.import_key_file, bg="#e0ffe0").pack(side=tk.LEFT)
        tk.Button(self.key_frame, text="Open Vault Key", command=self.load_key_b_from_vault, bg="#fff2cc").pack(side=tk.LEFT, padx=5)

        self.key_frame.pack(pady=5)

         # Generate Graphs Button
        tk.Button(
          self.root,
          text="📊 Generate Result Graphs",
          command=self.generate_graphs,
          bg="#e1f5fe",
          font=("Segoe UI", 10, "bold")
        ).pack(pady=10)

        # Buttons to copy or save Key B (only shown after encryption)
        self.copy_button = tk.Button(self.root, text="Copy Key B", command=self.copy_key_b, bg="#ffd0d0")
        self.copy_button.pack(pady=2)
        self.copy_button.pack_forget()

        self.save_key_button = tk.Button(self.root, text="Save Key B to .txt", command=self.save_key_b_to_file, bg="#ffe4b5")
        self.save_key_button.pack(pady=2)
        self.save_key_button.pack_forget()

        # Main execution button
        tk.Button(self.root, text="Run", command=self.run, bg="#c0ffc0").pack(pady=10)
        tk.Button(self.root, text="Download Metrics Report (PDF)", command=self.download_metrics_pdf, bg="#dcdcdc").pack(pady=5)

        # Output log area
        self.output_box = ScrolledText(self.root, height=10, bg="#ffffff")
        self.output_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Visual indicator for quantum process
        self.visual_frame = tk.Label(self.root, text="Quantum Key Exchange Simulation Status", bg="#f4f4f4", font=("Arial", 10, "italic"))
        self.visual_frame.pack(pady=5)
        self.visual_text = tk.StringVar(value="Idle")
        self.visual_label = tk.Label(self.root, textvariable=self.visual_text, bg="#ffffcc", width=80)
        self.visual_label.pack(pady=5)

        # Set visibility of GUI sections based on selected mode
        self.update_mode()

    def update_mode(self):
        # Update GUI layout based on selected operation mode
        if self.mode_var.get() == "encrypt":
            self.key_frame.pack_forget()
            self.copy_button.pack_forget()
            self.save_key_button.pack_forget()
        else:
            self.key_frame.pack(pady=5)
            self.copy_button.pack_forget()
            self.save_key_button.pack_forget()

    def simulate_quantum_process(self):
        # Simulate quantum key exchange visually
        steps = [
            "Initializing quantum channel...",
            "Alice is generating random bits...",
            "Bob is choosing bases...",
            "Qubits are being sent over the channel...",
            "Bob measures the qubits...",
            "Alice and Bob compare bases...",
            "Final key is extracted from matching bases.",
            "Key used to derive AES-256 key...",
            "Encryption process complete."
        ]
        for step in steps:
            self.visual_text.set(step)
            self.root.update()
            time.sleep(0.7)
        self.visual_text.set("Idle")

    def select_file(self):
        # Prompt user to select a file from the system
        path = filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.file_label.config(text=os.path.basename(path))
    def generate_graphs(self):
        try:
        # Always run from the project root so relative paths are stable
         project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
         script_path = os.path.join(project_root, "bb84_backend", "logic", "plot_results.py")

        # Use the SAME Python interpreter running the GUI (important for venv)
         subprocess.run([sys.executable, script_path], check=True, cwd=project_root)

         out_dir = os.path.join(project_root, "results", "figures")
         messagebox.showinfo("Done", f"✅ Graphs generated.\nSaved in:\n{out_dir}")

        except Exception as e:
         messagebox.showerror("Error", f"❌ Failed to generate graphs:\n{e}")


        # =========================
    # Option A - Key Vault Helpers
    # =========================

    def _ask_vault_passphrase(self, title):
        # Ask for a passphrase (hidden). Return None if user cancels.
        pw = simpledialog.askstring(title, "Enter vault passphrase:", show="*")
        if pw is None:
            return None
        pw = pw.strip()
        if not pw:
            messagebox.showerror("Passphrase Required", "Passphrase cannot be empty.")
            return None
        return pw

    def save_key_b_to_vault(self, bb84_path):
        # Save current Key B into an encrypted vault bound to the .bb84 file
        if not getattr(self, "key_b", None):
            messagebox.showerror("No Key B", "Key B is not available to store.")
            return False

        pw = self._ask_vault_passphrase("Create Key Vault")
        if pw is None:
            return False

        try:
            vault_path = default_vault_path(bb84_path)
            create_vault(self.key_b, bb84_path, pw, vault_path=vault_path)
            messagebox.showinfo("Vault Saved", f"Key vault saved to:\n{vault_path}")
            return True
        except Exception as e:
            messagebox.showerror("Vault Error", f"Failed to create vault:\n{e}")
            return False


    def _ask_passphrase(self, title, confirm=False):
        p1 = simpledialog.askstring(title, "Enter vault passphrase:", show="*")
        if not p1:
            return None

        if not confirm:
            return p1

        p2 = simpledialog.askstring(title, "Confirm passphrase:", show="*")
        if not p2:
            return None

        if p1 != p2:
            messagebox.showerror("Passphrase mismatch", "Passphrases do not match.")
            return None

        return p1
    def _ask_vault_passphrase(self, title):
        # Pop-up asks for passphrase (hidden with *)
        pw = simpledialog.askstring(title, "Enter vault passphrase:", show="*")
        if pw is None:
            return None
        pw = pw.strip()
        return pw if pw else None

    def load_key_b_from_vault(self):
        # Load Key B from the vault file that is bound to the selected .bb84 file
        if not self.file_path:
            messagebox.showerror("No File Selected", "Please select the .bb84 file first.")
            return

        bb84_path = self.file_path
        vault_path = default_vault_path(bb84_path)

        if not os.path.exists(vault_path):
            messagebox.showerror("Vault Not Found", f"No vault file found:\n{vault_path}")
            return

        pw = self._ask_vault_passphrase("Open Key Vault")
        if pw is None:
            return

        try:
            key_b = load_vault(vault_path, bb84_path, pw)
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key_b)
            messagebox.showinfo("Vault Loaded", "Key B loaded from vault successfully.")
        except Exception as e:
            messagebox.showerror("Vault Error", f"Failed to load vault:\n{e}")
                            
    def import_key_file(self):
        # Allow user to import Key B from a text file
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            with open(path, "r") as f:
                content = f.read().strip()
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, content)

    def copy_key_b(self):
        # Copy Key B to clipboard
        if self.key_b:
            pyperclip.copy(self.key_b)
            messagebox.showinfo("Copied", "Key B has been copied to clipboard.")

    def save_key_b_to_file(self):
        # Save Key B as a .txt file
        if self.key_b:
            path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
            if path:
                with open(path, "w") as f:
                    f.write(self.key_b)
                messagebox.showinfo("Saved", f"Key B saved to: {path}")

    def run(self):
        # Start encryption or decryption in a separate thread
        if not self.file_path:
            messagebox.showwarning("No file selected", "Please select a file first.")
            return

        self.output_box.delete(1.0, tk.END)
        self.process_file()


    def process_file(self):
        # Dispatch based on selected mode
        if self.mode_var.get() == "encrypt":
            self.simulate_quantum_process()
            self.encrypt()
        else:
            self.decrypt()

    def encrypt(self):
        # Perform encryption using quantum key and AES
        with open(self.file_path, "rb") as f:
            file_bytes = f.read()

        encrypted_data, key_b = encrypt_file_local(file_bytes, os.path.basename(self.file_path))

        save_path = filedialog.asksaveasfilename(defaultextension=".bb84")
        if not save_path:
            return

        with open(save_path, "w") as f:
            f.write(encrypted_data)

        self.key_b = key_b
        self.save_key_b_to_vault(save_path)

        self.output_box.insert(tk.END, f"File successfully encrypted and saved to: {save_path}\n")
        self.output_box.insert(tk.END, f"\nKey B (required for decryption):\n{key_b}\n")
        self.output_box.insert(tk.END, self.recommendations(key_b))

        self.copy_button.pack(pady=2)
        self.save_key_button.pack(pady=2)


    def decrypt(self):
        # Perform decryption using provided Key B
        with open(self.file_path, "r") as f:
            encrypted_base64 = f.read()

        key_b_input = self.key_entry.get().strip()

        if not re.fullmatch(r"[01]+", key_b_input):
            messagebox.showerror("Invalid Key", "Key B must be a binary string (only 0s and 1s).")
            return

        key_b_bits = [int(b) for b in key_b_input]

        data, metadata = decrypt_file_local(encrypted_base64, key_b_bits)
        if data is None:
            self.output_box.insert(tk.END, f"Decryption failed: {metadata}\n")
            return

                # ---- SAFE output filename/extension detection ----
        if not isinstance(metadata, dict):
            metadata = {}

        orig_name = metadata.get("original_filename") or metadata.get("filename") or "decrypted_file"
        orig_name = os.path.basename(orig_name)

        # 1) extension from metadata (if exists)
        ext = metadata.get("extension") or metadata.get("file_extension")
        if ext:
            ext = ext.lstrip(".").strip().lower()

        # 2) if missing, try from original filename
        _root, _ext = os.path.splitext(orig_name)
        if (not ext) and _ext:
            ext = _ext.lstrip(".").lower()

        # 3) if still missing, infer from file signature (magic bytes)
        if not ext:
            head = data[:16]

            if head.startswith(b"%PDF-"):
                ext = "pdf"
            elif head.startswith(b"\xFF\xD8\xFF"):          # JPEG
                ext = "jpg"
            elif head.startswith(b"\x89PNG\r\n\x1a\n"):     # PNG
                ext = "png"
            elif head.startswith(b"PK\x03\x04"):
                # ZIP / DOCX / XLSX / PPTX
                ext = "zip"
                try:
                    import io, zipfile
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        names = z.namelist()
                        if any(n.startswith("word/") for n in names):
                            ext = "docx"
                        elif any(n.startswith("xl/") for n in names):
                            ext = "xlsx"
                        elif any(n.startswith("ppt/") for n in names):
                            ext = "pptx"
                except Exception:
                    pass
            else:
                ext = "bin"

        # Build default filename shown in Save As dialog
        default_name = orig_name
        if not os.path.splitext(default_name)[1]:
            default_name = f"{default_name}.{ext}"

        save_path = filedialog.asksaveasfilename(
            defaultextension=f".{ext}",
            initialfile=default_name,
            filetypes=[(f"{ext.upper()} files", f"*.{ext}"), ("All files", "*.*")]
        )
                
        if not save_path:
            return

        with open(save_path, "wb") as f:
            f.write(data)

        self.output_box.insert(tk.END, f"File successfully decrypted and saved to: {save_path}\n")

    def recommendations(self, key_b):
        # Estimate strength of Key B based on bit balance
        ones = key_b.count('1')
        zeros = key_b.count('0')
        balance = abs(ones - zeros)
        status = "Strong" if balance < len(key_b) * 0.4 else "Weak"
        return f"\nKey B Strength Estimate: {status} (1s: {ones}, 0s: {zeros})\n"

    def download_metrics_pdf(self):
        # Load JSON metrics and export to PDF report
        try:
            with open("bb84_metrics.json", "r") as f:
                metrics = json.load(f)
        except:
            messagebox.showerror("Error", "Metrics file not found.")
            return
        # === (NEW) Key Quality Metrics: Ones Ratio + Binary Entropy + Min-Entropy ===
        import math

        def _to_int(x):
            try:
                return int(x)
            except:
                return None

        # 1) حاول نجيب counts من ملف bb84_metrics.json (إذا موجودة)
        ones = _to_int(metrics.get("Key B - Count of 1s"))
        zeros = _to_int(metrics.get("Key B - Count of 0s"))

        # 2) إذا ما موجودة بالـJSON، استخدم self.key_b (بعد التشفير)
        if (ones is None or zeros is None):
            kb = getattr(self, "key_b", None)
            if isinstance(kb, str) and set(kb).issubset({"0", "1"}):
                ones = kb.count("1")
                zeros = kb.count("0")

        # 3) احسب p1 و Entropy الصحيح للمفتاح الثنائي
        if ones is not None and zeros is not None:
            n = ones + zeros
            if n > 0:
                p1 = ones / n
                p0 = 1.0 - p1

                # Binary Shannon Entropy (Eq.13 corrected for binary key)
                if 0.0 < p1 < 1.0:
                    H_bin = -(p0 * math.log2(p0) + p1 * math.log2(p1))
                else:
                    H_bin = 0.0

                # Min-Entropy
                H_inf = -math.log2(max(p0, p1)) if max(p0, p1) > 0 else 0.0

                metrics["Ones Ratio (p1)"] = round(p1, 6)
                metrics["Binary Shannon Entropy (H_bin)"] = round(H_bin, 6)
                metrics["Min-Entropy (H_inf)"] = round(H_inf, 6)

               # Remove legacy entropy field to avoid duplicate/confusing lines in the PDF
                metrics.pop("Estimate Shannon Entropy", None)
                metrics.pop("Estimated Shannon Entropy", None)

                # === END NEW METRICS ===

        class PDF(FPDF):
            def header(self):
                self.set_font("Arial", "B", 14)
                self.cell(0, 10, "BB84 Metrics Report", ln=True, align="C")

            def chapter_body(self, content_dict):
                self.set_font("Arial", "", 11)
                for key, value in content_dict.items():
                    self.cell(0, 10, f"{key}: {value}", ln=True)

        pdf = PDF()
        pdf.add_page()
        pdf.chapter_body(metrics)

        save_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if save_path:
            pdf.output(save_path)
            messagebox.showinfo("Saved", f"PDF report saved to: {save_path}")

def main():
    import tkinter as tk
    root = tk.Tk()
    app = BB84App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
