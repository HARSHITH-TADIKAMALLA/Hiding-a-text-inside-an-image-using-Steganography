import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from cryptography.fernet import Fernet, InvalidToken
import base64

class Steganography:
    def _int_to_bin(self, rgb):
        r, g, b = rgb
        return f'{r:08b}', f'{g:08b}', f'{b:08b}'

    def _bin_to_int(self, rgb):
        r, g, b = rgb
        return int(r, 2), int(g, 2), int(b, 2)

    def _merge_bin(self, rgb, bits):
        r, g, b = self._int_to_bin(rgb)
        combined_bin = r[:-2] + bits[0:2], g[:-2] + bits[2:4], b[:-2] + bits[4:6]
        return self._bin_to_int(combined_bin)

    def _unmerge_bin(self, rgb):
        r, g, b = self._int_to_bin(rgb)
        return r[-2:] + g[-2:] + b[-2:]

    def merge_text(self, image, text, secret_key):
        cipher_suite = Fernet(secret_key)
        encrypted_text = cipher_suite.encrypt(text.encode())
        binary_text = ''.join(f'{byte:08b}' for byte in encrypted_text)

        max_bits = image.size[0] * image.size[1] * 3
        if len(binary_text) > max_bits:
            raise ValueError(f'Too much text to hide in the image. Maximum bits: {max_bits}')

        pixel_map = image.load()
        new_image = image.copy()
        width, height = image.size

        data_index = 0
        for x in range(width):
            for y in range(height):
                if data_index < len(binary_text):
                    rgb = pixel_map[x, y]
                    bits = binary_text[data_index:data_index+6].ljust(6, '0')
                    new_rgb = self._merge_bin(rgb, bits)
                    new_image.putpixel((x, y), new_rgb)
                    data_index += 6

        return new_image

    def unmerge_text(self, image, secret_key):
        pixel_map = image.load()
        width, height = image.size
        binary_text = ''

        for x in range(width):
            for y in range(height):
                rgb = pixel_map[x, y]
                binary_text += self._unmerge_bin(rgb)

        byte_list = [binary_text[i:i+8] for i in range(0, len(binary_text), 8)]
        encrypted_text = bytes([int(byte, 2) for byte in byte_list if byte.strip('0')])
        cipher_suite = Fernet(secret_key)
        decrypted_text = cipher_suite.decrypt(encrypted_text).decode()

        return decrypted_text

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography")
        self.root.geometry("400x400")
        self.root.config(bg="#e0f7fa")

        self.steganography = Steganography()

        self.create_widgets()

    def create_widgets(self):
        # Add an image above the buttons
        self.image_label = tk.Label(self.root, bg="#e0f7fa")
        self.image_label.pack(pady=20)

        # Load and display the image
        self.display_image()

        self.button_frame = tk.Frame(self.root, bg="#e0f7fa")
        self.button_frame.pack(pady=20)

        self.hide_text_button = tk.Button(self.button_frame, text="Hide Text", command=self.hide_text, bg="#00796b", fg="white", width=20)
        self.hide_text_button.pack(side="left", padx=10)

        self.show_hidden_text_button = tk.Button(self.button_frame, text="Show Hidden Text", command=self.show_hidden_text, bg="#00796b", fg="white", width=20)
        self.show_hidden_text_button.pack(side="right", padx=10)

    def display_image(self):
        try:
            image = Image.open("steganography_image.png")  # Replace with your image path
            image = image.resize((100, 100), Image.ANTIALIAS)
            photo = ImageTk.PhotoImage(image)
            self.image_label.config(image=photo)
            self.image_label.image = photo
        except Exception as e:
            pass

    def hide_text(self):
        image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if image_path:
            text = simpledialog.askstring("Input", "Enter the text to hide:")
            if text:
                try:
                    image = Image.open(image_path)
                    key = simpledialog.askstring("Input", "Enter the secret key (8 to 32 characters):")
                    if not (8 <= len(key) <= 32):
                        messagebox.showerror("Error", "Secret key must be between 8 and 32 characters long.")
                        return
                    secret_key = base64.urlsafe_b64encode(key.ljust(32).encode())

                    modified_image = self.steganography.merge_text(image, text, secret_key)
                    output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
                    if output_path:
                        modified_image.save(output_path)
                        messagebox.showinfo("Success", f"Text embedded and saved to {output_path}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))

    def show_hidden_text(self):
        image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if image_path:
            try:
                key = simpledialog.askstring("Input", "Enter the secret key (8 to 32 characters):")
                if not (8 <= len(key) <= 32):
                    messagebox.showerror("Error", "Secret key must be between 8 and 32 characters long.")
                    return
                secret_key = base64.urlsafe_b64encode(key.ljust(32).encode())

                image = Image.open(image_path)
                extracted_text = self.steganography.unmerge_text(image, secret_key)
                messagebox.showinfo("Extracted Text", extracted_text)
            except InvalidToken:
                messagebox.showerror("Error", "Incorrect secret key or no hidden text found.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == '__main__':
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
