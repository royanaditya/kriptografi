import streamlit as st
import mysql.connector
from mysql.connector import Error
import os
from PIL import Image, UnidentifiedImageError
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
import base64
import numpy as np
import io
import tempfile

# Custom CSS styling
st.set_page_config(
    page_title="Sistem Pengaduan",
    page_icon="🔐",
    layout="wide"
)
# Define custom CSS
custom_css = """
<style>
    /* Main container styling */
    .main {
        padding: 2rem;
        background-color: #274472;  /* Latar belakang biru dongker */
    }

    /* Seluruh body aplikasi */
    body {
        background-color: #274472; /* Latar belakang biru dongker untuk seluruh aplikasi */
        margin: 0;
        padding: 0;
    }

    /* Header styling */
    .stApp h1 {
        color: #ffffff;  /* Putih */
        font-size: 2.5rem;
        text-align: center;
        padding: 1rem;
        margin-bottom: 2rem;
        border-bottom: 3px solid #17a2b8;
    }

    .stApp h2 {
        color: #ffffff;  /* Putih */
        font-size: 1.8rem;
        margin-top: 1.5rem;
    }

    /* Form styling */
    .stTextInput > div > div {
        background-color: #ffffff !important;
        padding: 0.5rem;
        border-radius: 5px;
        border: 1px solid #333333 !important;
    }

    .stTextInput input {
        color: #000000 !important;
    }

    .stTextArea > div > div {
        background-color: #ffffff !important;
        padding: 0.5rem;
        border-radius: 5px;
        border: 1px solid #333333 !important;
    }

    .stTextArea textarea {
        color: #000000 !important;
    }

    /* Button styling */
    .stButton > button {
        background-color: #4299e1;
        color: white;
        border: none;
        border-radius: 5px;
        padding: 0.5rem 2rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }

    .stButton > button:hover {
        background-color: #2b6cb0;
        box-shadow: 0 4px 6px rgba(50, 50, 93, 0.11);
    }

    /* Sidebar styling */
    .css-1d391kg {
        background-color: #1e3a5f;  /* Sidebar biru dongker lebih gelap */
    }

    /* Success/Error message styling */
    .success-msg {
        background-color: #48bb78;
        color: white;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }

    .error-msg {
        background-color: #f56565;
        color: white;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
</style>
"""
# Inject custom CSS
st.markdown(custom_css, unsafe_allow_html=True)

# Key untuk enkripsi/dekripsi
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

UPLOAD_FOLDER = "uploaded_data"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Subfolders
IMAGE_FOLDER = os.path.join(UPLOAD_FOLDER, "images")
FILE_FOLDER = os.path.join(UPLOAD_FOLDER, "files")
os.makedirs(IMAGE_FOLDER, exist_ok=True)
os.makedirs(FILE_FOLDER, exist_ok=True)

# Session state initialization
if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = False
if 'user_data' not in st.session_state:
    st.session_state.user_data = None
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Login"

# Database connection helper
def create_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",  # Sesuaikan dengan username Anda
            password="",  # Sesuaikan dengan password Anda
            database="pengaduan"  # Pastikan nama database benar
        )
        if connection.is_connected():
            return connection
    except Error as e:
        st.error(f"Gagal terhubung ke database: {e}")
    return None


# Hashing and encryption helpers
def hash_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

def encrypt_vigenere(plain_text, key):
    key = key.upper()
    encrypted_text = ""
    key_index = 0
    for char in plain_text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
            key_index += 1
        else:
            encrypted_text += char
    return encrypted_text

def decrypt_vigenere(cipher_text, key):
    key = key.upper()
    decrypted_text = ""
    key_index = 0
    for char in cipher_text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            decrypted_text += chr((ord(char) - shift_base - shift) % 26 + shift_base)
            key_index += 1
        else:
            decrypted_text += char
    return decrypted_text

def encrypt_aes(text, key):
    # Convert key to bytes and ensure it's 32 bytes (256 bits)
    key = pad(key.encode(), AES.block_size)[:32]
    
    # Generate a random 16-byte IV
    iv = get_random_bytes(16)
    
    # Create cipher object and encrypt the data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Convert text to bytes and pad
    raw = pad(text.encode(), AES.block_size)
    
    # Encrypt and combine IV and encrypted text
    encrypted_data = iv + cipher.encrypt(raw)
    
    # Convert to base64 for safe storage
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_aes(encrypted_text, key):
    try:
        # Convert key to bytes and ensure it's 32 bytes
        key = pad(key.encode(), AES.block_size)[:32]
        
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_text)
        
        # Extract IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Create cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt and unpad
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None

def super_encrypt(text, vigenere_key, aes_key):
    # First encrypt with Vigenere
    vigenere_encrypted = encrypt_vigenere(text, vigenere_key)
    # Then encrypt with AES
    return encrypt_aes(vigenere_encrypted, aes_key)

def super_decrypt(encrypted_text, vigenere_key, aes_key):
    try:
        # First decrypt with AES
        aes_decrypted = decrypt_aes(encrypted_text, aes_key)
        if aes_decrypted is None:
            return "Error in decryption"
        # Then decrypt with Vigenere
        return decrypt_vigenere(aes_decrypted, vigenere_key)
    except Exception as e:
        return f"Decryption error: {str(e)}"


# Fungsi helper untuk handle image display
def display_image_from_data(image_data):
    try:

        if isinstance(image_data, bytes):
            st.write("Image data valid.")
        else:
            st.error("Image data is not valid bytes.")

    except Exception as e:
        st.error(f"Error displaying image: {e}")
def display_image_temp(image_data):
    try:
        if isinstance(image_data, bytes):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_file:
                tmp_file.write(image_data)
                tmp_file.seek(0)
                image = Image.open(tmp_file.name)
                st.image(image, use_column_width=True)
        else:
            st.warning("Data gambar tidak valid.")
    except Exception as e:
        st.error(f"Error displaying image: {e}")

# Fungsi helper untuk handle file display
def display_file_download(file_data, file_name, file_type):
    try:
        # Handle different file types
        mime_types = {
            'pdf': 'application/pdf',
            'txt': 'text/plain',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }
        
        file_extension = file_name.split('.')[-1].lower()
        mime_type = mime_types.get(file_extension, 'application/octet-stream')
        
        st.download_button(
            label=f"Download {file_name}",
            data=file_data,
            file_name=file_name,
            mime=mime_type
        )
    except Exception as e:
        st.error(f"Error creating download button: {e}")

# Validasi dan tampilkan gambar
def validate_and_display_image(image_path, caption):
    try:
        if isinstance(image_path, bytes):  # Jika gambar dalam bentuk binary data
            image = Image.open(io.BytesIO(image_path))
            st.image(image, caption=caption)
        elif os.path.exists(image_path):  # Jika gambar berupa path
            image = Image.open(image_path)
            st.image(image, caption=caption)
        else:
            st.warning("File gambar tidak ditemukan atau format tidak valid.")
    except Exception as e:
        st.warning(f"Error saat memuat gambar: {e}")

def validate_uploaded_image(uploaded_file):
    try:
        with Image.open(uploaded_file) as img:
            return True
    except UnidentifiedImageError:
        st.warning("File yang diunggah bukan gambar yang valid.")
        return False
# Menyisipkan pesan ke dalam gambar menggunakan LSB
# Menyisipkan pesan ke dalam gambar menggunakan LSB
def embed_message(image, message):
    """
    Menyisipkan pesan ke dalam gambar menggunakan metode LSB dengan penanganan yang lebih baik.
    """
    # Konversi gambar ke RGB jika dalam mode lain
    if image.mode != 'RGB':
        image = image.convert('RGB')
    
    # Tambahkan penanda akhir pesan
    message += "####"  # Penanda akhir pesan
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    message_len = len(binary_message)

    # Load gambar sebagai array numpy
    image_array = np.array(image)
    
    # Periksa apakah gambar cukup besar untuk pesan
    if message_len > image_array.size:
        raise ValueError("Pesan terlalu panjang untuk gambar ini")

    # Ubah array menjadi 1D untuk memudahkan manipulasi
    flat_image = image_array.reshape(-1)
    
    # Sisipkan bit pesan
    for i in range(message_len):
        bit = int(binary_message[i])
        # Pastikan nilai pixel tetap dalam rentang valid (0-255)
        flat_image[i] = (flat_image[i] & 0xFE) | bit
    
    # Kembalikan ke bentuk array asli
    modified_image = flat_image.reshape(image_array.shape)
    
    return Image.fromarray(modified_image)

def extract_message(image):
    """
    Membaca pesan yang disisipkan dari gambar dengan metode LSB yang lebih robust.
    """
    # Konversi gambar ke RGB jika dalam mode lain
    if image.mode != 'RGB':
        image = image.convert('RGB')
    
    # Load gambar sebagai array numpy
    image_array = np.array(image)
    flat_image = image_array.reshape(-1)
    
    # Ekstrak bit LSB
    binary_message = ''
    for i in range(len(flat_image)):
        binary_message += str(flat_image[i] & 1)
        
        # Cek setiap 8 bit untuk karakter
        if len(binary_message) >= 8:
            # Konversi setiap 8 bit ke karakter
            char_binary = binary_message[-(8):]  # Ambil 8 bit terakhir
            try:
                char = chr(int(char_binary, 2))
                # Cek apakah kita menemukan penanda akhir
                if len(binary_message) >= 32 and binary_message[-32:].endswith(''.join(format(ord(c), '08b') for c in "####")):
                    # Hapus penanda akhir dan kembalikan pesan
                    full_message = ''
                    for j in range(0, len(binary_message) - 32, 8):
                        full_message += chr(int(binary_message[j:j+8], 2))
                    return full_message
            except ValueError:
                continue
            
    return None

def steganography_page():
    st.title("Menu Steganografi Gambar")
    action = st.selectbox("Pilih Aksi", ["Sisipkan Pesan", "Baca Pesan"])

    if action == "Sisipkan Pesan":
        uploaded_image = st.file_uploader("Upload Gambar", type=["png", "jpg"])
        secret_message = st.text_input("Pesan Rahasia")

        if st.button("Sisipkan Pesan"):
            if uploaded_image is None:
                st.warning("Harap unggah gambar terlebih dahulu.")
                return
            if not secret_message:
                st.warning("Harap masukkan pesan rahasia.")
                return
                
            try:
                # Buka dan proses gambar
                image = Image.open(uploaded_image)
                
                # Hitung ukuran maksimum pesan yang dapat disisipkan
                max_bytes = (image.size[0] * image.size[1] * 3) // 8
                if len(secret_message) + len("####") > max_bytes:
                    st.error(f"Pesan terlalu panjang. Maksimum karakter yang dapat disisipkan: {max_bytes - len('####')}")
                    return
                
                # Sisipkan pesan
                new_image = embed_message(image, secret_message)
                
                # Simpan gambar ke buffer
                buffer = io.BytesIO()
                new_image.save(buffer, format="PNG")
                image_data = buffer.getvalue()
                
                # Tampilkan gambar hasil
                st.image(new_image, caption="Gambar dengan pesan tersembunyi")
                st.success("Pesan berhasil disisipkan ke dalam gambar.")
                
                # Tombol unduh
                st.download_button(
                    label="Unduh Gambar Steganografi",
                    data=image_data,
                    file_name="stego_image.png",
                    mime="image/png"
                )
                
                # Simpan ke database
                save_steganography_data(uploaded_image.name, image_data, secret_message)
                
            except Exception as e:
                st.error(f"Terjadi kesalahan: {str(e)}")

    elif action == "Baca Pesan":
        uploaded_image = st.file_uploader("Upload Gambar Steganografi", type=["png", "jpg"])
        
        if st.button("Baca Pesan"):
            if uploaded_image is None:
                st.warning("Harap unggah gambar terlebih dahulu.")
                return
                
            try:
                image = Image.open(uploaded_image)
                extracted_message = extract_message(image)
                
                if extracted_message:
                    st.success("Pesan berhasil diekstrak!")
                    st.info(f"Pesan yang ditemukan: {extracted_message}")
                else:
                    st.warning("Tidak ditemukan pesan tersembunyi dalam gambar ini.")
                    
            except Exception as e:
                st.error(f"Terjadi kesalahan saat membaca pesan: {str(e)}")

# Fungsi untuk mengambil file dari database
def fetch_file_from_db(file_id):
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT bukti_file FROM aduan WHERE id_laporan = %s", (file_id,))
            result = cursor.fetchone()
            if result:
                return result[0]  # Mengembalikan data terenkripsi
        except Error as e:
            st.error(f"Terjadi kesalahan saat mengambil file dari database: {e}")
        finally:
            cursor.close()
            connection.close()
    return None

def encrypt_file(file_data):
    return fernet.encrypt(file_data)

def decrypt_file(encrypted_data):
    return fernet.decrypt(encrypted_data)

# Fungsi untuk halaman login
def login_page():
    st.title("Login")
    with st.form(key='login_form'):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            user = login_user(username, password)
            if user:
                st.session_state.is_logged_in = True
                st.session_state.user_data = user
                st.session_state.current_page = "Enkripsi Dekripsi"
                st.rerun()  # Rerun the app to update the page
            else:
                st.error("Username atau password salah!")
    # Navigasi ke halaman register
    if st.button("Belum punya akun? Register"):
        st.session_state.current_page = "Register"
        
# Fungsi untuk login
def login_user(username, password):
    password_hashed = hash_password_md5(password)
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT * FROM user WHERE username = %s AND password = %s", (username, password_hashed))
            user = cursor.fetchone()
            if user:
                st.session_state.is_logged_in = True
                st.session_state.user_data = user  # Simpan seluruh data user ke session
                return user
        except Error as e:
            st.error(f"Terjadi kesalahan: {e}")
        finally:
            cursor.close()
            connection.close()
    return None

# Fungsi untuk register user baru
def register_user(nama, username, email, password):
    password_hashed = hash_password_md5(password)
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT * FROM user WHERE username = %s OR email = %s", (username, email))
            user = cursor.fetchone()
            if user:
                return False

            cursor.execute("INSERT INTO user (nama, username, email, password) VALUES (%s, %s, %s, %s)",
                           (nama, username, email, password_hashed))
            connection.commit()
            return True
        except Error as e:
            st.error(f"Terjadi kesalahan: {e}")
        finally:
            cursor.close()
            connection.close()
    return False

# Fungsi untuk halaman register
def register_page():
    st.markdown("""
        <div style='text-align: center; padding: 2rem;'>
            <h1>📝 Registrasi Akun Baru</h1>
        </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.markdown("<div class='form-card'>", unsafe_allow_html=True)
        with st.form(key='register_form'):
            st.markdown("<h2 style='text-align: center; color: #2c5282;'>Register</h2>", unsafe_allow_html=True)
            nama = st.text_input("Nama Lengkap")
            username = st.text_input("Username")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submit_button = st.form_submit_button("Register")
            if submit_button:
                if register_user(nama, username, email, password):
                    st.success("Registrasi berhasil! Silakan login.")
                    st.session_state.current_page = "Login"
                    st.rerun()
                else:
                    st.error("Username atau email sudah digunakan.")
        
        if st.button("Sudah punya akun? Login"):
            st.session_state.current_page = "Login"
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

def encryption_decryption_page():
    st.markdown("""
        <div style='text-align: center; padding: 1rem;'>
            <h1>🔒 Enkripsi dan Dekripsi</h1>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<div class='form-card'>", unsafe_allow_html=True)
    with st.form(key='encryption_decryption_form'):
        col1, col2 = st.columns(2)
        with col1:
            judul_pengaduan = st.text_input("Judul Pengaduan")
            vigenere_key = st.text_input("Kunci Vigenere")
        with col2:
            kronologi = st.text_area("Kronologi Pengaduan")
            aes_key = st.text_input("Kunci AES")
        
        action = st.selectbox("Pilih Aksi", ["Enkripsi", "Dekripsi"])
        submit_button = st.form_submit_button("Proses")
        
        if submit_button:
            id_pelapor = st.session_state.get("user_data")[0]
            if action == "Enkripsi":
                encrypted_judul = super_encrypt(judul_pengaduan, vigenere_key, aes_key)
                encrypted_kronologi = super_encrypt(kronologi, vigenere_key, aes_key)
                st.success(f"Judul terenkripsi: {encrypted_judul}")
                st.success(f"Kronologi terenkripsi: {encrypted_kronologi}")
                save_aduan(id_pelapor, encrypted_judul, encrypted_kronologi, vigenere_key, aes_key)
            else:
                decrypted_judul = super_decrypt(judul_pengaduan, vigenere_key, aes_key)
                decrypted_kronologi = super_decrypt(kronologi, vigenere_key, aes_key)
                st.success(f"Judul terdekripsi: {decrypted_judul}")
                st.success(f"Kronologi terdekripsi: {decrypted_kronologi}")
    st.markdown("</div>", unsafe_allow_html=True)

def steganography_page():
    st.title("Menu Steganografi Gambar")
    action = st.selectbox("Pilih Aksi", ["Sisipkan Pesan", "Baca Pesan"])

    if action == "Sisipkan Pesan":
        uploaded_image = st.file_uploader("Upload Gambar", type=["png", "jpg"])
        secret_message = st.text_input("Pesan Rahasia")

        if st.button("Sisipkan Pesan"):
            if uploaded_image and secret_message:
                try:
                    image = Image.open(uploaded_image)
                    new_image = embed_message(image, secret_message)

                    # Simpan gambar ke buffer
                    buffer = io.BytesIO()
                    new_image.save(buffer, format="PNG")
                    image_data = buffer.getvalue()

                    # Tampilkan gambar yang sudah disisipkan
                    st.image(new_image, caption="Gambar dengan pesan rahasia")
                    st.success("Pesan berhasil disisipkan.")

                    # Simpan ke database
                    save_steganography_data(uploaded_image.name, image_data, secret_message)

                    # Tombol unduh
                    st.download_button(
                        label="Unduh Gambar Steganografi",
                        data=image_data,
                        file_name="stego_image.png",
                        mime="image/png"
                    )
                except Exception as e:
                    st.error(f"Error: {e}")
            else:
                st.warning("Harap unggah gambar dan masukkan pesan rahasia.")

    elif action == "Baca Pesan":
        uploaded_image = st.file_uploader("Upload Gambar", type=["png", "jpg"])
        if st.button("Baca Pesan"):
            if uploaded_image:
                try:
                    image = Image.open(uploaded_image)
                    extracted_message = extract_message(image)
                    if extracted_message:
                        st.success(f"Pesan yang disisipkan: {extracted_message}")
                    else:
                        st.warning("Tidak ada pesan yang ditemukan di gambar ini.")
                except Exception as e:
                    st.error(f"Error: {e}")
            else:
                st.warning("Harap unggah gambar untuk membaca pesan.")

def save_steganography_data(image_name, image_data, secret_message):
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO steganography_data (image_name, image_data, secret_message)
                VALUES (%s, %s, %s)
                """,
                (image_name, image_data, secret_message)
            )
            connection.commit()
            st.success("Data steganografi berhasil disimpan ke database.")
        except Error as e:
            st.error(f"Kesalahan saat menyimpan ke database: {e}")
        finally:
            cursor.close()
            connection.close()

def file_encryption_decryption_page():
    st.title("Menu Enkripsi dan Dekripsi File")
    
    # Ambil id_pelapor dari session state
    if not st.session_state.get("is_logged_in"):
        st.error("Anda harus login untuk mengakses fitur ini.")
        return

    id_pelapor = st.session_state.get("user_data")[0]  # Ambil ID pengguna dari data login

    key_option = st.radio("Pilih opsi kunci:", ["Generate kunci baru", "Gunakan kunci yang ada"])
    
    if key_option == "Generate kunci baru":
        if st.button("Generate Kunci"):
            new_key = Fernet.generate_key()
            st.code(new_key.decode(), language="text")
            st.info("Simpan kunci ini dengan aman! Anda akan membutuhkannya untuk mendekripsi file.")
    
    key_input = st.text_input("Masukkan Kunci Fernet (Base64)", 
                             help="Masukkan kunci yang digunakan untuk enkripsi/dekripsi")
    action = st.selectbox("Pilih Aksi", ["Enkripsi File", "Dekripsi File"])
    uploaded_file = st.file_uploader("Upload File")
    
    if st.button("Proses"):
        if not key_input:
            st.error("Harap masukkan kunci terlebih dahulu!")
            return
        if not uploaded_file:
            st.warning("Harap unggah file.")
            return
        
        try:
            key_bytes = key_input.encode()
            fernet = Fernet(key_bytes)
            
            file_data = uploaded_file.read()
            file_name = uploaded_file.name

            if action == "Enkripsi File":
                encrypted_data = fernet.encrypt(file_data)
                save_file_data(id_pelapor, file_name, encrypted_data)
                st.success("File berhasil dienkripsi dan disimpan.")
                st.download_button("Unduh File Terenkripsi", 
                                   data=encrypted_data, 
                                   file_name=f"{file_name}.encrypted")
            else:  # Dekripsi
                decrypted_data = fernet.decrypt(file_data)
                decrypted_file_name = file_name.replace('.encrypted', '') 
                st.success("File berhasil didekripsi.")
                st.download_button("Unduh File Terdekripsi", 
                                   data=decrypted_data, 
                                   file_name=decrypted_file_name)
        except Exception as e:
            st.error(f"Terjadi kesalahan: {str(e)}")

def save_aduan(id_pelapor, judul_pengaduan, kronologi, vigenere_key, aes_key):
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO aduan (id_pelapor, judul_pengaduan, kronologi, vigenere_key, aes_key)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (id_pelapor, judul_pengaduan, kronologi, vigenere_key, aes_key)
            )
            connection.commit()
            st.success("Aduan berhasil disimpan.")
        except Error as e:
            st.error(f"Kesalahan menyimpan aduan: {e}")
        finally:
            cursor.close()
            connection.close()

            
def save_file_data(id_pelapor, original_file_name, encrypted_data):
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO files (id_pelapor, file_name, encrypted_data)
                VALUES (%s, %s, %s)
                """,
                (id_pelapor, original_file_name, encrypted_data)
            )
            connection.commit()
            st.success("File berhasil disimpan ke database.")
        except Error as e:
            st.error(f"Error menyimpan file: {e}")
        finally:
            cursor.close()
            connection.close()

def fetch_aduan(id_pelapor):
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                SELECT judul_pengaduan, kronologi FROM aduan WHERE id_pelapor = %s
                """,
                (id_pelapor,)
            )
            results = cursor.fetchall()
            return results
        except Error as e:
            st.error(f"Kesalahan mengambil data aduan: {e}")
        finally:
            cursor.close()
            connection.close()
    return []



# Fungsi untuk logout
def logout():
    st.session_state.is_logged_in = False
    st.session_state.user_data = None
    st.session_state.current_page = "Login"

# Fungsi utama
def main():
    # Initialize session state
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "Login"
    if 'is_logged_in' not in st.session_state:
        st.session_state.is_logged_in = False
    
    # Show sidebar navigation only if logged in
    if st.session_state.is_logged_in:
        with st.sidebar:
            st.markdown("""
                <div style='text-align: center; padding: 1rem;'>
                    <h2 style='color: white;'>Menu Navigasi</h2>
                </div>
            """, unsafe_allow_html=True)
            if st.button("📊 Enkripsi Dekripsi"):
                st.session_state.current_page = "Enkripsi Dekripsi"
            if st.button("🖼️ Steganografi"):
                st.session_state.current_page = "Steganografi"
            if st.button("📁 Enkripsi File"):
                st.session_state.current_page = "Enkripsi File"
            if st.button("🚪 Logout"):
                logout()
                st.rerun()

    # Page routing
    if not st.session_state.is_logged_in:
        if st.session_state.current_page == "Register":
            register_page()
        else:
            login_page()
    else:
        if st.session_state.current_page == "Enkripsi Dekripsi":
            encryption_decryption_page()
        elif st.session_state.current_page == "Steganografi":
            steganography_page()
        elif st.session_state.current_page == "Enkripsi File":
            file_encryption_decryption_page()
        else:
            encryption_decryption_page()  # Default to encryption page if no valid page is selected

if __name__ == "__main__":
    main()