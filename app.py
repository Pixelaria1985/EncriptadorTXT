import os
import hashlib
import base64
from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
from cryptography.fernet import Fernet

# Función para convertir la contraseña en una clave válida de Fernet
def generar_clave_desde_contraseña(contrasena):
    # Usamos PBKDF2 para generar una clave de 32 bytes
    key = hashlib.pbkdf2_hmac('sha256', contrasena.encode(), b'salt', 100000)
    # Codificamos la clave en base64 para que sea válida para Fernet
    return base64.urlsafe_b64encode(key)

# Encriptar el archivo
def encriptar_archivo(archivo, clave):
    fernet = Fernet(clave)
    with open(archivo, 'rb') as file:
        datos = file.read()
    
    datos_encriptados = fernet.encrypt(datos)
    
    with open(archivo, 'wb') as file:
        file.write(datos_encriptados)

# Desencriptar el archivo
def desencriptar_archivo(archivo, clave):
    fernet = Fernet(clave)
    with open(archivo, 'rb') as file:
        datos = file.read()
    
    datos_desencriptados = fernet.decrypt(datos)
    
    with open(archivo, 'wb') as file:
        file.write(datos_desencriptados)

# Función para verificar la contraseña e inhabilitar las otras opciones si la contraseña es incorrecta
def verificar_contraseña():
    contrasena = entry_contraseña.get()
    
    if contrasena == "admin":  # Contraseña correcta
        messagebox.showinfo("Acceso correcto", "Contraseña correcta, puedes seleccionar un archivo.")
        btn_encriptar.pack(pady=10)
        btn_desencriptar.pack(pady=10)
    else:
        messagebox.showerror("Acceso denegado", "Contraseña incorrecta.")
        btn_encriptar.pack_forget()
        btn_desencriptar.pack_forget()

# Función para abrir el cuadro de diálogo para seleccionar el archivo a encriptar
def abrir_dialogo_encriptar():
    archivo = filedialog.askopenfilename(title="Selecciona un archivo para encriptar", filetypes=[("Archivos de texto", "*.txt")])
    if archivo:
        clave = generar_clave_desde_contraseña(entry_contraseña.get())  # Generamos la clave desde la contraseña
        encriptar_archivo(archivo, clave)
        messagebox.showinfo("Archivo encriptado", f"El archivo {archivo} ha sido encriptado.")
    else:
        messagebox.showwarning("No se seleccionó archivo", "No se ha seleccionado ningún archivo.")

# Función para abrir el cuadro de diálogo para seleccionar el archivo a desencriptar
def abrir_dialogo_desencriptar():
    archivo = filedialog.askopenfilename(title="Selecciona un archivo para desencriptar", filetypes=[("Archivos de texto", "*.txt")])
    if archivo:
        clave = generar_clave_desde_contraseña(entry_contraseña.get())  # Generamos la clave desde la contraseña
        try:
            desencriptar_archivo(archivo, clave)
            messagebox.showinfo("Archivo desencriptado", f"El archivo {archivo} ha sido desencriptado.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo desencriptar el archivo: {str(e)}")
    else:
        messagebox.showwarning("No se seleccionó archivo", "No se ha seleccionado ningún archivo.")

# Configuración de la ventana principal con Tkinter
ventana = Tk()
ventana.title("Protector de Archivos y Carpetas")
ventana.geometry("400x400")

# Definir los widgets primero, antes de usarlos
label_contraseña = Label(ventana, text="Introduce la contraseña:")
label_contraseña.pack(pady=10)

entry_contraseña = Entry(ventana, show="*")
entry_contraseña.pack(pady=10)

btn_entrar = Button(ventana, text="Acceder", command=verificar_contraseña)
btn_entrar.pack(pady=20)

# Botón para encriptar el archivo
btn_encriptar = Button(ventana, text="Encriptar archivo", command=abrir_dialogo_encriptar)
btn_encriptar.pack_forget()  # Lo ocultamos hasta que se ingrese la contraseña

# Botón para desencriptar el archivo
btn_desencriptar = Button(ventana, text="Desencriptar archivo", command=abrir_dialogo_desencriptar)
btn_desencriptar.pack_forget()  # Lo ocultamos hasta que se ingrese la contraseña

ventana.mainloop()
