from tkinter import *
from tkinter import messagebox
import base64
import os

def decrypt():
    password = code.get()

    if password == "Risi":
        screen = Toplevel()
        screen.title("Decryption")
        screen.geometry("400x200")

        message = text.get(1.0, END)
        decode_message = base64.b64decode(message)
        decrypt = decode_message.decode("ascii")

        Label(screen, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10, y=10)
        text_dec = Text(screen, font="Robote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text_dec.place(x=10, y=40, width=380, height=150)

        text_dec.insert(END, decrypt)
    else:
        messagebox.showerror("Decryption", "Invalid Password")

def encrypt():
    password = code.get()

    if password == "Risi":
        screen = Toplevel()
        screen.title("Encryption")
        screen.geometry("400x200")

        message = text.get(1.0, END)
        encode_message = message.encode("ascii")
        base64_bytes = base64.b64encode(encode_message)
        encrypt = base64_bytes.decode("ascii")

        Label(screen, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=10)
        text_enc = Text(screen, font="Robote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text_enc.place(x=10, y=40, width=380, height=150)

        text_enc.insert(END, encrypt)
    else:
        messagebox.showerror("Encryption", "Invalid Password")

def Tool_screen():
    global screen, text, code
    screen = Tk()
    screen.geometry("375x398")
    screen.title("Hide App")

    Label(text="Enter text for encryption and decryption", fg="black", font=("calibri", 13)).place(x=10, y=10)
    text = Text(screen, font="Robote 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text.place(x=10, y=50, width=355, height=100)

    Label(text="Enter secret key for encryption and decryption", fg="black", font=("calibri", 13)).place(x=10, y=170)
    code = StringVar()
    Entry(screen, textvariable=code, width=19, bd=0, font=("arial", 25), show="*").place(x=10, y=200)

    Button(screen, text="ENCRYPT", height=2, width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=250)
    Button(screen, text="DECRYPT", height=2, width=23, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=200, y=250)
    Button(screen, text="RESET", height=2, width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=300)

    screen.mainloop()

def reset():
    code.set("")
    text.delete(1.0, END)

Tool_screen()
