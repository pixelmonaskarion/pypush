from tkinter import *
import tkinter as tk
from tkinter import ttk
root = Tk()
frm = ttk.Frame(root, padding=10)
root.geometry('600x400')

import json
import logging
from base64 import b64decode, b64encode

from rich.logging import RichHandler

import apns
import ids
import imessage

logging.basicConfig(
    level=logging.NOTSET, format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)

# Set sane log levels
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("jelly").setLevel(logging.INFO)
logging.getLogger("nac").setLevel(logging.INFO)
logging.getLogger("apns").setLevel(logging.INFO)
logging.getLogger("albert").setLevel(logging.INFO)
logging.getLogger("ids").setLevel(logging.DEBUG)
logging.getLogger("bags").setLevel(logging.INFO)
logging.getLogger("imessage").setLevel(logging.DEBUG)


def reset_frame(frm):
    for child in frm.winfo_children():
        child.destroy()

# Try and load config.json
try:
    with open("config.json", "r") as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    CONFIG = {}

conn = apns.APNSConnection(
    CONFIG.get("push", {}).get("key"), CONFIG.get("push", {}).get("cert")
)


def safe_b64decode(s):
    try:
        return b64decode(s)
    except:
        return None


conn.connect(token=safe_b64decode(CONFIG.get("push", {}).get("token")))
conn.set_state(1)
conn.filter(["com.apple.madrid"])

user = ids.IDSUser(conn)
im = None
msg_list = None
msg_len = 0

effect_names = [
    "None",
    "Slam",
    "Loud",
    "Gentle",
    "Invisible Ink",
    "Echo",
    "Spotlight",
    "Balloons",
    "Confetti",
    "Heart",
    "Lasers",
    "Fireworks",
    "Celebration",
    "Shooting Star",
]

effect_ids = [
    "",
    "com.apple.MobileSMS.expressivesend.impact",
    "com.apple.MobileSMS.expressivesend.loud",
    "com.apple.MobileSMS.expressivesend.gentle",
    "com.apple.MobileSMS.expressivesend.invisibleink",
    "com.apple.messages.effect.CKEchoEffect",
    "com.apple.messages.effect.CKSpotlightEffect",
    "com.apple.messages.effect.CKHappyBirthdayEffect",
    "com.apple.messages.effect.CKConfettiEffect",
    "com.apple.messages.effect.CKHeartEffect",
    "com.apple.messages.effect.CKLasersEffect",
    "com.apple.messages.effect.CKFireworksEffect",
    "com.apple.messages.effect.CKSparklesEffect",
    "com.apple.messages.effect.CKShootingStarEffect",
]

def get_effect_id(name):
    name_index = effect_names.index(name)
    if name_index != 0:
        return effect_ids[name_index]
    else:
        return None

def send_message(text, send_to, effect):
    im.send(imessage.iMessage(
                text=text,
                participants=[send_to],
                sender=user.current_handle,
                effect=effect,
                # reply_to=current_reply
            ))
def tick():
    global msg_list, msg_len
    msg = im.receive()
    if msg is not None:
        msg_list.insert(msg_len, msg.to_string())
        msg_len += 1

    root.after(100, tick)

def setup():
    global msg_list
    frm.grid()
    send_to_var = tk.StringVar()
    ttk.Label(frm, text="Send To:").grid(column=0, row=0)
    ttk.Entry(frm, textvariable=send_to_var).grid(column=1, row=0)
    msg_var = tk.StringVar()
    ttk.Label(frm, text="Message:").grid(column=0, row=1)
    ttk.Entry(frm, textvariable=msg_var).grid(column=1, row=1)
    chosen_effect_var = StringVar()
    chosen_effect_var.set( effect_names[0] )
    OptionMenu(frm, chosen_effect_var, *effect_names).grid(column=0, row=2)
    button = ttk.Button(frm, text="Send", command=lambda: send_message(msg_var.get(), send_to_var.get(), get_effect_id(chosen_effect_var.get())))
    button.grid(column=1, row=2)
    msg_list = tk.Listbox(frm, width=400, height=300, font=("Arial", 10))
    msg_list.grid(column=2, row=3)
    tick()

def continue_setup():
    reset_frame(frm)
    user.encryption_identity = ids.identity.IDSIdentity(
        encryption_key=CONFIG.get("encryption", {}).get("rsa_key"),
        signing_key=CONFIG.get("encryption", {}).get("ec_key"),
    )

    if (
        CONFIG.get("id", {}).get("cert") is not None
        and user.encryption_identity is not None
    ):
        id_keypair = ids._helpers.KeyPair(CONFIG["id"]["key"], CONFIG["id"]["cert"])
        user.restore_identity(id_keypair)
    else:
        logging.info("Registering new identity...")
        import emulated.nac

        vd = emulated.nac.generate_validation_data()
        vd = b64encode(vd).decode()

        user.register(vd)

    logging.info("Waiting for incoming messages...")

    # Write config.json
    CONFIG["encryption"] = {
        "rsa_key": user.encryption_identity.encryption_key,
        "ec_key": user.encryption_identity.signing_key,
    }
    CONFIG["id"] = {
        "key": user._id_keypair.key,
        "cert": user._id_keypair.cert,
    }
    CONFIG["auth"] = {
        "key": user._auth_keypair.key,
        "cert": user._auth_keypair.cert,
        "user_id": user.user_id,
        "handles": user.handles,
    }
    CONFIG["push"] = {
        "token": b64encode(user.push_connection.token).decode(),
        "key": user.push_connection.private_key,
        "cert": user.push_connection.cert,
    }

    with open("config.json", "w") as f:
        json.dump(CONFIG, f, indent=4)

    global im
    im = imessage.iMessageUser(conn, user)
    setup()

if CONFIG.get("auth", {}).get("cert") is not None:
    auth_keypair = ids._helpers.KeyPair(CONFIG["auth"]["key"], CONFIG["auth"]["cert"])
    user_id = CONFIG["auth"]["user_id"]
    handles = CONFIG["auth"]["handles"]
    user.restore_authentication(auth_keypair, user_id, handles)
    continue_setup()
else:
    username_var=tk.StringVar()
    passw_var=tk.StringVar()
    frm.grid()
    ttk.Label(frm, text="Username: ").grid(column=0, row=0)
    ttk.Entry(frm, textvariable=username_var).grid(column=1, row=0)
    ttk.Label(frm, text="Password: ").grid(column=0, row=1)
    ttk.Entry(frm, textvariable=passw_var, show="*").grid(column=1, row=1)
    def get_2fa():
        tfa_var=tk.StringVar()
        ttk.Label(frm, text="2FA Code: ").grid(column=0, row=2)
        ttk.Entry(frm, textvariable=tfa_var).grid(column=1, row=2)
        waiting = tk.IntVar()
        button = ttk.Button(frm, text="Continue", command=lambda: waiting.set(1))
        button.grid(column=0, row=3)
        button.wait_variable(waiting)
        return tfa_var.get()
    log_in_button = None
    def auth():
        log_in_button.destroy()
        user.authenticate(username_var.get(), passw_var.get(), get_2fa)
        continue_setup()
        
    log_in_button = ttk.Button(frm, text="Log in", command=auth)
    log_in_button.grid(column=0, row=2)


root.mainloop()
