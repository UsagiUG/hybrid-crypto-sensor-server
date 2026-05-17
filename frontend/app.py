from nicegui import ui
import requests

def get_server_public_key():

# sensor data is made manually
def get_sensor_data():

def generate_aes_key():

def get_aes_key():

def generate_iv():

def aes_encrypt():

def json():

def rsa_encrypt():

def send_sensor_data():
    try:
        server_public_key = get_server_public_key()
    except Exception as e:
        ui.notify('Error: Tidak bisa terhubung ke /public-key', type='negative')
        return
    
    try:
        aes_key = get_aes_key()
    except Exception as e:
        generate_aes_key()
        aes_key = get_aes_key()

    iv = generate_iv()

    try:
        sensor_data = get_sensor_data()
    except Exception as e:
        ui.notify('Error: Tidak ada data sensor', type='negative')
        return

    ciphertext = aes_encrypt(aes_key=aes_key, iv=iv, data=sensor_data)

    data_to_send = json(encrypted_key=rsa_encrypt(aes_key), iv=iv, ciphertext=ciphertext)

    try:
        url='http://localhost:3000/api/telemetry' 
        response=requests.post(url, json=data_to_send)
        if response.status_code==200:
            data=response.json()
            return()
    except Exception as e:


# Tampilan Aplikasi (NiceGUI)
ui.label('Generator Kunci (NiceGUI + Node.js)').classes('text-h5 m-4')
ui.button('Generate New Keys', on_click=kirim_data).classes('bg-blue-500 text-white m-4')

# Tempat untuk menampilkan teks hasil generate key nanti
hasil_box = ui.label('').classes('m-4 text-grey-8 font-mono break-all')

ui.run()