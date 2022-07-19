""" Rasperi Wireless Connection """
# Author: Utku ISBIR
import sys

from air_ci_pkg.core.wl_client import WlClientConnector

pi_dict = [
    {'name': 'WatPi61', 'ip': '10.30.39.61',
        'user': 'test', 'pw': 'test', 'interface': 'wlan0'},
    {'name': 'WatPi62', 'ip': '10.30.39.62',
        'user': 'test', 'pw': 'test', 'interface': 'wlan0'},
    {'name': 'WatPi63', 'ip': '10.30.39.63',
        'user': 'test', 'pw': 'test', 'interface': 'wlan0'},
    {'name': 'WatPi64', 'ip': '10.30.39.64',
        'user': 'test', 'pw': 'test', 'interface': 'wlan0'},
    {'name': 'WatPi65', 'ip': '10.30.39.65',
        'user': 'test', 'pw': 'test', 'interface': 'wlan0'},
    {'name': 'WatPi66', 'ip': '10.30.39.66',
        'user': 'test', 'pw': 'test', 'interface': 'wlan0'},
    {'name': 'WatPi67', 'ip': '10.30.39.67',
        'user': 'test', 'pw': 'test', 'interface': 'wlan0'},
    {'name': 'WatPi68', 'ip': '10.30.39.68',
        'user': 'test', 'pw': 'test', 'interface': 'wlan0'},
    {'name': 'WatPi69', 'ip': '10.30.39.69',
        'user': 'test', 'pw': 'test', 'interface': 'wlan0'},
    {'name': 'WatPi70', 'ip': '10.30.39.70',
        'user': 'test', 'pw': 'test', 'interface': 'wlan0'},
    {'name': 'WatPi71', 'ip': '10.30.39.71',
        'user': 'test', 'pw': 'test', 'interface': 'wlan0'},
]


def f_connect(ssh_ip, ssh_user, ssh_pass, ssid, password, interface, sec_mode, bssid=""):
    """ Wl Connection """
    print("*** -------------------------- ***")
    wlc_connector = WlClientConnector()
    wlc_connector.ssh_ip = ssh_ip
    wlc_connector.ssh_username = ssh_user
    wlc_connector.ssh_password = ssh_pass
    print("wlc_connector is running on {}".format(wlc_connector.ssh_ip))
    wlc_connector.connect(interface=interface, ssid=ssid, password=password,
                          sec_mode=sec_mode, bssid=bssid, sta_autoconnect=True)
    return True


def f_disconnect(ssh_ip, interface):
    """ Wl Disconnection """
    print("Wireless Client is disconnected.{}".format(ssh_ip))
    wl_client_disconnect(ssh_ip, interface)


def main():
    """ Main Function """
    ssid_or_ip = ""
    wifi_password = ""
    sec_mode = ""
    bssid = ""
    try:
        method = sys.argv[1]
        ssid_or_ip = sys.argv[2]
        wifi_password = sys.argv[3]
        sec_mode = sys.argv[4]
        bssid = sys.argv[5]
    except:
        pass

    if method == "connect":
        ssid = ssid_or_ip
        for _pi in pi_dict:
            f_connect(ssh_ip=_pi['ip'], ssh_user=_pi['user'], ssh_pass=_pi['pw'], ssid=ssid,
                      password=wifi_password, interface=_pi['interface'], sec_mode=sec_mode, bssid=bssid)
    elif method == "disconnect":
        disconnect_ip = ssid_or_ip
        if disconnect_ip == '':
            for _pi in pi_dict:
                f_disconnect(
                    ssh_ip=_pi['ip'], interface=_pi['interface'])
        else:
            for _pi in pi_dict:
                if _pi.get('ip') == disconnect_ip:
                    f_disconnect(
                        ssh_ip=disconnect_ip, interface=_pi.get('interface'))
                    break
            else:
                print("there is no client with this ip")
    else:
        print("Unsupported method: {}".format(method))


if __name__ == "__main__":
    main()
