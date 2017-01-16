#!/usr/bin/python2
# FIT VUT
# Projekt ISA - 2016/2017
# Autor: Marian Orszagh

import sys
import string
import socket
import pcapy
import fcntl
from struct import unpack
from pcapy import *
from datetime import datetime
from datetime import timedelta
import time
import curses
import threading
import csv
import array

# Zoznamy pre adresy
address_list = []
network_list = []
# Interval zapisu do suboru
interval = 0
# Indikator, ze mam ukoncit vlakna
exit = 0

# Zamoke pre vlakna
lock = threading.RLock()

# Kontrola, ci je dana adresa adresou siete
def is_network_valid(prefix, mask):
    address_octets = prefix.split(".")
    tmp = ""

    # Vytvorenie stringu masky
    for i in range(mask):
        tmp += "1"
    while len(tmp) < 32:
        tmp += "0"

    a3 = int(address_octets[2])
    a4 = int(address_octets[3])

    m3 = int(tmp[16:-8], 2)
    m4 = int(tmp[-8:], 2)

    # Porovnanie masky a adresy
    if ((~m3 & a3) or (~m4 & a4)):
        print("ERROR - Given address is not an address of a network")
        sys.exit(1)

# Funkcia, ktora kontroluje, ci adresa patri do danej podsiete
def check_range(prefix, mask, address):
    pre_octets = prefix.split(".")
    add_octets = address.split(".")

    pre_octets = [str('{0:08b}'.format(int(i))) for i in pre_octets]
    pre_binary = ''.join(str(e) for e in pre_octets)

    add_octets = [str('{0:08b}'.format(int(i))) for i in add_octets]
    add_binary = ''.join(str(e) for e in add_octets)

    # Iteracia cez oba stringy a ich porovnavanie, porovnavanie po bitoch
    for i,a,p in zip(range(mask),add_binary,pre_binary):
        if a != p:
            return(False)

    return(True)

# Ziskanie masky zo stringu ip/maska a jej Kontrola
def get_mask(address):
    if len(address.split("/")) != 2:
        print("ERROR - Invalid address format")
        sys.exit(1)

    mask = address.split("/")[1]
    try:
        mask = int(mask)

    except ValueError:
        print("ERROR - Invalid address format")
        sys.exit(1)

    if not ((isinstance(mask, int)) and (16 <= mask < 32)):
        print("ERROR - Invalid mask given")
        sys.exit(1)

    return mask

# Vytiahnutie prefixu a jeho kontrola
def get_prefix(address):
    prefix = address.split("/")[0]
    prefix_ = prefix.split(".")

    if len(prefix_) != 4:
        print("ERROR - Invalid address given")
        sys.exit(1)
    else:
        if not all(0 <= int(i) <= 255 for i in prefix_):
            print("ERROR - Invalid address given")
            sys.exit(1)

    return prefix

# Parsovanie argumentov z prikazoveho riadku
# -> Zoznam adries sieti uklada do globalnej premennej
# -> Ak bol zadany prepinac -i, vrati zoznam zariadeni
def parse_args():
    global network_list
    global interval

    interfaces = False
    iterable = sys.argv
    iterable = iter(iterable[1:])
    for i in iterable:
        # Logging
        if i == '-c':
            if interval != 0:
                print("ERROR - Multiple -c arguments")
                sys.exit(1)

            interval = next(iterable)
            try:
                interval = int(interval)
            except ValueError:
                print("ERROR - Invalid time interval given")
                sys.exit(1)

            if interval < 1:
                print("ERROR - Interval has to be an integer greater than zero")
                sys.exit(1)

        # Vyber interface
        elif i == '-i':
            if interfaces != False:
                print("ERROR - multiple -i arguments")
                sys.exit(1)

            interfaces = next(iterable)
            interfaces = interfaces.split(',')

            if interfaces == []:
                print("ERROR - No interfaces given")
                sys.exit(1)

        # Inac adresa
        elif not i in network_list:
            network_list.append(i)

    if network_list == []:
        print("ERROR - No addresses given")
        sys.exit(1)

    # Kontrola validity adries
    for n in network_list:
        is_network_valid(get_prefix(n),get_mask(n))

    return interfaces

# Funkcia, ktora prejde zoznam adries a ich expire casov a tie, ktorym vyprsal,
# zo zoznamu odstrani
def check_expiration():
    global address_list
    rem_addr = []
    for a in address_list:
        # Pripad, ze bola adresa ziskana cez inform
        if a[1] == -1:
            continue
        elif a[1] < datetime.now():
            rem_addr.append(a[0])

    address_list = [a for a in address_list if a[0] not in rem_addr]

# Vypis zoznamu cez curses, pripadne zapis do suboru
def print_table(stdscr, writer):
    global network_list
    global address_list
    global interval

    seconds_passed = 0
    # Zahlavie v subore
    if interval != 0:
        writer.writerow(('Date','Network address', 'Max hosts','Allocated addresses',
                        'Utilization'))

    while (True):
        stdscr.clear()

        # Kontrola, ci niektorej z adries nevyprsal lease time
        check_expiration()
        statistics = []

        # Hlavicka
        line = ''.join(['IP Prefix'.ljust(24), 'Max hosts'.ljust(24),
                        'Allocated addresses'.ljust(24), 'Utilization'.ljust(24)])
        stdscr.addstr(line + '\n')

        for n in network_list:
            statistics.append([])

            # Max hosts
            max_h = pow(2, 32 - get_mask(n)) - 2

            # Allocated addresses
            sum_ = 0
            for a in address_list:
                if check_range(get_prefix(n), get_mask(n), a[0]):
                    sum_ += 1

            # Utilization
            util = (sum_ / float(max_h)) * 100

            # Zapis do premennej pre zapis do suboru
            statistics[-1].append(n)
            statistics[-1].append(str(max_h))
            statistics[-1].append(str(sum_))
            statistics[-1].append(str(round(util,2)) + '%')

            line = ''.join(word.ljust(24) for word in statistics[-1])
            stdscr.addstr(line + '\n')

        # Zapis do CSV suboru log.csv
        if seconds_passed == interval and interval != 0:
            time_ = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for s in statistics:
                writer.writerow((str(time_),s[0], str(s[1]), str(s[2]), s[3] ))
            seconds_passed = 0

        stdscr.refresh()
        time.sleep(1)
        seconds_passed += 1

# Odstranenie adresy zo zoznamu
def remove_address(add):
    global address_list
    address_list = [a for a in address_list if not a[0] == add]

# Parsovanie paketu
def parse_packet(packet) :
    global address_list

    # Eth header
    eth_len = 14
    eth_h = packet[:eth_len]

    eth = unpack('!6s6sH' , eth_h)
    eth_prot = socket.ntohs(eth[2])

    # IP Protokol
    if eth_prot == 8 :

        # Parsovanie IP headeru
        ip_h = packet[eth_len : 20 + eth_len]
        iph = unpack('!BBHHHBBH4s4s' , ip_h)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        protocol = iph[6]

        # Zaujimaju nas iba UDP pakety
        if protocol == 17 :
            h_len = eth_len + iph_length + 8

            # Vytiahnutie samotnych dat z paketu
            data = packet[h_len:]

            # Kontrola magic cookie
            mck = unpack('!BBBB' , data[236:240])
            if not(int(mck[0]) == int(mck[3]) == 99 and int(mck[1]) == 130 and int(mck[2]) == 83):
                return

            message = 0
            dhcp_option  = 0
            lease_time = 0
            ptr = 240

            while(True):
                if len(data) < ptr:
                    break

                # Kod spravy a jej dlzka
                message = unpack('!B' , data[ptr])[0]
                ln = unpack('!B' , data[ptr + 1])[0]

                # Ak je to message 53, pozriem sa, ci je to ACK, ak nie koncim,
                # ak ano pokracujem, a hladam lease time, v pripade ze este
                # nebol najdeny
                if int(message) == 53:
                    # Ack
                    if int(unpack('!B' , data[ptr + 2])[0]) == 5:
                        dhcp_option = 5
                        ptr += 3

                        # Vytah IP adresy klienta z dat
                        yiaddr = unpack('!BBBB' , data[16:20])
                        yiaddr = '.'.join(str(y) for y in yiaddr)

                        # ACK na INFORM
                        if yiaddr == '0.0.0.0':
                            yiaddr = unpack('!BBBB', data[12:16])
                            if yiaddr not in [a[0] for a in address_list]:
                                address_list.append([yiaddr,-1])
                            return

                    # Release - odstranim adresu zo zoznamu
                    elif int(unpack('!B' , data[ptr + 2])[0]) == 7:
                        ciaddr = unpack('!BBBB', data[12:16])
                        ciaddr = '.'.join(str(d) for d in ciaddr)

                        lock.acquire()
                        remove_address(ciaddr)
                        lock.release()
                        return


                    else:
                        break

                # Ak je message 51 nacitam lease time
                elif message == 51:
                    # Vytiahnutie pozadovanych bytov
                    lease_t_bytes = unpack('!BBBB', data[ptr + 2: ptr + ln + 2])
                    lease_t = ''.join(chr(i) for i in lease_t_bytes)

                    # Ziskanie hodnoty
                    lease_time = int(lease_t.encode('hex'), 16)
                    ptr += ln + 2

                # Inak pokracujem dalej
                else:
                    ptr += ln + 2

                # V pripade, ze boli najdene obe polozky, koncim cyklus
                if dhcp_option != 0 and lease_time != 0:
                    # Vypocitam, kedy sa ma skoncit lease time danej adrese a
                    # vlozim tieto hodnoty do zoznamu
                    expiration_time = datetime.now() + timedelta(seconds=lease_time)
                    tmp = 0

                    for a in address_list:
                        if a[0] == yiaddr:
                            tmp = 1
                    if tmp == 0:
                        # Ulozenie do zoznamu adries
                        lock.acquire()
                        remove_address(yiaddr)
                        address_list.append([yiaddr, expiration_time])
                        lock.release()
                    break

# Loop na zariadeni, na vstupe funkcie je meno zariadenia,
# na ktorom sa ma odpocuvat
def sniff_loop(dev):
    global exit
    try:
        cap = pcapy.open_live(dev, 65536, 0, 0)
    except:
        return

    if cap.datalink() != pcapy.DLT_EN10MB:
        return

    # Filter na porty 67 a 68
    cap.setfilter("portrange 67-68")

    while(True) :
        (header, packet) = cap.next()
        parse_packet(packet)
        if exit != 0:
            return


def main():
    interfaces = parse_args()
    devices = pcapy.findalldevs()

    # Kontrola, ci zadane zariadenia su v pocitaci
    if interfaces != False:
        for i in interfaces:
            if i not in devices and i != '':
                print("ERROR - invalid interface given")
                sys.exit(1)
        devices = interfaces

    # Inicializacia Curses modulu
    stdscr = curses.initscr()

    try:
        # Zapisovac pre CSV
        writer = None
        # Otvorenie suboru
        if interval != 0:
            fp = open('log.csv', "w")
            writer = csv.writer(fp)

        # Spusti sa n vlakien, podla toho, na kolkych rozhraniach nacuvame
        sniff_threads = []
        for d in devices:
            # Nechceme loopback
            if d != 'lo':
                dev = str(d)
                sniff_t = threading.Thread(target = sniff_loop, args = ([dev]))
                sniff_t.daemon = True
                sniff_t.start()
                sniff_threads.append(sniff_t)

        # Loop vypisujuci statistiky na konzolu
        print_table(stdscr,writer)

    except KeyboardInterrupt:
        pass
    finally:
        exit = 1
        if interval != 0:
            fp.close()

        # Vratenie nastaveni Curses
        curses.nocbreak()
        stdscr.keypad(0)
        curses.echo()
        curses.endwin()

if __name__ == "__main__":
    main()
