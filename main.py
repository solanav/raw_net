import socket
import netifaces

class Forge():
    def __init__(self, interface):
        self.interface = interface

        self.packet = bytearray()

        # Ethernet
        self.src_mac = bytearray(6)
        self.dst_mac = bytearray(6)
        self._type   = b'\x08\x00'

        # IPv4 default values
        self.version = 0b01000000 # Version 4
        self.pro     = b'\x06' # TCP Protocol
        self.ihl     = 0b00000101 # always 20 for now

        # IPv4 calculated values
        self.length  = b'\x00\x14' # Lenght
        self.check   = b'\x00\x00' # Checksum
        self.src     = bytearray() # Source IP

        # IPv4 user settings
        self.dscp    = 0 # Best effort
        self.ecn     = 0 # No ecn
        self._id     = bytearray(2) # ID
        self.flags   = 0 # Fragmentation
        self.foff    = 0 # Fragment Offset
        self.ttl     = 0 # Max time to live (255)
        self.dst     = bytearray(4) # Destination IP

        # TCP default values
        self.src_port = b'\xd0\x62' # 53346
        self.dst_port = b'\x00\x50' # 80
        self.seqnum   = b'\x00\x00\x00\x00'
        self.acknum   = b'\x00\x00\x00\x00' 
        self.dataoff  = 0b01010000 # Header size 5
        self.reserved = 0b00000000 # Nop
        self.ns       = 0b00000000 # No experimental things
        self.cwr      = 0b00000000 # Not a response
        self.ece      = 0b00000000 # Idk what ecn is so no
        self.urg      = 0b00000000 # Not urgent?
        self.ack      = 0b00000000 # Not an ack
        self.psh      = 0b00000000 # Don't push?
        self.rst      = 0b00000000 # Don't reset
        self.syn      = 0b00000010 # Send a syn
        self.fin      = 0b00000000 # Not my last packet (hehe) 
        self.win_size = b'\x00\x00'
        self.checksum = b'\x00\x00'
        self.urg_ptr  = b'\x00\x00'

    def __ip_to_hex(self, ip):
        hex_ip = []
        for letter in ip.split('.'):
            hex_ip.append(int(letter))

        return bytearray(hex_ip)

    def __add(self, value):
        if type(value) == bytearray:
            self.packet.extend(value)
        elif type(value) == int:
            self.packet.append(value)
        elif type(value) == bytes:
            self.packet.extend(bytearray(value))
        else:
            print("Error, type not recognized")

    def add_eth(self, src_mac, dst_mac):
        if type(src_mac) != bytes or type(dst_mac) != bytes:
            raise ValueError('Arguments for add_eth must be of type bytearray')

        self.src_mac = bytearray(src_mac)
        self.dst_mac = bytearray(dst_mac)
    
    def add_ipv4(self, dscp, ecn, _id, flags, foff, ttl, dst):
        if type(dscp) != int or dscp >= pow(2, 6):
            raise ValueError('dscp value too high')

        if type(ecn) != int or ecn >= pow(2, 2):
            raise ValueError('ecn value too high')

        if type(_id) != int or _id >= pow(2, 16):
            raise ValueError('_id value too high')

        if type(flags) != int or flags >= pow(2, 3):
            raise ValueError('flags value too high')

        if type(foff) != int or foff >= pow(2, 13):
            raise ValueError('foff value too high')

        if type(ttl) != int or ttl >= pow(2, 8):
            raise ValueError('ttl value too high')

        if type(dst) != str:
            raise ValueError('dst has to be a string')

        # Get local ip
        local_ip = netifaces.ifaddresses('wlp3s0')[2][0]['addr']
        self.src = self.__ip_to_hex(local_ip)

        # Get user values
        self.dscp  = dscp
        self.ecn   = ecn
        self._id   = _id.to_bytes(2, byteorder='big')
        self.flags = flags
        self.foff  = foff
        self.ttl   = ttl
        self.dst   = self.__ip_to_hex(dst)

    def generate_eth(self):
        header = bytearray()
        self.__add(self.dst_mac)
        self.__add(self.src_mac)
        self.__add(self._type)

        return header

    def generate_ipv4(self):
        header = bytearray()
        self.__add(self.version | self.ihl)
        self.__add(self.dscp & 0x11111100 | self.ecn & 0x11)
        self.__add(self.length)
        self.__add(self._id)
        self.__add(self.flags >> 8 | self.foff >> 8) # parte de arriba de la palabra
        self.__add(self.flags & 0b11111111 | self.foff & 0b11111111) # parte de abajo
        self.__add(self.ttl)
        self.__add(self.pro)
        self.__add(self.check)
        self.__add(self.src)
        self.__add(self.dst)

        return header

    def generate_syn(self):
        header = bytearray()

        self.__add(self.src_port)
        self.__add(self.dst_port)
        self.__add(self.seqnum)
        self.__add(self.acknum)
        self.__add(self.dataoff | self.reserved | self.ns)
        self.__add(self.cwr | self.ece | self.urg | self.ack | self.psh | self.rst | self.syn | self.fin)
        self.__add(self.win_size)
        self.__add(self.checksum)
        self.__add(self.urg_ptr)

        return header

    def generate(self):
        self.__add(self.generate_eth())
        self.__add(self.generate_ipv4())
        self.__add(self.generate_syn())

        return self.packet

    def __str__(self):
        _str = []
        for i in self.generate():
            _str.append('{:02X}'.format(i))
        
        return ' '.join(_str)

def main():
    interface = 'wlp3s0'

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((interface, 0))

    # Forge packet
    f = Forge(interface)
    f.add_eth(b'\x6c\x88\x14\xc3\x47\x44', b'\xb4\x0c\x25\xe0\x40\x11')
    f.add_ipv4(0, 0, 0, 0b010, 0, 255, "1.1.1.1")
    packet = f.generate()

    s.send(packet)

    print(f)

    s.close()

if __name__ == '__main__':
    main()