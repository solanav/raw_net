import socket
import netifaces

class Forge():
    def __init__(self, interface):
        self.interface = interface

        self.p_eth = bytearray(14) # Ethernet header
        self.p_ipv4 = bytearray(20) # IPv4 header

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
        self.src     = socket.gethostbyname(socket.gethostname()) # Source IP

        # IPv4 user settings
        self.dscp    = 0 # Best effort
        self.ecn     = 0 # No ecn
        self._id     = 0 # ID
        self.flags   = 0 # Fragmentation
        self.foff    = 0 # Fragment Offset
        self.ttl     = 0 # Max time to live (255)
        self.dst     = bytearray(4) # Destination IP

    def __ip_to_hex(self, ip):
        hex_ip = []
        for letter in ip.split('.'):
            hex_ip.append(int(letter))

        return bytearray(hex_ip)

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

        self.dscp  = dscp
        self.ecn   = ecn
        self._id   = _id
        self.flags = flags
        self.foff  = foff
        self.ttl   = ttl
        self.dst   = self.__ip_to_hex(dst)

    def generate(self):
        # Get local ip
        local_ip = netifaces.ifaddresses('wlp3s0')[2][0]['addr']
        self.src = self.__ip_to_hex(local_ip)
        return "nothing yet"

    def __str__(self):
        return "nothing yet"

ip_p = {
    'ihl':     0b00000101, # 20 bytes
    'dscp':    0b00000000, # Best effort
    'ecn':     0b00000000, # No ecn
    'length':  b'\x00\x14', # Lenght
    'id':      b'\x00\x00', # ID
    'flags':   0b0100000000000000, # Fragmentation
    'foff':    0b0000000000000000, # Fragment Offset
    'ttl':     b'\xff', # Max time to live (255)
    'pro':     b'\x06', # TCP Protocol
    'check':   b'\x00\x00', # Checksum
    'src':     b'\xac\x11\x02\xec', # Source IP
    'dst':     b'\x01\x01\x01\x01' # Destination IP
}

# bytes([ip_p['version'] | ip_p['ihl']])
# bytes([ip_p['dscp'] & 0x11111100 | ip_p['ecn'] & 0x11])
# bytes([(ip_p['flags'] >> 8 | ip_p['foff'] >> 8), (ip_p['flags'] & 0b11111111 | ip_p['foff'] & 0b11111111)])

def main():
    interface = 'wlp3s0'

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((interface, 0))

    # Forge packet
    f = Forge(interface)
    f.add_eth(b'\x6c\x88\x14\xc3\x47\x44', b'\xb4\x0c\x25\xe0\x40\x11')
    f.add_ipv4(0, 0, 0, 0b010, 0, 255, "1.1.1.1")
    packet = f.generate()

    s.close()

if __name__ == "__main__":
    main()