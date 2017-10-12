import random
import socketserver

import protocol_pb2

from update_image import read_image_header
import rsa512
import rsakeys

# Debug mode: no encryption
DEBUG = True

# Protocol states
IDLE = 1
AUTH = 2
GU_CHALLENGE = 3
GC_CHALLENGE = 4
DONE = 5

# Organization IDs
I_GU = 111
I_GC = 222

# Current version
V = 1234

# Path to update image
IMAGE_PATH = 'output_image.bin'

class ProtocolStateHandler(socketserver.BaseRequestHandler):
    def idle_state(self):
        data = self.request.recv(512)
        
        # Deserialize UpdateCheck message and store current device ID
        try:
            uc = protocol_pb2.UpdateCheck()
            uc.ParseFromString(data)
        except:
            print('Invalid UpdateCheck message received from {0}.'.format(self.client_address))
            return False
        
        self.ID = uc.ID

        # Ignore message if device version is current
        # Stop connection
        if uc.V == V:
            self.request.sendall(b'\xFF')
            return False

        # Number of authentications made
        self.num_auths = 0

        if DEBUG:
            print('- Got UpdateCheck from ID={0}'.format(self.ID))
        
        self.current_state = AUTH

        return True
    
    def auth_state(self):
        # Build OrgChallenge for GU/GC
        oc = protocol_pb2.OrgChallenge()

        if self.num_auths == 0:
            oc.NG = self.N_GU
            oc.IG = I_GU
            self.current_state = GU_CHALLENGE # Next state

            if DEBUG:
                print('- GU sent OrgChallenge(NG={0}, IG={1}) to ID={2}'.format(self.N_GU, I_GU, self.ID))
        elif self.num_auths == 1:
            oc.NG = self.N_GC
            oc.IG = I_GC
            self.current_state = GC_CHALLENGE # Next state

            if DEBUG:
                print('- GC sent OrgChallenge(NG={0}, IG={1}) to ID={2}'.format(self.N_GC, I_GC, self.ID))

        # Build full message including V
        m1 = protocol_pb2.M1()
        m1.V = V

        # Encrypt if not in debug mode
        if not DEBUG:
            m1.OC = self.d_rsa.encrypt(oc.SerializeToString())
        else:
            m1.OC = oc.SerializeToString()

        # Send message back to the device
        self.request.sendall(m1.SerializeToString())

        return True

    def gu_challenge_state(self):
        data = self.request.recv(512)
        
        # In this state, device replies with DeviceChallenge message
        # We first verify it, then send back ND as response
        try:
            m2 = protocol_pb2.M2()
            m2.ParseFromString(data)

            # Decrypt and parse DeviceChallenge message
            if not DEBUG:
                dc_msg = self.gu_rsa.decrypt(m2.DC)
            else:
                dc_msg = m2.DC

            dc = protocol_pb2.DeviceChallenge()
            dc.ParseFromString(dc_msg)
        except:
            print('Invalid M2 message received by G_U from {0}.'.format(self.ID))
            return False
        
        if DEBUG:
            print('- GU received DeviceChallenge(NG={0}, ND={1}, ID={2})'.format(dc.NG, dc.ND, dc.ID))

        # Challenge failed; close socket
        if self.N_GU != dc.NG:
            self.request.sendall(b'\xFF')
            return False
        
        # Authentication successful
        self.num_auths += 1

        # Build OrgResponse message and send it back to client
        ur = protocol_pb2.OrgResponse()
        ur.ND = dc.ND
        ur.IG = I_GU

        m3 = protocol_pb2.M3()

        if not DEBUG:
            m3.OR = self.d_rsa.encrypt(ur.SerializeToString())
        else:
            m3.OR = ur.SerializeToString()

        self.request.sendall(m3.SerializeToString())

        print('- GU sent UpdatingOrgResponse(ND={0}, IG={1}) to ID={2}'.format(ur.ND, ur.IG, self.ID))

        # Next, send the update image
        with open(IMAGE_PATH, 'rb') as f:
            content = f.read()

            # Send the length of the update image first to simplify buffer allocation
            ui = protocol_pb2.UpdateImage()
            ui.size = len(content)
            self.request.sendall(ui.SerializeToString())

            # Wait for OK to continue
            _ = self.request.recv(512)
            
            if not DEBUG:
                self.request.sendall(self.d_rsa.encrypt(content))
            else:
                self.request.sendall(content)

        # Wait for client to confirm
        _ = self.request.recv(512)

        print('- GU sent update image to ID={0}'.format(self.ID))

        # Authenticate GC next
        self.current_state = AUTH

        return True

    def gc_challenge_state(self):
        data = self.request.recv(1024)
        
        # In this state, device replies with DeviceChallenge message
        # We first verify it, then send GC challenge and confirming hash
        try:
            m2 = protocol_pb2.M2()
            m2.ParseFromString(data)

            # Decrypt and parse DeviceChallenge message
            if not DEBUG:
                dc_msg = self.gc_rsa.decrypt(m2.DC)
            else:
                dc_msg = m2.DC

            dc = protocol_pb2.DeviceChallenge()
            dc.ParseFromString(dc_msg)
        except:
            print('Invalid M2 message received by G_C from {0}.'.format(self.ID))
            return False
        
        if DEBUG:
            print('- GC received DeviceChallenge(NG={0}, ND={1}, ID={2})'.format(dc.NG, dc.ND, dc.ID))

        # Challenge failed; close socket
        if self.N_GC != dc.NG:
            self.request.sendall(b'\xFF')
            return False

        self.num_auths += 1

        # Build OrgResponse message and send it back to client
        cr = protocol_pb2.OrgResponse()
        cr.ND = dc.ND
        cr.IG = I_GC

        # Append hash of update image to OrgResponse
        headers = read_image_header(IMAGE_PATH)
        cr.HC = headers[-1]

        m3 = protocol_pb2.M3()

        if not DEBUG:
            m3.OR = self.d_rsa.encrypt(cr.SerializeToString())
        else:
            m3.OR = cr.SerializeToString()

        self.request.sendall(m3.SerializeToString())

        if DEBUG:
            print('- GC sent ConfirmingOrgResponse(ND={0}, IG={1}, HC={2}) to ID={3}'.format(cr.ND, cr.IG, cr.HC, self.ID))

        self.current_state = DONE

        return True

    def handle(self):
        self.current_state = IDLE

        # Challenge nonces for both orgs
        self.N_GU = random.randint(1, 1000000000)
        self.N_GC = random.randint(1, 1000000000)

        # RSA512 objects for each party
        self.d_rsa = rsa512.RSA512(rsakeys.D_PUB, None)
        self.gu_rsa = rsa512.RSA512(rsakeys.GU_PUB, rsakeys.GU_PRV)
        self.gc_rsa = rsa512.RSA512(rsakeys.GC_PUB, rsakeys.GC_PRV)

        running = True

        print('* New session with client: {0}'.format(self.client_address))
        
        while running:
            if self.current_state == IDLE:
                running = self.idle_state()
            elif self.current_state == AUTH:
                running = self.auth_state()
            elif self.current_state == GU_CHALLENGE:
                running = self.gu_challenge_state()
            elif self.current_state == GC_CHALLENGE:
                running = self.gc_challenge_state()
            elif self.current_state == DONE:
                running = False

if __name__ == "__main__":
    HOST, PORT = 'localhost', 8080

    server = socketserver.TCPServer((HOST, PORT), ProtocolStateHandler)
    server.serve_forever()
