import socket

import protocol_pb2
import update_image

HOST = '127.0.0.1'
PORT = 8080

# Connect to server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# Send an UpdateCheck message
uc = protocol_pb2.UpdateCheck()
uc.ID = 12345
uc.V = 1235
s.send(uc.SerializeToString())

print('Sent: UpdateCheck(ID={0}, V={1})'.format(uc.ID, uc.V))

### For GU

# Parse M1 and OrgChallenge response from GU
data = s.recv(512)

m1 = protocol_pb2.M1()
m1.ParseFromString(data)
oc = protocol_pb2.OrgChallenge()
oc.ParseFromString(m1.OC)

print('Received from GU: M1(V={0}, OrgChallenge(NG={1}, IG={2}))'.format(m1.V, oc.NG, oc.IG))

# Send to GU a M2 containing a DeviceChallenge
dc = protocol_pb2.DeviceChallenge()
dc.NG = oc.NG
dc.ND = 9999999 # Device challenge nonce
dc.ID = 12345

m2 = protocol_pb2.M2()
m2.DC = dc.SerializeToString()
s.send(m2.SerializeToString())

print('Sent to GU: M2(DeviceChallenge(NG={0}, ND={1}, ID={2}))'.format(dc.NG, dc.ND, dc.ID))

# Receive M3 containing an UpdatingOrgResponse from GU
data = s.recv(512)

m3 = protocol_pb2.M3()
m3.ParseFromString(data)
ur = protocol_pb2.OrgResponse()
ur.ParseFromString(m3.OR)

print('Received from GU: M3(UpdatingOrgResponse(ND={0}, IG={1}))'.format(ur.ND, ur.IG))

# Receive UpdateImage containing size of update
data = s.recv(512)
ui = protocol_pb2.UpdateImage()
ui.ParseFromString(data)

print('Received from GU: UpdateImage(size={0})'.format(ui.size))
s.send(b'OK')

# Receive the update image
image = b''

# Keep reading until update receive
while len(image) < ui.size:
    image += s.recv(4096)

print('Received image!')
s.send(b'OK')

### Now for GC

# Parse M1 and OrgChallenge response from GC
data = s.recv(512)

m1 = protocol_pb2.M1()
m1.ParseFromString(data)
oc = protocol_pb2.OrgChallenge()
oc.ParseFromString(m1.OC)

print('Received from GC: M1(V={0}, OrgChallenge(NG={1}, IG={2}))'.format(m1.V, oc.NG, oc.IG))

# Send to GC a M2 containing a DeviceChallenge
dc = protocol_pb2.DeviceChallenge()
dc.NG = oc.NG
dc.ND = 9999999 # Device challenge nonce
dc.ID = 12345

m2 = protocol_pb2.M2()
m2.DC = dc.SerializeToString()
s.send(m2.SerializeToString())

print('Sent to GC: M2(DeviceChallenge(NG={0}, ND={1}, ID={2}))'.format(dc.NG, dc.ND, dc.ID))

# Receive M3 containing an ConfirmingOrgResponse from GC
data = s.recv(512)

m3 = protocol_pb2.M3()
m3.ParseFromString(data)
ur = protocol_pb2.OrgResponse()
ur.ParseFromString(m3.OR)

print('Received from GC: M3(ConfirmingOrgResponse(ND={0}, IG={1}, HC={2}))'.format(ur.ND, ur.IG, ur.HC))

s.close()
