import protocol_pb2
import socketserver

import update_image

class CustomTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        print("{} wrote:".format(self.client_address[0]))

        # Deserialize updatecheck message
        uc = protocol_pb2.UpdateCheck()
        uc.ParseFromString(self.data)
        print('V={0}, ID={1}'.format(uc.ID, uc.V))

        self.request.sendall('V={0}, ID={1}'.format(uc.ID, uc.V).encode('ascii'))

if __name__ == "__main__":
    HOST, PORT = 'localhost', 8080

    u = update_image.UpdateImage()
    hash = u.build(inputs=['image/a.txt', 'image/b.txt', 'image/c.txt'], output_path='testimage.bin')
    print(hash)

    headers = u.read_header('testimage.bin')
    print(headers)
    print(update_image.convert_binary(headers[-1]))

    # server = socketserver.TCPServer((HOST, PORT), CustomTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    # server.serve_forever()
