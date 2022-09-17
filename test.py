import paramiko

targethost = "192.168.1.1"
user = "uranus"
#user = "root"
password = "butterfly"
#password = "666"
command = "ls -la"
command = "cat user.txt"

sshserver = paramiko.SSHClient()
sshserver.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sshserver.load_system_host_keys()
sshserver.connect(targethost, 22, user, password)

stdin, stdout, sterr = sshserver.exec_command(command)
output = stdout.readlines()

for line in output:
    print(line.replace("\n", ''))