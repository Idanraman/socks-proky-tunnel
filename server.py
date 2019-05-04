from __future__ import print_function

from twisted.conch import avatar, recvline
from twisted.conch.interfaces import IConchUser, ISession
from twisted.conch.ssh import factory, keys, session
from twisted.conch.insults import insults
from twisted.cred import portal, checkers
from twisted.web import proxy, http
from twisted.internet.endpoints import clientFromString
from twisted.internet.defer import inlineCallbacks
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.protocols.portforward import ProxyFactory

from zope.interface import implements
from txsocksx.client import SOCKS5ClientEndpoint, SOCKS4ClientEndpoint
import txtorcon
import sys
import paramiko

class ProxyFactory(http.HTTPFactory):
    protocol = proxy.Proxy

class SysUser():
    def __init__(self):
        global portcounter
        self.tunnel_route = []
        self.aps = [ProEntity(1,b'localhost',8080,'example','password')]
        self.allocated_port = 30000 + portcounter
        portcounter+=1

        self.id_val = 10

class ProEntity():
    def __init__(self,pid,ip_address,port,user,password):
        self.pid = pid
        self.ip_address = ip_address
        self.port = port
        self.user = user
        self.password = password

    def __repr__(self):
        #return(b'ID:'+self.pid +b'| IP:'+self.ip_address + b'| PORT:'+self.port)
        return('ID:%d| IP:%s| PORT:%d|USER:%s |PASS:%s\n' %
            (self.pid,self.ip_address,self.port,self.user,self.password))

class SSHDemoProtocol(recvline.HistoricRecvLine):
    def __init__(self, user):
       self.user = user
       self.data = SysUser()

    clist = {
        b'add': b'Add a new proxy to database. format - add [ip_address]:[port]:[user]:[pass]',
        b'remove': b'Removes a proxy from database. format - remove [proxy_id] ',
        b'ctunnel': b'Specifies the current listed. format - ctunnel',
        b'tunnel': b'Allows to set the tunnel to a new route. use - tunnel [tor/proxy_id]:...:[proxy_id]',
        b'list': b'Lists the existing proxy database. format - list',
        b'help': b'lists all commands. format - help',
        None: b" is an unknown command. type 'help' to get command list"
    }

    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.terminal.write(b'Hey %s. This is setup interface for the proxy. type help to view available commands\n' % (self.user.username))
        self.terminal.nextLine()

    def lineReceived(self, line):
        command = line.split(b' ', 1)[0]
        if command in self.clist:
            try:
                if command == b'add':
                    self.add_p(line)
                if command == b'remove':
                    self.remove(line)
                if command == b'ctunnel':
                    self.ctunnel(line)
                if command == b'tunnel':
                    self.tunnel(line)
                if command == b'list':
                    self.list(line)
                if command == b'help':
                    self.help(line)
            except:
                self.terminal.write(b"An error has accourd during the handling of your command. try again")
            #    self.terminal.nextLine()
        elif command == b'':
            pass
        else:
            self.terminal.write(command + self.clist[None])
            self.terminal.nextLine()


    def add_p(self,line):
        try:
            indata = line.split(b' ', 1)[1]
            ip_address = indata.split(b':')[0]
            port = int(indata.split(b':')[1])
            user = indata.split(b':')[2]
            password = indata.split(b':')[3]
        except:
            self.terminal.write(b"command was incorrect - either port/ip/user/pass were wrong, or format was wrong")
            self.terminal.nextLine()
            return()

        self.data.aps.append(ProEntity(self.data.id_val,ip_address,port,user,password))
        self.terminal.write(b"proxy was added with id %d" % (self.data.id_val))
        self.terminal.nextLine()
        self.data.id_val+=1

    def remove(self,line):
        indata = line.split(b' ', 1)
        if len(indata) != 2:
            self.terminal.write(b"An incorrect amount of arguments has been specified")
            self.terminal.nextLine()
            return()
        try:
            pro_id = int(indata[1])
        except:
            self.terminal.write(indata[1] + b" isn't a recognized proxy server id in the system. try 'list'.")
            self.terminal.nextLine()
            return()

        for pro in self.data.aps:
            if pro.pid == pro_id:
                self.data.aps.remove(pro)
                return()

        self.terminal.write(indata[1] + b" isn't a recognized proxy server id in the system. try 'list'.")
        self.terminal.nextLine()
        return()

    def ctunnel(self,line):
        self.terminal.write(str.encode(str(self.data.tunnel_route)))
        self.terminal.nextLine()

    def tunnel(self,line):
        add_tor = False
        self.data.tunnel_route = []

        id_arr = line.split(b' ', 1)
        if len(id_arr) != 2:
            self.terminal.write(b"An incorrect amount of arguments has been specified")
            self.terminal.nextLine()
            return()
        id_arr = id_arr[1].split(b':')

        if id_arr[0] == b'tor':
            add_tor = True
            id_arr = id_arr[1:]

        for pro_id in id_arr:
            pro_id = int(pro_id)
            for pro in self.data.aps:
                if pro.pid == pro_id:
                    self.data.tunnel_route.append(pro)

        if len(id_arr)>len(self.data.tunnel_route):
            self.terminal.write(b"An unknown proxy ID has been specified")
            self.terminal.nextLine()
            self.data.tunnel_route = []
            return()

        self.terminal.write(b"Tunnel is being created")
        self.terminal.nextLine()

        logport,logip = self.do_connections(self.data.tunnel_route,self.data.allocated_port, add_tor)
        #self.alter_do_connections(self.data.tunnel_route,self.data.allocated_port, add_tor)

        self.terminal.write(b"Tunnel is done! you can access it through port %s on ip %s" %(logport,logip))
        self.terminal.nextLine()
    
    @inlineCallbacks
    def alter_do_connections(self,tunnel_route,port,torused):
        linking_list = [None]*(len(tunnel_route)+1)

        for idx in range(len(linking_list)):
            if idx==0:
                if torused:
                    linking_list[idx] = clientFromString(reactor, "unix:/var/run/tor/control")
                else:
                    linking_list[idx] = TCP4ClientEndpoint(reactor, '127.0.0.1', 8080)

            else:
                proxy_data = tunnel_route[idx-1]
                linking_list[idx] = SOCKS5ClientEndpoint( proxy_data.ip_address, proxy_data.port, linking_list[idx-1], methods={'login': (str(proxy_data.user), str(proxy_data.password))})
                #SOCKS4ClientEndpoint(proxy_data.ip_address, proxy_data.port, linking_list[idx-1])
 
        if torused:
            tor = yield txtorcon.connect(reactor,linking_list[-1:][0])
            config = yield tor.get_config()
            config.SOCKSPort = [str(port)]
            yield config.save()

        else:
            linking_list[-1:][0].connect(ProxyFactory('127.0.0.1',port))


    def do_connections(self,tunnel_route,port,torused):
        '''
        ssh -D 55557 -L 55556:127.0.0.1:55556 -L 55555:127.0.0.1:55555 user1@host1.domain-one.tld -t
        ssh -D 55556 -L 55555:127.0.0.1:55555 user2@host2.domain-two.tld -t
        ssh -D 55555 user3@host3.domain-three.tld
        '''
        logip = tunnel_route[0].ip_address
        ssh1 = paramiko.SSHClient()
        ssh1.load_system_host_keys()
        ssh1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh1.connect(tunnel_route[0].ip_address,
            username=tunnel_route[0].user,
            password=tunnel_route[0].password)

        tunnel_route[1:]
        #creating the command text
        sshd = 'ssh -D'
        links = len(tunnel_route)
        command_list = [None]*links
        beginstring = str(port)
        for idx in range(links):
            proxy_data = tunnel_route[links-idx-1]
            command_list[links-idx-1] = '%s %s %s@%s' %(
                sshd,beginstring,proxy_data.user,proxy_data.ip_address)

            beginstring = '%d -L %d:127.0.0.1:%s' % (port+1,port,beginstring)
            port+=1
        tunnel_cmd = " -t ".join(command_list)

        #send the command
        channel = ssh1.get_transport().open_session()
        try :
            (ssh_stdin, ssh_stdout, ssh_stderr) =  channel.exec_command(tunnel_cmd) 
            for prox in tunnel_route:
                (ssh_stdin, ssh_stdout, ssh_stderr) =  channel.exec_command(prox.password) 
        except paramiko.SSHException as sshEx:
            print (sshEx)
        except Exception  as e :
            print (e)

        return(str(port),logip)

    def list(self,line):
        self.terminal.write(str.encode(str(self.data.aps)))
        self.terminal.nextLine()

    def help(self,line):
        for command in self.clist:
            if command is not None:
                self.terminal.write(command + b' : ' + self.clist[command])
                self.terminal.nextLine()

class SSHDemoAvatar(avatar.ConchUser):
    implements(ISession)
 
    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({'session': session.SSHSession})
 
    def openShell(self, protocol):
        serverProtocol = insults.ServerProtocol(SSHDemoProtocol, self)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))
 
    def getPty(self, terminal, windowSize, attrs):
        return None
 
    def execCommand(self, protocol, cmd):
        raise NotImplementedError()
 
    def closed(self):
        pass

    def __repr__(self):
        return(self.username)
 
class SSHDemoRealm(object):
    implements(portal.IRealm)
     
    def requestAvatar(self, avatarId, mind, *interfaces):
        if IConchUser in interfaces:
            return interfaces[0], SSHDemoAvatar(avatarId), lambda: None
        else:
            raise NotImplementedError("No supported interfaces found.")


def getRSAKeys():
    with open('/home/idan/.ssh/id_rsa') as privateBlobFile:
        privateBlob = privateBlobFile.read()
        privateKey = keys.Key.fromString(data=privateBlob)
 
 
    with open('/home/idan/.ssh/id_rsa.pub') as publicBlobFile:
        publicBlob = publicBlobFile.read()
        publicKey = keys.Key.fromString(data=publicBlob)
        
    return publicKey, privateKey
 
class ProxFactory(factory.SSHFactory):
    portal = portal.Portal(SSHDemoRealm())

portcounter = 1
users = {'admin': 'aaa', 'guest': 'bbb'}

sshFactory = ProxFactory()
sshFactory.portal.registerChecker(
    checkers.InMemoryUsernamePasswordDatabaseDontUse(**users))
pubKey, privKey = getRSAKeys()
sshFactory.publicKeys = {'ssh-rsa': pubKey}
sshFactory.privateKeys = {'ssh-rsa': privKey}
reactor.listenTCP(22222, sshFactory)
reactor.run()