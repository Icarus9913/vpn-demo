package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/liuyehcf/common-gtools/assert"
	buf "github.com/liuyehcf/common-gtools/buffer"
	"github.com/liuyehcf/vpn-demo/tunnel"
	"github.com/songgao/water"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// tcp tunnel's ip and port

	// peer node IP
	peerIp net.IP
	// peer port
	peerPort int

	// ip in current side
	// tunnel device IP
	tunIp net.IP

	// virtual network
	// tunnel device IP/CIDR
	tunNet *net.IPNet

	// tun interface
	tunIf *water.Interface

	tcpPipe = make(chan []byte)

	fd int
)

var log *zap.Logger

func init() {
	config := zap.NewProductionEncoderConfig()
	config.EncodeTime = zapcore.ISO8601TimeEncoder
	log = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(config), zapcore.AddSync(os.Stdout), zap.NewAtomicLevelAt(zap.DebugLevel)), zap.AddCaller())
}

func main() {
	parseTunIp()
	createTunInterface()
	setRoute()
	createRawSocket()

	go tcpListenerLoop()
	go tcpSendLoop()
	go tunReceiveLoop()

	<-make(chan interface{})
}

func parseTunIp() {
	var err error
	peerIp = net.ParseIP(os.Args[1]).To4() // peer node IP
	assert.AssertNotNil(peerIp, "peerIp invalid")

	peerPort, err = strconv.Atoi(os.Args[2])
	assert.AssertNil(err, "peerPort illegal")

	tunIp, tunNet, err = net.ParseCIDR(os.Args[3]) // tunnel IP/CIDR
	assert.AssertNil(err, "network illegal")
	assert.AssertNotNil(tunIp, "network illegal")
	assert.AssertNotNil(tunNet, "network illegal")
	tunIp = tunIp.To4()

	log.Sugar().Infof("tunIp='%s'", tunIp.String())
}

func createTunInterface() {
	var err error
	tunIf, err = water.New(water.Config{
		DeviceType: water.TUN,
	})
	assert.AssertNil(err, "failed to create tunIf")

	log.Sugar().Infof("Tun Interface Name: %s\n", tunIf.Name())
}

func setRoute() {
	// ip address add 192.169.66.1 dev tun0
	execCommand(fmt.Sprintf("ip address add %s dev %s", tunIp.String(), tunIf.Name()))

	// ip link set dev tun0 up
	execCommand(fmt.Sprintf("ip link set dev %s up", tunIf.Name()))

	// ip route add table main 192.169.66.0/24 dev tun0
	execCommand(fmt.Sprintf("ip route add table main %s dev %s", tunNet.String(), tunIf.Name()))
}

func createRawSocket() {
	// create ip level raw socket
	var err error
	fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	assert.AssertNil(err, "failed to create raw socket")
}

func execCommand(command string) {
	log.Sugar().Infof("exec command '%s'\n", command)

	cmd := exec.Command("/bin/bash", "-c", command)

	err := cmd.Run()
	assert.AssertNil(err, "failed to execute command")

	state := cmd.ProcessState
	assert.AssertTrue(state.Success(), fmt.Sprintf("exec command '%s' failed, code=%d", command, state.ExitCode()))
}

func tunReceiveLoop() {
	buffer := buf.NewByteBuffer(65536)
	packet := make([]byte, 65536)
	for {
		n, err := tunIf.Read(packet)

		assert.AssertNil(err, "failed to read data from tun")

		buffer.Write(packet[:n])
		for {
			frame, err := tunnel.ParseIPFrame(buffer)

			if err != nil {
				log.Info(err.Error())
				buffer.Clean()
				break
			}
			if frame == nil {
				break
			}

			// transfer to peer side
			tcpPipe <- frame.ToBytes()

			log.Info("receive from tun device, send through tunnel " + frame.String())
		}
	}
}

func tcpSendLoop() {
	var err error

	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", peerIp, peerPort))
	assert.AssertNil(err, "failed to parse tcpAddr")

	var conn *net.TCPConn

	log.Info("try to connect peer")

	conn, err = net.DialTCP("tcp", nil, tcpAddr)

	for {
		if err == nil {
			log.Info("connect peer success")
			break
		}

		log.Sugar().Infof("try to reconnect 1s later, addr=%s, err=%v", tcpAddr.String(), err)

		time.Sleep(time.Second)

		conn, err = net.DialTCP("tcp", nil, tcpAddr)
	}

	for bytes := range tcpPipe {
		conn.Write(bytes)
	}
}

func tcpListenerLoop() {
	var err error

	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", "0.0.0.0", peerPort))
	assert.AssertNil(err, "failed to parse tcpAddr")

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	assert.AssertNil(err, "failed to listener")

	log.Sugar().Infof("listener on '%s'\n", tcpAddr.String())
	conn, err := tcpListener.AcceptTCP()
	assert.AssertNil(err, "failed to accept")

	log.Info("accept peer success")

	buffer := buf.NewByteBuffer(65536)
	packet := make([]byte, 65536)

	for {
		n, err := conn.Read(packet)
		assert.AssertNil(err, "failed to read from tcp tunnel")

		buffer.Write(packet[:n])

		for {
			frame, err := tunnel.ParseIPFrame(buffer)
			assert.AssertNil(err, "failed to parse ip package from tcp tunnel")

			if err != nil {
				log.Info(err.Error())
				buffer.Clean()
				break
			}
			if frame == nil {
				break
			}

			log.Info("receive from tunnel, send through raw socket" + frame.String())

			// send ip frame through raw socket
			addr := syscall.SockaddrInet4{
				Addr: tunnel.IPToArray4(frame.Target),
			}
			err = syscall.Sendto(fd, frame.ToBytes(), 0, &addr)
			assert.AssertNil(err, "failed to send data through raw socket")
		}
	}
}
