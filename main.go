package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func parseCmdArgs() (proxy string, local string, remote string) {
	flag.StringVar(&proxy, "proxy", "", "socks5(ip:port),user:passwd@socks5(ip:port),socks4(ip:port),username@socks4(ip:port),sslsocks5(ip:port)")
	flag.StringVar(&remote, "remote", "", "ip:port or ssl(ip:port)")
	flag.StringVar(&local, "local", "", "ip:port")
	flag.Parse()
	if len(remote) == 0 || len(local) == 0 {
		flag.Usage()
		os.Exit(0)
	}
	return
}

func parseIP(ipaddr string) (string, uint16, error) {
	ipport := strings.Split(ipaddr, ":")
	if len(ipport) != 2 {
		return "", 0, fmt.Errorf("%s is not ip:port format", ipaddr)
	}
	ip := net.ParseIP(ipport[0])
	if ip == nil || ip.To4() == nil {
		return "", 0, fmt.Errorf("%s invalid ipv4 address", ipaddr)
	}
	port, err := strconv.ParseUint(ipport[1], 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("%s invalid port", ipaddr)
	}
	return ip.String(), uint16(port), nil
}

type ProxyInfo struct {
	Type     string
	SSL      bool
	IP       string
	Port     uint16
	Username string
	Password string
	Raw      string
}

type RemoteInfo struct {
	SSL  bool
	IP   string
	Port uint16
}

func parseSingleProxy(rawStr string) (*ProxyInfo, error) {
	pinfo := new(ProxyInfo)
	pinfo.Raw = rawStr
	ipaddr := rawStr
	index := strings.LastIndex(rawStr, "@")
	if index != -1 {
		ipaddr = rawStr[index+1:]
		userpass := rawStr[0:index]
		index := strings.LastIndex(userpass, ":")
		if index == -1 {
			pinfo.Username = userpass
		} else {
			pinfo.Username = userpass[0:index]
			pinfo.Password = userpass[index+1:]
		}
	}
	if strings.HasPrefix(ipaddr, "socks4(") {
		pinfo.Type = "socks4"
		pinfo.SSL = false
	} else if strings.HasPrefix(ipaddr, "socks5(") {
		pinfo.Type = "socks5"
		pinfo.SSL = false
	} else if strings.HasPrefix(ipaddr, "sslsocks4(") {
		pinfo.Type = "socks4"
		pinfo.SSL = true
	} else if strings.HasPrefix(ipaddr, "sslsocks5(") {
		pinfo.Type = "socks5"
		pinfo.SSL = true
	} else {
		return nil, fmt.Errorf("%s format invalid(just support socks5,socks4,sslsocks5,sslsocks4)", rawStr)
	}
	endIndex := strings.Index(ipaddr, ")")
	if endIndex == -1 {
		return nil, fmt.Errorf("%s format invalid, not found )", rawStr)
	}
	begIndex := strings.Index(ipaddr, "(")
	ipaddr = ipaddr[begIndex+1 : endIndex]
	ip, port, err := parseIP(ipaddr)
	if err != nil {
		return nil, err
	}
	pinfo.IP = ip
	pinfo.Port = port
	return pinfo, nil
}

func parseProxyChain(proxy string) ([]ProxyInfo, error) {
	var ret []ProxyInfo
	if len(proxy) == 0 {
		return ret, nil
	}
	strVec := strings.Split(proxy, ",")
	for _, v := range strVec {
		tmp := strings.TrimSpace(v)
		if len(tmp) == 0 {
			continue
		}
		pinfo, err := parseSingleProxy(tmp)
		if err != nil {
			return nil, err
		}
		ret = append(ret, *pinfo)
	}
	return ret, nil
}

func parseRemote(remote string) (*RemoteInfo, error) {
	pinfo := new(RemoteInfo)
	remote = strings.TrimSpace(remote)
	if strings.HasPrefix(remote, "ssl(") {
		if !strings.HasSuffix(remote, ")") {
			return nil, fmt.Errorf("%s invalid format", remote)
		}
		pinfo.SSL = true
		remote = remote[4 : len(remote)-1]
	}
	ip, port, err := parseIP(remote)
	if err != nil {
		return nil, err
	}
	pinfo.IP = ip
	pinfo.Port = port
	return pinfo, nil
}

func main() {
	proxy, local, remote := parseCmdArgs()
	premote, err := parseRemote(remote)
	if err != nil {
		fmt.Printf("parse remote fail:%s\n", err)
		return
	}
	pproxy, err := parseProxyChain(proxy)
	if err != nil {
		fmt.Printf("parse proxy chain fail:%s\n", err)
		return
	}
	listener, err := net.Listen("tcp4", local)
	if err != nil {
		fmt.Printf("listen fail:%s\n", err)
		return
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("accept fail:%s\n", err)
			continue
		}
		go newConnect(conn, pproxy, premote)
	}
}

func socks4(conn *net.Conn, pinfo *ProxyInfo, dstIP string, dstPort uint16, dstSSL bool) error {
	var connect bytes.Buffer
	connect.WriteByte(4)
	connect.WriteByte(1)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(dstPort))
	connect.Write(portBytes[:])
	ip := net.ParseIP(dstIP).To4()
	connect.Write(ip)
	if len(pinfo.Username) != 0 {
		connect.WriteString(pinfo.Username)
	}
	connect.WriteByte(0)
	if err := TcpWrite(*conn, connect.Bytes()); err != nil {
		return err
	}
	(*conn).SetReadDeadline(time.Now().Add(8 * time.Second))
	var connectRsp [8]byte
	if _, err := io.ReadFull((*conn), connectRsp[:]); err != nil {
		return fmt.Errorf("read %s connect rsp fail: %s", pinfo.Raw, err)
	}
	(*conn).SetReadDeadline(time.Time{})
	if connectRsp[0] != 0 {
		return fmt.Errorf("%s connect response invalid", pinfo.Raw)
	}
	if connectRsp[1] != 90 {
		return fmt.Errorf("%s connect reponse code %d", pinfo.Raw, connectRsp[1])
	}
	if !dstSSL {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conf := tls.Config{
		InsecureSkipVerify: true,
	}
	newConn := tls.Client(*conn, &conf)
	if err := newConn.HandshakeContext(ctx); err != nil {
		return err
	}
	AddCert(dstIP, dstPort, calcSha256(newConn.ConnectionState().PeerCertificates[0].Raw))
	(*conn) = newConn
	return nil
}

func socks5(conn *net.Conn, pinfo *ProxyInfo, dstIP string, dstPort uint16, dstSSL bool) error {
	var auth bytes.Buffer
	auth.WriteByte(5)
	if len(pinfo.Username) != 0 || len(pinfo.Password) != 0 {
		auth.WriteByte(2)
		auth.WriteByte(0)
		auth.WriteByte(2)
	} else {
		auth.WriteByte(1)
		auth.WriteByte(0)
	}
	if err := TcpWrite(*conn, auth.Bytes()); err != nil {
		return err
	}
	(*conn).SetReadDeadline(time.Now().Add(10 * time.Second))
	var authRsp [2]byte
	if _, err := io.ReadFull((*conn), authRsp[:]); err != nil {
		return fmt.Errorf("read %s auth rsp fail: %s", pinfo.Raw, err)
	}
	if authRsp[0] != 5 {
		return fmt.Errorf("%s auth response invalid", pinfo.Raw)
	}
	if authRsp[1] != 0 && authRsp[1] != 2 {
		return fmt.Errorf("%s auth reponse method code %d", pinfo.Raw, authRsp[1])
	}
	if authRsp[1] == 2 {
		var loginReq bytes.Buffer
		loginReq.WriteByte(1)
		userLen := byte(len(pinfo.Username))
		loginReq.WriteByte(userLen)
		loginReq.WriteString(pinfo.Username[0:userLen])
		passLen := byte(len(pinfo.Password))
		loginReq.WriteByte(passLen)
		loginReq.WriteString(pinfo.Password[0:passLen])
		if err := TcpWrite(*conn, loginReq.Bytes()); err != nil {
			return err
		}
		var loginRsp [2]byte
		if _, err := io.ReadFull((*conn), loginRsp[:]); err != nil {
			return fmt.Errorf("read %s login rsp fail: %s", pinfo.Raw, err)
		}
		if loginRsp[0] != 1 {
			return fmt.Errorf("%s login response invalid", pinfo.Raw)
		}
		if loginRsp[1] != 0 {
			return fmt.Errorf("%s login reponse code %d", pinfo.Raw, loginRsp[1])
		}
	}
	var connect bytes.Buffer
	connect.WriteByte(5)
	connect.WriteByte(1)
	connect.WriteByte(0)
	connect.WriteByte(1)
	ip := net.ParseIP(dstIP).To4()
	connect.Write(ip)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(dstPort))
	connect.Write(portBytes[:])
	if err := TcpWrite(*conn, connect.Bytes()); err != nil {
		return err
	}
	var connectRsp [10]byte
	if _, err := io.ReadFull((*conn), connectRsp[:]); err != nil {
		return fmt.Errorf("read %s connect rsp fail: %s", pinfo.Raw, err)
	}
	(*conn).SetReadDeadline(time.Time{})
	if connectRsp[0] != 5 || connectRsp[2] != 0 || connectRsp[3] != 1 {
		return fmt.Errorf("%s connect response invalid", pinfo.Raw)
	}
	if connectRsp[1] != 0 {
		return fmt.Errorf("%s connect reponse code %d", pinfo.Raw, connectRsp[1])
	}
	if !dstSSL {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conf := tls.Config{
		InsecureSkipVerify: true,
	}
	newConn := tls.Client(*conn, &conf)
	if err := newConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("tls handshake with %s:%d fail: %s", dstIP, dstPort, err)
	}
	AddCert(dstIP, dstPort, calcSha256(newConn.ConnectionState().PeerCertificates[0].Raw))
	(*conn) = newConn
	return nil
}

func socks(conn *net.Conn, pinfo *ProxyInfo, dstIP string, dstPort uint16, dstSSL bool) error {
	if pinfo.Type == "socks4" {
		return socks4(conn, pinfo, dstIP, dstPort, dstSSL)
	} else {
		return socks5(conn, pinfo, dstIP, dstPort, dstSSL)
	}
}

func proxyConn(infos []ProxyInfo, remote *RemoteInfo) (net.Conn, error) {
	if len(infos) == 0 {
		return TcpConnect(remote.IP, remote.Port, remote.SSL, 8*time.Second)
	}
	conn, err := TcpConnect(infos[0].IP, infos[0].Port, infos[0].SSL, 8*time.Second)
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(infos); i++ {
		if err := socks(&conn, &(infos[i-1]), infos[i].IP, infos[i].Port, infos[i].SSL); err != nil {
			conn.Close()
			return nil, err
		}
	}
	plast := &(infos[len(infos)-1])
	if err := socks(&conn, plast, remote.IP, remote.Port, remote.SSL); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func newConnect(from net.Conn, infos []ProxyInfo, remote *RemoteInfo) {
	defer from.Close()
	to, err := proxyConn(infos, remote)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	defer to.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buffer := make([]byte, 2048)
		for {
			from.SetReadDeadline(time.Now().Add(60 * time.Second))
			len, err := from.Read(buffer)
			if err != nil {
				from.Close()
				to.Close()
				return
			}
			err = TcpWrite(to, buffer[0:len])
			if err != nil {
				from.Close()
				to.Close()
				return
			}
		}
	}()
	go func() {
		wg.Done()
		buffer := make([]byte, 2048)
		for {
			to.SetReadDeadline(time.Now().Add(60 * time.Second))
			len, err := to.Read(buffer)
			if err != nil {
				from.Close()
				to.Close()
				return
			}
			err = TcpWrite(from, buffer[0:len])
			if err != nil {
				from.Close()
				to.Close()
				return
			}
		}
	}()
	wg.Wait()
}

func TcpWrite(conn net.Conn, data []byte) error {
	writeBytes := 0
	for writeBytes < len(data) {
		n, err := conn.Write(data[writeBytes:])
		if err != nil {
			return err
		}
		writeBytes += n
	}
	return nil
}

func TcpDialTimeoutWithSSL(ipStr string, port uint16, timeout time.Duration) (net.Conn, error) {
	address := fmt.Sprintf("%s:%d", ipStr, port)
	conf := tls.Config{
		InsecureSkipVerify: true,
	}
	pdial := new(net.Dialer)
	pdial.Timeout = timeout
	conn, err := tls.DialWithDialer(pdial, "tcp4", address, &conf)
	if err != nil {
		return nil, err
	}
	AddCert(ipStr, port, calcSha256(conn.ConnectionState().PeerCertificates[0].Raw))
	return conn, nil
}

func TcpConnect(ipStr string, port uint16, ssl bool, timeout time.Duration) (net.Conn, error) {
	if ssl {
		return TcpDialTimeoutWithSSL(ipStr, port, timeout)
	}
	return net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", ipStr, port), timeout)
}

func calcSha256(data []byte) string {
	tmp := sha256.Sum256(data)
	return hex.EncodeToString(tmp[:])
}
