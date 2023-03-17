package main

import (
	"fmt"
	"sync"
)

func init() {
	certmgr.contains = make(map[string]string)
}

var certmgr struct {
	mutex    sync.RWMutex
	contains map[string]string
}

func AddCert(ip string, port uint16, sha256 string) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	certmgr.mutex.RLock()
	old, exist := certmgr.contains[addr]
	certmgr.mutex.RUnlock()
	if exist {
		if old == sha256 {
			return
		}
		fmt.Printf("warn %s cert sha256:%s\n", addr, sha256)
		return
	}
	certmgr.mutex.Lock()
	old, exist = certmgr.contains[addr]
	if !exist {
		certmgr.contains[addr] = sha256
	}
	certmgr.mutex.Unlock()
	if !exist {
		fmt.Printf("%s cert sha256:%s\n", addr, sha256)
		return
	}
	if old == sha256 {
		return
	}
	fmt.Printf("warn %s cert sha256:%s\n", addr, sha256)
}
