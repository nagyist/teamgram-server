/*
 * Created from 'scheme.tl' by 'mtprotoc'
 *
 * Copyright (c) 2021-present,  Teamgram Studio (https://teamgram.io).
 *  All rights reserved.
 *
 * Author: teamgramio (teamgram.io@gmail.com)
 */

package config

import (
	"github.com/zeromicro/go-zero/zrpc"
)

type Config struct {
	zrpc.RpcServerConf
	// MaxProc        int
	KeyFile        string
	KeyFingerprint string
	Server         *TcpServerConfig
	Session        zrpc.RpcClientConf
}

type TcpServerConfig struct {
	Addrs      []string
	Multicore  bool
	SendBuf    int
	ReceiveBuf int
}