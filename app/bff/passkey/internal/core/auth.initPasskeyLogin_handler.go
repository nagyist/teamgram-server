// Copyright 2025 Teamgram Authors
//  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: teamgramio (teamgram.io@gmail.com)
//

package core

import (
	"github.com/teamgram/proto/mtproto"
)

// AuthInitPasskeyLogin
// auth.initPasskeyLogin#518ad0b7 api_id:int api_hash:string = auth.PasskeyLoginOptions;
func (c *PasskeyCore) AuthInitPasskeyLogin(in *mtproto.TLAuthInitPasskeyLogin) (*mtproto.Auth_PasskeyLoginOptions, error) {
	authKeyId := int64(0)
	if c.MD != nil {
		authKeyId = c.MD.PermAuthKeyId
	}

	challenge, err := RandomChallenge()
	if err != nil {
		c.Logger.Errorf("auth.initPasskeyLogin - challenge: %v", err)
		return nil, mtproto.ErrInternalServerError
	}

	// 登录时使用空 allowCredentials，依赖客户端 resident key 发现
	optionsJSON, err := BuildAssertionOptionsJSON(challenge, "teamgram.me", nil)
	if err != nil {
		c.Logger.Errorf("auth.initPasskeyLogin - options: %v", err)
		return nil, mtproto.ErrInternalServerError
	}

	if err := c.svcCtx.Dao.SetLoginChallenge(c.ctx, authKeyId, string(challenge)); err != nil {
		c.Logger.Errorf("auth.initPasskeyLogin - set challenge: %v", err)
		return nil, mtproto.ErrInternalServerError
	}

	return mtproto.MakeTLAuthPasskeyLoginOptions(&mtproto.Auth_PasskeyLoginOptions{
		Options: mtproto.MakeTLDataJSON(&mtproto.DataJSON{Data: optionsJSON}).To_DataJSON(),
	}).To_Auth_PasskeyLoginOptions(), nil
}
