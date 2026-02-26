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
	"encoding/json"
	"time"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/bff/passkey/internal/dao"
	userpb "github.com/teamgram/teamgram-server/app/service/biz/user/user"
	"google.golang.org/grpc/status"
)

// AccountRegisterPasskey
// account.registerPasskey#55b41fd6 credential:InputPasskeyCredential = Passkey;
func (c *PasskeyCore) AccountRegisterPasskey(in *mtproto.TLAccountRegisterPasskey) (*mtproto.Passkey, error) {
	if c.MD == nil || c.MD.UserId == 0 {
		c.Logger.Errorf("account.registerPasskey - not logged in")
		return nil, status.Error(mtproto.ErrUnauthorized, "AUTH_KEY_UNREGISTERED")
	}

	cred := in.GetCredential()
	if cred == nil || cred.GetPredicateName() != mtproto.Predicate_inputPasskeyCredentialPublicKey {
		return nil, status.Error(mtproto.ErrBadRequest, "INPUT_CONSTRUCTOR_INVALID")
	}
	credPK := cred.To_InputPasskeyCredentialPublicKey()
	resp := credPK.GetResponse()
	if resp == nil || resp.GetPredicateName() != mtproto.Predicate_inputPasskeyResponseRegister {
		return nil, status.Error(mtproto.ErrBadRequest, "INPUT_CONSTRUCTOR_INVALID")
	}
	regResp := resp.To_InputPasskeyResponseRegister()

	credId := credPK.GetId()
	if credId == "" {
		credId = credPK.GetRawId()
	}
	if credId == "" {
		return nil, status.Error(mtproto.ErrBadRequest, "PASSKEY_CREDENTIAL_INVALID")
	}

	// 可选：校验 session challenge 与 clientData 中的 challenge 一致（完整实现需解析 clientData JSON）
	_, _ = c.svcCtx.Dao.GetRegChallenge(c.ctx, c.MD.PermAuthKeyId)

	dcId := c.svcCtx.Config.DcId
	if dcId <= 0 {
		dcId = 1
	}
	now := int32(time.Now().Unix())
	name := "Passkey"
	if regResp.GetClientData() != nil && regResp.GetClientData().GetData() != "" {
		raw := regResp.GetClientData().GetData()
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err == nil {
			// 优先使用自定义字段，其次使用标准字段
			if v, ok := m["teamgram_name"].(string); ok && v != "" {
				name = v
			} else if v, ok := m["name"].(string); ok && v != "" {
				name = v
			}
		}
	}
	// 如果 clientData 中没有带 name，则退回到用户信息（phone/username）
	if name == "Passkey" {
		if immutableUser, err := c.svcCtx.Dao.UserClient.UserGetImmutableUser(c.ctx, &userpb.TLUserGetImmutableUser{
			Id: c.MD.UserId,
		}); err == nil && immutableUser != nil {
			if u := immutableUser.Username(); u != "" {
				name = u
			} else if p := immutableUser.Phone(); p != "" {
				name = p
			}
		}
	}

	stored := &dao.StoredPasskey{
		Id:     credId,
		Name:   name,
		UserId: c.MD.UserId,
		DcId:   dcId,
		Date:   now,
	}
	if err := c.svcCtx.Dao.SavePasskey(c.ctx, stored); err != nil {
		c.Logger.Errorf("account.registerPasskey - save: %v", err)
		return nil, mtproto.ErrInternalServerError
	}

	p := &mtproto.Passkey{
		Id:   stored.Id,
		Name: stored.Name,
		Date: stored.Date,
	}
	return mtproto.MakeTLPasskey(p).To_Passkey(), nil
}
