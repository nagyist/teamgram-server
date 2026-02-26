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
	"fmt"
	"strconv"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/bff/passkey/internal/dao"
	userpb "github.com/teamgram/teamgram-server/app/service/biz/user/user"
	"google.golang.org/grpc/status"
)

/**
{
    "publicKey": {
        "rp": {
            "id": "teamgram.me",
            "name": "Teamgram"
        },
        "user": {
            "id": "NToyNjQ2OTY4NDU",
            "name": "+8613606512716",
            "displayName": "@benqi"
        },
        "challenge": "3rFPseG6MFctyrKnw5I4HHZ937f6pTCnMkcOfMOdRkw",
        "pubKeyCredParams": [
            {
                "type": "public-key",
                "alg": -7
            }
        ],
        "timeout": 300000,
        "attestation": "none",
        "authenticatorSelection": {
            "userVerification": "preferred",
            "requireResidentKey": true,
            "residentKey": "required",
            "authenticatorAttachment": "platform"
        }
    }
}
***/

// AccountInitPasskeyRegistration
// account.initPasskeyRegistration#429547e8 = account.PasskeyRegistrationOptions;
func (c *PasskeyCore) AccountInitPasskeyRegistration(in *mtproto.TLAccountInitPasskeyRegistration) (*mtproto.Account_PasskeyRegistrationOptions, error) {
	if c.MD == nil || c.MD.UserId == 0 {
		c.Logger.Errorf("account.initPasskeyRegistration - not logged in")
		return nil, status.Error(mtproto.ErrUnauthorized, "AUTH_KEY_UNREGISTERED")
	}

	dcId := c.svcCtx.Config.DcId
	if dcId <= 0 {
		dcId = 1
	}
	userHandle := fmt.Sprintf("%d:%d", dcId, c.MD.UserId)

	// 读取用户信息，以便在 WebAuthn user 字段中使用手机号和 username
	immutableUser, err := c.svcCtx.Dao.UserClient.UserGetImmutableUser(c.ctx, &userpb.TLUserGetImmutableUser{
		Id: c.MD.UserId,
	})
	if err != nil {
		c.Logger.Errorf("account.initPasskeyRegistration - get user: %v", err)
		return nil, mtproto.ErrInternalServerError
	}

	userPhone := immutableUser.Phone()
	if userPhone == "" {
		// 兜底：没有手机号时使用 userId
		userPhone = strconv.FormatInt(c.MD.UserId, 10)
	}
	userUsername := immutableUser.Username()
	if userUsername == "" {
		// 兜底：没有 username 时使用手机号
		userUsername = userPhone
	}

	challenge, err := RandomChallenge()
	if err != nil {
		c.Logger.Errorf("account.initPasskeyRegistration - challenge: %v", err)
		return nil, mtproto.ErrInternalServerError
	}

	optionsJSON, err := BuildCreationOptionsJSON(
		challenge,
		"teamgram.me",
		"Teamgram Messenger",
		userHandle,
		"+"+userPhone,    // user.name  使用该用户的电话号码
		"@"+userUsername, // user.displayName 使用该用户的 username
	)
	if err != nil {
		c.Logger.Errorf("account.initPasskeyRegistration - options: %v", err)
		return nil, mtproto.ErrInternalServerError
	}

	session := &dao.PasskeyRegSession{
		Challenge:   string(challenge),
		UserId:      c.MD.UserId,
		DcId:        dcId,
		OptionsJSON: optionsJSON,
	}
	if err := c.svcCtx.Dao.SetRegChallenge(c.ctx, c.MD.PermAuthKeyId, session); err != nil {
		c.Logger.Errorf("account.initPasskeyRegistration - set challenge: %v", err)
		return nil, mtproto.ErrInternalServerError
	}

	return mtproto.MakeTLAccountPasskeyRegistrationOptions(&mtproto.Account_PasskeyRegistrationOptions{
		Options: mtproto.MakeTLDataJSON(&mtproto.DataJSON{Data: optionsJSON}).To_DataJSON(),
	}).To_Account_PasskeyRegistrationOptions(), nil
}
