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
	"github.com/teamgram/teamgram-server/app/service/authsession/authsession"
	userpb "github.com/teamgram/teamgram-server/app/service/biz/user/user"
	"google.golang.org/grpc/status"
)

// AuthFinishPasskeyLogin
// auth.finishPasskeyLogin#9857ad07 flags:# credential:InputPasskeyCredential from_dc_id:flags.0?int from_auth_key_id:flags.0?long = auth.Authorization;
func (c *PasskeyCore) AuthFinishPasskeyLogin(in *mtproto.TLAuthFinishPasskeyLogin) (*mtproto.Auth_Authorization, error) {
	cred := in.GetCredential()
	if cred == nil || cred.GetPredicateName() != mtproto.Predicate_inputPasskeyCredentialPublicKey {
		return nil, status.Error(mtproto.ErrBadRequest, "INPUT_CONSTRUCTOR_INVALID")
	}
	credPK := cred.To_InputPasskeyCredentialPublicKey()
	resp := credPK.GetResponse()
	if resp == nil || resp.GetPredicateName() != mtproto.Predicate_inputPasskeyResponseLogin {
		return nil, status.Error(mtproto.ErrBadRequest, "INPUT_CONSTRUCTOR_INVALID")
	}
	loginResp := resp.To_InputPasskeyResponseLogin()

	userHandle := loginResp.GetUserHandle()
	if userHandle == "" {
		return nil, status.Error(mtproto.ErrBadRequest, "PASSKEY_CREDENTIAL_INVALID")
	}

	_, userId, err := ParseUserHandle(userHandle)
	if err != nil {
		c.Logger.Errorf("auth.finishPasskeyLogin - parse userHandle: %v", err)
		return nil, status.Error(mtproto.ErrBadRequest, "PASSKEY_CREDENTIAL_INVALID")
	}

	credId := credPK.GetId()
	if credId == "" {
		credId = credPK.GetRawId()
	}
	stored, err := c.svcCtx.Dao.GetPasskey(c.ctx, credId)
	if err != nil || stored == nil {
		c.Logger.Errorf("auth.finishPasskeyLogin - passkey not found")
		return nil, status.Error(mtproto.ErrBadRequest, "PASSKEY_NOT_FOUND")
	}
	if stored.UserId != userId {
		c.Logger.Errorf("auth.finishPasskeyLogin - userHandle mismatch")
		return nil, status.Error(mtproto.ErrBadRequest, "PASSKEY_CREDENTIAL_INVALID")
	}

	authKeyId := int64(0)
	if c.MD != nil {
		authKeyId = c.MD.PermAuthKeyId
	}

	_, err = c.svcCtx.Dao.AuthsessionClient.AuthsessionBindAuthKeyUser(c.ctx, &authsession.TLAuthsessionBindAuthKeyUser{
		AuthKeyId: authKeyId,
		UserId:    userId,
	})
	if err != nil {
		c.Logger.Errorf("auth.finishPasskeyLogin - bind auth key: %v", err)
		return nil, err
	}

	user, err := c.svcCtx.Dao.UserClient.UserGetImmutableUser(c.ctx, &userpb.TLUserGetImmutableUser{
		Id: userId,
	})
	if err != nil {
		c.Logger.Errorf("auth.finishPasskeyLogin - get user: %v", err)
		return nil, err
	}

	return mtproto.MakeTLAuthAuthorization(&mtproto.Auth_Authorization{
		User: user.ToSelfUser(),
	}).To_Auth_Authorization(), nil
}
