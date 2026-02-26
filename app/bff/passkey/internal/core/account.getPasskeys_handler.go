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
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// AccountGetPasskeys
// account.getPasskeys#ea1f0c52 = account.Passkeys;
func (c *PasskeyCore) AccountGetPasskeys(in *mtproto.TLAccountGetPasskeys) (*mtproto.Account_Passkeys, error) {
	if c.MD == nil || c.MD.UserId == 0 {
		c.Logger.Errorf("account.getPasskeys - not logged in")
		return nil, status.Error(mtproto.ErrUnauthorized, "AUTH_KEY_UNREGISTERED")
	}

	ids, err := c.svcCtx.Dao.ListUserPasskeyIds(c.ctx, c.MD.UserId)
	if err != nil {
		c.Logger.Errorf("account.getPasskeys - list ids: %v", err)
		return nil, err
	}

	var list []*mtproto.Passkey
	for _, id := range ids {
		cred, err := c.svcCtx.Dao.GetPasskey(c.ctx, id)
		if err != nil {
			continue
		}
		p := &mtproto.Passkey{
			Id:              cred.Id,
			Name:            "Google Password Manager",
			Date:            cred.Date,
			LastUsageDate:   &wrapperspb.Int32Value{Value: cred.LastUsageDate},
			SoftwareEmojiId: nil, // mtproto.MakeFlagsInt64(4974455483281704470),
		}
		if cred.LastUsageDate == 0 {
			p.LastUsageDate = nil
		}
		list = append(list, mtproto.MakeTLPasskey(p).To_Passkey())
	}

	return mtproto.MakeTLAccountPasskeys(&mtproto.Account_Passkeys{Passkeys: list}).To_Account_Passkeys(), nil
}
