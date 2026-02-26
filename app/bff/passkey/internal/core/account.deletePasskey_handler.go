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
)

// AccountDeletePasskey
// account.deletePasskey#f5b5563f id:string = Bool;
func (c *PasskeyCore) AccountDeletePasskey(in *mtproto.TLAccountDeletePasskey) (*mtproto.Bool, error) {
	if c.MD == nil || c.MD.UserId == 0 {
		c.Logger.Errorf("account.deletePasskey - not logged in")
		return nil, status.Error(mtproto.ErrUnauthorized, "AUTH_KEY_UNREGISTERED")
	}

	if in.GetId() == "" {
		return nil, status.Error(mtproto.ErrBadRequest, "PASSKEY_ID_INVALID")
	}

	err := c.svcCtx.Dao.DeletePasskey(c.ctx, in.GetId(), c.MD.UserId)
	if err != nil {
		c.Logger.Errorf("account.deletePasskey - %v", err)
		return nil, status.Error(mtproto.ErrBadRequest, "PASSKEY_NOT_FOUND")
	}

	return mtproto.BoolTrue, nil
}
