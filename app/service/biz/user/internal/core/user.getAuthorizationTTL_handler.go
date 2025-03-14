// Copyright 2024 Teamgram Authors
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
	"github.com/teamgram/teamgram-server/app/service/biz/user/user"
)

// UserGetAuthorizationTTL
// user.getAuthorizationTTL user_id:long = AccountDaysTTL;
func (c *UserCore) UserGetAuthorizationTTL(in *user.TLUserGetAuthorizationTTL) (*mtproto.AccountDaysTTL, error) {
	userDO, _ := c.svcCtx.Dao.UsersDAO.SelectAuthorizationTTL(c.ctx, in.UserId)
	if userDO == nil {
		err := mtproto.ErrUserIdInvalid
		c.Logger.Errorf("user.getAccountDaysTTL - error: %v", err)
		return nil, err
	}

	return mtproto.MakeTLAccountDaysTTL(&mtproto.AccountDaysTTL{
		Days: userDO.AuthorizationTtlDays,
	}).To_AccountDaysTTL(), nil
}
