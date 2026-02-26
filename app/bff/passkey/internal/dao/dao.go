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

package dao

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/teamgram/marmota/pkg/net/rpcx"
	"github.com/teamgram/teamgram-server/app/bff/passkey/internal/config"
	authsession_client "github.com/teamgram/teamgram-server/app/service/authsession/client"
	user_client "github.com/teamgram/teamgram-server/app/service/biz/user/client"
	"github.com/zeromicro/go-zero/core/stores/kv"
)

const (
	passkeyRegChallengePrefix  = "passkey_reg_challenge:"
	passkeyLoginChallengePrefix = "passkey_login_challenge:"
	passkeyCredPrefix           = "passkey_cred:"
	passkeyUserPrefix           = "passkey_user:"
	passkeyChallengeTTL         = 5 * time.Minute
)

type Dao struct {
	kv kv.Store
	authsession_client.AuthsessionClient
	user_client.UserClient
}

// StoredPasskey 持久化的 passkey 信息（用于 getPasskeys 返回与登录校验）
type StoredPasskey struct {
	Id            string `json:"id"`
	Name          string `json:"name"`
	UserId        int64  `json:"user_id"`
	DcId          int32  `json:"dc_id"`
	Date          int32  `json:"date"`
	LastUsageDate int32  `json:"last_usage_date,omitempty"`
	PublicKeyB64  string `json:"public_key_b64,omitempty"` // 用于 finishPasskeyLogin 校验签名
}

// PasskeyRegSession 注册阶段的 session（challenge 等）
type PasskeyRegSession struct {
	Challenge  string `json:"challenge"`
	UserId     int64  `json:"user_id"`
	DcId       int32  `json:"dc_id"`
	OptionsJSON string `json:"options_json,omitempty"`
}

// PasskeyLoginSession 登录阶段的 session
type PasskeyLoginSession struct {
	Challenge string `json:"challenge"`
}

func New(c config.Config) *Dao {
	return &Dao{
		kv:                kv.NewStore(c.KV),
		AuthsessionClient: authsession_client.NewAuthsessionClient(rpcx.GetCachedRpcClient(c.AuthsessionClient)),
		UserClient:        user_client.NewUserClient(rpcx.GetCachedRpcClient(c.UserClient)),
	}
}

func (d *Dao) SetRegChallenge(ctx context.Context, authKeyId int64, session *PasskeyRegSession) error {
	key := passkeyRegChallengePrefix + strconv.FormatInt(authKeyId, 10)
	data, _ := json.Marshal(session)
	return d.kv.SetCtx(ctx, key, string(data))
}

func (d *Dao) GetRegChallenge(ctx context.Context, authKeyId int64) (*PasskeyRegSession, error) {
	key := passkeyRegChallengePrefix + strconv.FormatInt(authKeyId, 10)
	data, err := d.kv.GetCtx(ctx, key)
	if err != nil || data == "" {
		return nil, fmt.Errorf("challenge not found or expired")
	}
	var session PasskeyRegSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (d *Dao) SetLoginChallenge(ctx context.Context, authKeyId int64, challenge string) error {
	key := passkeyLoginChallengePrefix + strconv.FormatInt(authKeyId, 10)
	session := PasskeyLoginSession{Challenge: challenge}
	data, _ := json.Marshal(&session)
	return d.kv.SetCtx(ctx, key, string(data))
}

func (d *Dao) GetLoginChallenge(ctx context.Context, authKeyId int64) (string, error) {
	key := passkeyLoginChallengePrefix + strconv.FormatInt(authKeyId, 10)
	data, err := d.kv.GetCtx(ctx, key)
	if err != nil || data == "" {
		return "", fmt.Errorf("challenge not found or expired")
	}
	var session PasskeyLoginSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return "", err
	}
	return session.Challenge, nil
}

func (d *Dao) SavePasskey(ctx context.Context, cred *StoredPasskey) error {
	data, _ := json.Marshal(cred)
	if err := d.kv.SetCtx(ctx, passkeyCredPrefix+cred.Id, string(data)); err != nil {
		return err
	}
	userKey := passkeyUserPrefix + strconv.FormatInt(cred.UserId, 10)
	existing, _ := d.kv.GetCtx(ctx, userKey)
	ids := splitAndTrim(existing, ",")
	for _, id := range ids {
		if id == cred.Id {
			return nil
		}
	}
	if existing == "" {
		existing = cred.Id
	} else {
		existing = existing + "," + cred.Id
	}
	return d.kv.SetCtx(ctx, userKey, existing)
}

func (d *Dao) GetPasskey(ctx context.Context, credentialId string) (*StoredPasskey, error) {
	data, err := d.kv.GetCtx(ctx, passkeyCredPrefix+credentialId)
	if err != nil || data == "" {
		return nil, fmt.Errorf("passkey not found")
	}
	var cred StoredPasskey
	if err := json.Unmarshal([]byte(data), &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

func (d *Dao) ListUserPasskeyIds(ctx context.Context, userId int64) ([]string, error) {
	userKey := passkeyUserPrefix + strconv.FormatInt(userId, 10)
	data, err := d.kv.GetCtx(ctx, userKey)
	if err != nil || data == "" {
		return nil, nil
	}
	var ids []string
	// 简单逗号分隔
	for _, s := range splitAndTrim(data, ",") {
		if s != "" {
			ids = append(ids, s)
		}
	}
	return ids, nil
}

func (d *Dao) DeletePasskey(ctx context.Context, credentialId string, userId int64) error {
	cred, err := d.GetPasskey(ctx, credentialId)
	if err != nil {
		return err
	}
	if cred.UserId != userId {
		return fmt.Errorf("passkey not owned by user")
	}
	if _, err := d.kv.DelCtx(ctx, passkeyCredPrefix+credentialId); err != nil {
		return err
	}
	userKey := passkeyUserPrefix + strconv.FormatInt(userId, 10)
	data, _ := d.kv.GetCtx(ctx, userKey)
	newIds := removeFromList(data, credentialId)
	return d.kv.SetCtx(ctx, userKey, newIds)
}

func splitAndTrim(s, sep string) []string {
	var out []string
	for _, p := range splitSimple(s, sep) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitSimple(s, sep string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			out = append(out, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	out = append(out, s[start:])
	return out
}

func removeFromList(list, id string) string {
	parts := splitSimple(list, ",")
	var newParts []string
	for _, p := range parts {
		if p != id {
			newParts = append(newParts, p)
		}
	}
	result := ""
	for i, p := range newParts {
		if i > 0 {
			result += ","
		}
		result += p
	}
	return result
}
