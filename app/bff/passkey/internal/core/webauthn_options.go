// Copyright 2025 Teamgram Authors
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

package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// PublicKeyCredentialCreationOptions 与客户端 CreatePublicKeyCredentialRequest 兼容的创建选项
// 参考: https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
func BuildCreationOptionsJSON(challenge []byte, rpId, rpName, userHandle, userName, userDisplayName string) (string, error) {
	challengeB64 := base64.RawURLEncoding.EncodeToString(challenge)
	userHandleB64 := base64.RawURLEncoding.EncodeToString([]byte(userHandle))
	publicKey := map[string]interface{}{
		"challenge": challengeB64,
		"rp": map[string]interface{}{
			"id":   rpId,
			"name": rpName,
		},
		"user": map[string]interface{}{
			"id":          userHandleB64,
			"name":        userName,
			"displayName": userDisplayName,
		},
		"pubKeyCredParams": []map[string]interface{}{
			{
				"type": "public-key",
				"alg":  -7,
			},
		},
		"timeout":     300000,
		"attestation": "none",
		"authenticatorSelection": map[string]interface{}{
			"userVerification":        "preferred",
			"requireResidentKey":      true,
			"residentKey":             "required",
			"authenticatorAttachment": "platform",
		},
	}
	outer := map[string]interface{}{
		"publicKey": publicKey,
	}
	raw, err := json.Marshal(outer)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// PublicKeyCredentialRequestOptions 与客户端 GetCredential 兼容的认证选项
// 参考: https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions
func BuildAssertionOptionsJSON(challenge []byte, rpId string, allowCredentials []string) (string, error) {
	challengeB64 := base64.RawURLEncoding.EncodeToString(challenge)
	publicKey := map[string]interface{}{
		"challenge": challengeB64,
		"rpId":      rpId,
	}
	if len(allowCredentials) > 0 {
		allow := make([]map[string]interface{}, 0, len(allowCredentials))
		for _, id := range allowCredentials {
			allow = append(allow, map[string]interface{}{
				"id":   id,
				"type": "public-key",
			})
		}
		publicKey["allowCredentials"] = allow
	} else {
		publicKey["allowCredentials"] = []interface{}{}
	}
	outer := map[string]interface{}{
		"publicKey": publicKey,
	}
	raw, err := json.Marshal(outer)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// RandomChallenge 生成 32 字节随机 challenge
func RandomChallenge() ([]byte, error) {
	b := []byte(uuid.New().String() + uuid.New().String())
	if len(b) > 32 {
		return b[:32], nil
	}
	return b, nil
}

// ParseUserHandle 解析 Android 端 userHandle 格式 "datacenterId:userId"
func ParseUserHandle(userHandle string) (dcId int, userId int64, err error) {
	parts := strings.SplitN(userHandle, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid userHandle format")
	}
	_, _ = fmt.Sscanf(parts[0], "%d", &dcId)
	_, _ = fmt.Sscanf(parts[1], "%d", &userId)
	if userId == 0 {
		return 0, 0, fmt.Errorf("invalid userId in userHandle")
	}
	return dcId, userId, nil
}
