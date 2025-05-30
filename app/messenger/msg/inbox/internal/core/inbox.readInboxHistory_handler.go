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
	"fmt"

	"github.com/teamgram/proto/mtproto"
	"github.com/teamgram/teamgram-server/app/messenger/msg/inbox/inbox"
	"github.com/teamgram/teamgram-server/app/messenger/sync/sync"
	"github.com/teamgram/teamgram-server/app/service/biz/dialog/dialog"

	"google.golang.org/protobuf/types/known/wrapperspb"
)

// InboxReadInboxHistory
// inbox.readInboxHistory user_id:long auth_key_id:long peer_type:int peer_id:long unread_count:int read_inbox_max_id:int max_id:int = Void;
func (c *InboxCore) InboxReadInboxHistory(in *inbox.TLInboxReadInboxHistory) (*mtproto.Void, error) {
	var (
		maxId       = in.MaxId
		did         = mtproto.MakeDialogId(in.UserId, in.PeerType, in.PeerId)
		unreadCount int32
	)

	if maxId > in.ReadInboxMaxId {
		readCount := c.svcCtx.Dao.CommonDAO.CalcSizeByWhere(
			c.ctx,
			c.svcCtx.Dao.MessagesDAO.CalcTableName(in.UserId),
			fmt.Sprintf("user_id = %d AND dialog_id1 = %d AND dialog_id2 = %d AND sender_user_id <> %d AND user_message_box_id > %d AND user_message_box_id <= %d AND deleted = 0",
				in.UserId, did.A, did.B, in.UserId, in.ReadInboxMaxId, maxId))
		unreadCount = in.UnreadCount - int32(readCount)
		if unreadCount < 0 {
			unreadCount = 0
		}
	}

	_, _ = c.svcCtx.Dao.DialogClient.DialogInsertOrUpdateDialog(
		c.ctx,
		&dialog.TLDialogInsertOrUpdateDialog{
			UserId:          in.UserId,
			PeerType:        in.PeerType,
			PeerId:          in.PeerId,
			TopMessage:      nil,
			ReadOutboxMaxId: nil,
			ReadInboxMaxId:  &wrapperspb.Int32Value{Value: maxId},
			UnreadCount:     &wrapperspb.Int32Value{Value: unreadCount},
			UnreadMark:      false,
			PinnedMsgId:     nil,
			Date2:           nil,
		})

	isUseV3 := false
	if in.GetLayer() != nil {
		isUseV3 = true
	}
	if !isUseV3 && in.GetServerId() != nil {
		isUseV3 = true
	}
	if !isUseV3 && in.GetSessionId() != nil {
		isUseV3 = true
	}
	if !isUseV3 && in.GetClientReqMsgId() != nil {
		isUseV3 = true
	}

	var (
		pts      = in.Pts
		ptsCount = in.PtsCount
	)
	if isUseV3 {
		pts = c.svcCtx.Dao.IDGenClient2.NextPtsId(c.ctx, in.UserId)
		ptsCount = 1

		rpcResult := &mtproto.TLRpcResult{
			ReqMsgId: in.GetClientReqMsgId().GetValue(),
			Result: mtproto.MakeTLMessagesAffectedMessages(&mtproto.Messages_AffectedMessages{
				Pts:      pts,
				PtsCount: ptsCount,
			}).To_Messages_AffectedMessages(),
		}
		// push
		x := mtproto.NewEncodeBuf(512)
		_ = rpcResult.Encode(x, in.GetLayer().GetValue())
		_, _ = c.svcCtx.Dao.SyncClient.SyncPushRpcResult(c.ctx, &sync.TLSyncPushRpcResult{
			UserId:         in.UserId,
			AuthKeyId:      in.AuthKeyId,
			PermAuthKeyId:  in.AuthKeyId,
			ServerId:       in.GetServerId().GetValue(),
			SessionId:      in.GetSessionId().GetValue(),
			ClientReqMsgId: in.GetClientReqMsgId().GetValue(),
			RpcResult:      x.GetBuf(),
		})
	}

	_, _ = c.svcCtx.Dao.SyncClient.SyncUpdatesNotMe(
		c.ctx,
		&sync.TLSyncUpdatesNotMe{
			UserId:        in.UserId,
			PermAuthKeyId: in.AuthKeyId,
			Updates: mtproto.MakeUpdatesByUpdates(mtproto.MakeTLUpdateReadHistoryInbox(&mtproto.Update{
				Peer_PEER: mtproto.MakePeer(in.PeerType, in.PeerId),
				MaxId:     maxId,
				Pts_INT32: pts,
				PtsCount:  ptsCount,
			}).To_Update()),
		})

	return mtproto.EmptyVoid, nil
}
