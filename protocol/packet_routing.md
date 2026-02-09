# Packet Routing & Server Assignment

Analysis of which packets are routed to which server tier in the VAMPIR protocol.

**Note**: The in-game `PacketDest.csv` was found to be a stub file (header only, no data rows).
The routing below is inferred from packet naming conventions, the three-tier server architecture
documented in `endpoints.md`, and the `PktLobby*` / `PktWorld*` naming patterns.

---

## Server Tiers

| Server | Role | Key Packets |
|--------|------|-------------|
| **Lobby Server** | Authentication, server selection, platform SDK | `PktLobby*`, `PktServerTransfer*`, `PktNetmarbleS*` |
| **Game Server** | Core gameplay, inventory, social, combat | Most `Pkt*` packets (character, item, guild, etc.) |
| **World Server** | World state, movement, effects, environment | `PktWorld*`, `PktEffect*`, `PktEnvironment*` |

---

## Packet Distribution by System

### Lobby Server (~18 packets)

| System | Count | Examples |
|--------|-------|---------|
| ServerTransfer | 6 | PktServerTransferListRead, PktServerTransferCheck |
| NetmarbleSDK | 12 | PktNetmarbleSDeliverySubscription*, PktNetmarbleSAuth* |

The lobby server also handles the initial login flow:
- `PktLobbyLogin` / `PktLobbyLoginResult`
- `PktLobbyServerListRead` / `PktLobbyServerListReadResult`
- `PktLobbyCharacterListRead` / `PktLobbyCharacterListReadResult`

*(Note: `PktLobby*` packets are among the 361 unmapped Pkt* strings - they exist in the binary
but are not registered in the main dispatch function, suggesting they use a separate lobby
dispatch handler.)*

### World Server (~33 packets)

| System | Count | Examples |
|--------|-------|---------|
| World | 27 | PktWorldMoveStart, PktWorldMoveFinish, PktWorldEnter |
| Effect | 4 | PktEffectAddNotify, PktEffectRemoveNotify |
| Environment | 2 | PktEnvironmentManage, PktEnvironmentManageResult |

### Game Server (~1,144 packets)

| System | Count | Examples |
|--------|-------|---------|
| Connection | 30 | PktVersion, PktLogin, PktPing, PktKeyChange |
| Guild | 110 | PktGuildCreate, PktGuildInvite, PktGuildDungeon* |
| Party | 90 | PktPartyInvite, PktPartyKick, PktPartyBuff* |
| Character | 71 | PktCharacterCreate, PktCharacterMove, PktCharacterDie* |
| Item | 57 | PktItemUse, PktItemEquip, PktItemAutoUse* |
| Chat | 50 | PktChatMessage, PktChatGroupRoom*, PktChatBlock* |
| Quest | 48 | PktQuestAccept, PktQuestComplete, PktQuestAutoStart* |
| Auction | 48 | PktAuctionRegister, PktAuctionBuy, PktAuctionFavorite* |
| PvP | 40 | PktPvpAlert*, PktPvpMatch*, PktPvpRanking* |
| Skill | 25 | PktSkillUse, PktSkillCancel, PktSkillPreset* |
| Mail | 22 | PktMailListRead, PktMailWrite, PktMailReceive* |
| Conquest | 20 | PktConquestDataRead, PktConquestJoin* |
| Dungeon | 19 | PktDungeonEnter, PktDungeonClear* |
| Combat | 16 | PktCombatPreset*, PktCombatPower* |
| Collection | 11 | PktCollectRegister, PktCollectReward* |
| Achievement | 9 | PktAchievementListRead, PktAchievementReward* |
| Summon | 7 | PktSummonCallRequest, PktSummonDismiss* |
| ServerTransfer | 6 | PktServerTransferListRead, PktServerTransferCheck* |
| Follower | 5 | PktFollowerNpc*, PktFollowerCommand* |
| Shop | 5 | PktShopBuy, PktShopListRead* |
| Ranking | 4 | PktRankingListRead, PktRankingReward* |
| Other | 457 | Various game systems |

---

## Connection Flow

```
Client                    Lobby Server              Game Server
  |                            |                         |
  |--- HTTPS GMC2 /constants ->|                         |
  |<-- server URLs, config ----|                         |
  |                            |                         |
  |--- PktLobbyLogin -------->|                         |
  |<-- PktLobbyLoginResult ---|                         |
  |                            |                         |
  |--- PktLobbyServerListRead>|                         |
  |<-- server list + IPs -----|                         |
  |                            |                         |
  |--- TCP connect ---------------------------------->  |
  |                            |                         |
  |--- PktVersion (1) -------------------------------->|
  |<-- PktVersionResult (2) ----------------------------|
  |                            |                         |
  |--- PktLogin (3) ---------------------------------->|
  |<-- PktLoginResult (4) -----------------------------|
  |                            |                         |
  |<-- PktKeyChangeNotify (11) -------------------------|
  |--- PktKeyChanged (12) ---------------------------->|
  |<-- PktKeyChangedResult (13) ------------------------|
  |                            |                         |
  |--- PktCharacterListRead (101) -------------------->|
  |<-- PktCharacterListReadResult (102) ----------------|
  |                            |                         |
  |--- PktCharacterSelect (109) ---------------------->|
  |<-- PktCharacterSelectResult (110) ------------------|
  |                            |                         |
  |=== Game session established, encrypted with new key =|
```

---

## Opcode Ranges

| Range | System | Notes |
|-------|--------|-------|
| 1-30 | Connection | Version, login, ping, key exchange, waiting queue |
| 101-200 | Character | Create, delete, select, name change |
| 201-500 | Core Gameplay | World move, combat, skills, effects |
| 501-1000 | Items & Equipment | Inventory, equip, enhance, craft |
| 1001-2500 | Social & Economy | Guild, party, chat, mail, auction |
| 2501-10425 | Extended Systems | Quests, achievements, rankings, PvP |
| 28901-29162 (0x70E5-0x71EA) | Anti-Cheat | Xigncode, security verification |
| 30105-30308 (0x75F9-0x7664) | Admin/Debug | Internal tools |
| 30101-30117 (0x7595-0x7598) | System | Low-level system packets |
| 31001-31053 (0x7919-0x794D) | GM Tools | Environment manage, packet zip |
