# Game Server Endpoint Architecture & Connection Flow

Analysis of `lib/arm64-v8a/libUnreal.so` (.rodata section) for server endpoint strings,
connection flow packets, and authentication architecture.

Source binary: 150MB ARM64 ELF, Unreal Engine, Netmarble SDK integrated.

---

## 1. Discovered URLs / API Endpoints

### Netmarble GMC2 (Game Management Console v2) - Configuration Service

The GMC2 `/v4/constants` endpoint is the **entry point** for all server configuration.
It returns game constants including server URLs, log endpoints, and the NMP (Netmarble Platform) URL.

| Environment | URL | VA |
|---|---|---|
| Production | `https://apis.netmarble.com/gmc2/v4/constants` | 0x57baaa |
| Dev | `https://dev-apis.netmarble.com/gmc2/v4/constants` | 0x57bad7 |
| Alpha | `https://alpha-apis.netmarble.com/gmc2/v4/constants` | 0x57bb08 |

Evidence of GMC2 being the source of runtime configuration:
- `Failed to get NMP url from GMC2` (0x6c095b) - NMP URL is fetched from GMC2 response
- `[LOG] No logUrl in GMC2` (0x6c0943) - Log submission URL comes from GMC2
- `bUsingLegacyGMC2` (0x6c091c) - Legacy fallback flag
- `LastUpdateTimeForGMC2` (0x6c092d) - Caching/refresh mechanism

### Netmarble GC2 (Game Center v2) - Platform SDK Backend

GC2 handles SDK-level operations: authentication, billing, push notifications, subscriptions.

| Environment | URL | VA |
|---|---|---|
| Production | `https://apis.netmarble.com/gc2` | 0x6c0211 |
| Dev | `https://dev-apis.netmarble.com/gc2` | 0x6c0230 |
| Alpha | `https://alpha-apis.netmarble.com/gc2` | 0x6c0253 |

### Other Endpoints

| URL | VA | Purpose |
|---|---|---|
| `https://android.crashsight.wetest.net/pb/async` | 0x68c684 | CrashSight crash reporting (WeTest/Tencent) |
| `http://game.local/` | 0x6c57bd | Local dev game server |
| `http://localhost` | 0x54de73 | Localhost fallback |

### URL Validation Pattern

A regex at 0x6d29ec validates Netmarble URLs:
```
^((http|https)://)?[a-zA-Z0-9.-]+(netmarble.com|netmarble.net).*$
```

### API Path Fragment

- `/netmarbles/versions/` (0x6c5741) - Version-related API path on Netmarble backend

---

## 2. Environment Zones (ENMSDKZone)

The SDK supports three environment zones that select which API endpoints to use:

| Zone | VA | Maps To |
|---|---|---|
| `ENMSDKZone::Real` | 0x5fbfc8 | `apis.netmarble.com` (production) |
| `ENMSDKZone::Dev` | 0x5494f6 | `dev-apis.netmarble.com` |
| `ENMSDKZone::Alpha` | 0x698067 | `alpha-apis.netmarble.com` |

---

## 3. Server Addressing Model

### Lobby Server

The lobby server address is configured through two properties:

- **`LobbyServerAddr`** (0x5bb0c5) - IP address or hostname of the lobby server
- **`LobbyServerPort`** (0x55374a) - Port number for lobby server connection

These are likely populated from the GMC2 constants response or a secondary configuration endpoint.

### Game Server Ports

Unreal Engine standard port properties found adjacent to `LobbyServerPort`:

| Property | VA | Purpose |
|---|---|---|
| `BeaconPort` | 0x55375a | UE online beacon port (server discovery) |
| `ListenPort` | 0x553765 | UE main listen port for game connections |
| `GamePort` | 0x553779 | Game-specific port |
| `MeshPort` | 0x553770 | Mesh networking (P2P/relay) port |
| `bReuseAddressAndPort` | 0x553782 | Socket address reuse flag |

### Network Driver Architecture (Iris)

The game uses Unreal's **Iris** replication system (experimental, newer than traditional UE replication):

- `IrisNetDriverConfig` (0x61648e) - Iris net driver configuration
- `IrisNetDriverConfigs` (0x592dcd) - Multiple Iris driver configurations (likely per server type)
- `GameNetDriver` (0x5b0149) - Main game network driver
- `BeaconNetDriver` (0x5b011a) - Beacon network driver for matchmaking/discovery
- `DemoNetDriver` (0x5b010c) - Demo recording driver
- `PendingNetDriver` (0x5b0138) - Pending connection driver
- `MeshNetDriver` (0x5b012a) - Mesh networking driver
- Source path: `Runtime/Experimental/Iris/Core/`

---

## 4. Packet Routing (PacketDest)

The `PacketDest.csv` file (0x5476e5) defines packet routing destinations. Packets can be sent to:

- **Lobby server** - via `PktLobby*` prefixed packets
- **Game server** - via direct game packets and `PktChatListReadToGameServer` (0x5af914)
- **World server** - via `PktChatListReadToWorldServer` (0x5af9ac) and `PktBroadCastSendWorldServer` (0x5af9c9)

This reveals a **three-tier server architecture**:
1. **Lobby Server** - authentication, server selection, character management
2. **Game Server** - gameplay, instanced content
3. **World Server** - cross-server features (world chat, broadcasts)

---

## 5. Connection Flow (Packet Sequence)

### Phase 1: Netmarble SDK Authentication

```
ENetmarbleSDKStep::StartService          (0x6686a8) - Initialize SDK
    |
    v
ENetmarbleSDKStep::SilentlySignIn        (0x5e8ccf) - Try stored token
    |-- fail --> ENetmarbleSDKStep::AutoSignIn   (0x5e8d3b)
    |-- fail --> ENetmarbleSDKStep::ShowAuthMemberLogin (0x5e3e38)
    |
    v
OnSuccessNetmarbleSDKAuth                (0x6020d4) - Auth success callback
```

Channel types for sign-in:
- `ENMChannelType::GooglePlay`, `::Guest`, `::Facebook`, `::Twitter`,
  `::GameCenter`, `::SignInWithApple`, `::SignInWithGoogle`, `::Steam`,
  `::EpicGames`, `::Launcher`, `::PlayStation`, `::Xbox`, `::Netmarble`,
  `::EmailAuth`

Tokens produced:
- `accessToken` - Primary platform access token
- `channelAccessToken` - Channel-specific token
- `NMGameToken` - Game-specific server auth token
- `idToken` - Identity token
- `NetmarbleSToken` - Netmarble S platform token
- `SessionTicket` - Session maintenance ticket

### Phase 2: GMC2 Configuration Fetch

```
GET https://apis.netmarble.com/gmc2/v4/constants
    |
    v
Parse response -> extract:
  - NMP URL (Netmarble Platform URL)
  - logUrl (log submission endpoint)
  - LobbyServerAddr / LobbyServerPort
  - Other configuration constants
```

### Phase 3: Version Check + Lobby Login

```
Client -> Lobby:  PktLobbyVersion        (0x5e0fb5)
Client <- Lobby:  PktLobbyVersionResult  (0x56365d)
    |
    v  (if version OK)
Client -> Lobby:  PktLobbyLogin          (0x5e3e14)
Client <- Lobby:  PktLobbyLoginResult    (0x5636bd)
    |
    v  (security verification)
Client -> Lobby:  PktLobbyNetmarbleSSecurityVerify     (0x536617)
Client <- Lobby:  PktLobbyNetmarbleSSecurityVerifyResult (0x561f5b)
    |
    v  (optional OTP)
Client -> Lobby:  PktLobbyInHouseOtpVerify             (0x536638)
Client <- Lobby:  PktLobbyInHouseOtpVerifyResult       (0x561f82)
```

### Phase 4: Server Selection + Character Selection

```
Client -> Lobby:  PktLobbyServerListRead                (0x6872cf)
Client <- Lobby:  PktLobbyServerListReadResult          (0x564eb2)
    |
    |  -> _InitServerList (0x54f38d) -> _SetServerList (0x54f39d)
    |  -> ServerGroupList / ServerGroupDataList populated
    |
    v  (user selects server/world)
Client -> Lobby:  PktLobbyServerRead                    (0x6878a9)
Client <- Lobby:  PktLobbyServerReadResult              (0x5655bb)
    |
    v
Client -> Lobby:  PktLobbyCharacterListRead             (0x687305)
Client <- Lobby:  PktLobbyCharacterListReadResult       (0x564ef4)
    |
    v
Client -> Lobby:  PktLobbyLastPlayedCharacterListRead    (0x687371)
Client <- Lobby:  PktLobbyLastPlayedCharacterListReadResult (0x564f78)
    |
    v
Client -> Lobby:  PktLobbyCurrentConnectedCharacterRead  (0x6878bc)
Client <- Lobby:  PktLobbyCurrentConnectedCharacterReadResult (0x5655d4)
```

### Phase 5: Game Server Entry

```
Client -> Game:   PktLogin                              (0x5e3e2f)
Client <- Game:   PktLoginResult                        (0x5636d1)
    |
    v  (world movement: EWorldMoveType::Login)
Client -> Game:   PktWorldMoveCast                      (0x552c66)
Client <- Game:   PktWorldMoveCastResult                (0x562708)
    |
    v
Client -> Game:   PktWorldMoveStart                     (0x55451a)
Client <- Game:   PktWorldMoveStartResult               (0x5628ba)
    |
    v  (loading zone, entering world)
Client -> Game:   PktWorldMoveFinish                    (0x605f93)
Client <- Game:   PktWorldMoveFinishResult              (0x563c54)
    |
    v  -> IN GAME
```

### Phase 6: Server Group Data (Runtime)

```
Client <- Game:   PktServerGroupDataNotify              (0x536332)  [push notification]
Client -> Game:   PktServerGroupMatchInfoRead           (0x687afc)
Client <- Game:   PktServerGroupMatchInfoReadResult     (0x565871)
```

### Phase 7: Server Transfer (Runtime)

```
Client -> Lobby:  PktServerTransferCheck                (0x5ff95d)
Client <- Lobby:  PktServerTransferCheckResult          (0x563b28)
    |
Client -> Lobby:  PktServerTransferListRead             (0x687411)
Client <- Lobby:  PktServerTransferListReadResult       (0x565036)
    |
Client -> Lobby:  PktServerTransferRequest              (0x5510cf)
Client <- Lobby:  PktServerTransferRequestResult        (0x562442)
    |
Client <- Lobby:  PktServerTransferStatus               (0x5779c4) [status updates]
```

### Phase 8: Logout / Exit

```
Client -> Game:   PktServerExit                         (0x566ff0)
Client <- Game:   PktServerExitResult                   (0x5629bd)
    |  -> returns to lobby
    v
Client -> Lobby:  PktLogout                             (0x54c017)
Client <- Lobby:  PktLogoutResult                       (0x5622d5)
```

### Phase 9: Reconnection

```
Client <- Game:   PktReconnectPopUpNotify               (0x534f73) [server triggers reconnect]
    |
    v
ReconnectSocket                                         (0x56e769)
    |
    v  (if reconnect during world move)
Client <- Game:   PktWorldMoveCastReconnectNotify       (0x534ce2)
```

### Phase 10: Auth Token Refresh (Background)

```
Client -> Lobby:  PktNetmarbleSAuthUpdate               (0x62795b)
Client <- Lobby:  PktNetmarbleSAuthUpdateResult         (0x5643a8)
```

---

## 6. Lobby State Machine

The lobby follows this state progression:

```
ELobbyState::Splash                     (0x607380)
    |
    v
ELobbyState::Title                      (0x64bc32)
    |
    v  [SDK auth + login]
ELobbyState::TrasnsitionSelectWorld     (0x671198)   [note: typo in binary]
    |
    v  [server list loaded, character selected]
ELobbyState::CharacterSelect            (0x572592)
    |-- create --> ELobbyState::CharacterClassSelect  (0x5724e6)
    |              --> ELobbyState::CharacterCreateIntro (0x5c9649)
    |              --> ELobbyState::CharacterCustomize   (0x618f28)
    |
    v  [enter game]
ELobbyState::TransitionInGameWorld      (0x67187d)
```

---

## 7. Authentication Token Hierarchy

```
Netmarble SDK Auth
  |
  +-- accessToken              (primary platform token)
  +-- channelAccessToken       (Google/Apple/Facebook/etc. token)
  +-- idToken                  (identity assertion)
  |
  v  [exchanged for game tokens]
  |
  +-- NMGameToken              (game server authentication)
  +-- NetmarbleSToken          (Netmarble S platform services)
  +-- SessionTicket            (session maintenance)
  |
  v  [periodic refresh]
  |
  +-- refresh_token            (OAuth refresh token)
  +-- RefreshTokenForGooglePlay
  +-- EmailAuthRefreshToken
  +-- TermRefreshSessionMinutes (refresh interval)
  +-- beforeAccessTokenExpireTimeSec (pre-expiry timing)
```

Validation error strings confirm required tokens:
- `accessToken is null or empty` (0x52bb67)
- `channelAccessToken is null or empty` (0x52bb84)
- `gameToken is null or empty` (0x52bba8)
- `idToken is null or empty` (0x52bbc3)

---

## 8. Data Configuration Files

Server-related CSV tables loaded at runtime:

| File | VA | Purpose |
|---|---|---|
| `PacketDest.csv` | 0x5476e5 | Packet routing destination table |
| `ServerGroup.csv` | 0x547a1d | Server group definitions |
| `ServerGroupName.csv` | 0x5483b8 | Server group display names |
| `ServerGroupPenaltySetting.csv` | 0x548122 | Server group penalty rules |
| `ServerGroupPointSetting.csv` | 0x548140 | Server group point rules |
| `ServerTransfer.csv` | 0x5479af | Server transfer rules |
| `ServerTransferGroup.csv` | 0x547a2d | Transfer group definitions |
| `ServerTransferCondition.csv` | 0x547c3d | Transfer conditions |
| `ServerTransferConditionGroup.csv` | 0x547a55 | Transfer condition groups |
| `ServerAuctionGroup.csv` | 0x547a76 | Cross-server auction groups |
| `ServerDrivenOptimization.csv` | 0x547d01 | Server-driven performance settings |
| `LobbyResultCodeString.csv` | 0x548200 | Lobby error/result code strings |
| `WorldMove.csv` | 0x548256 | World movement/teleportation defs |

---

## 9. World Movement Types

`EWorldMoveType` defines all zone transition types:

| Type | VA | Context |
|---|---|---|
| `Login` | 0x5e3ee5 | Initial login world entry |
| `Enter` | 0x5b1e17 | Generic world entry |
| `TownReturn` | 0x5d0138 | Return to town |
| `CombatTownReturn` | 0x5d00d7 | Return from combat to town |
| `Waypoint` | 0x5598ab | Waypoint teleport |
| `WaypointAreas` | 0x5a2c17 | Area waypoint teleport |
| `LocationMemory` | 0x530da6 | Saved location teleport |
| `WorldRandom` | 0x5ed23f | Random world entry |
| `CombatWorldRandom` | 0x5ed1fd | Random combat world entry |
| `QuestFastEnter` | 0x5b1b1a | Quest fast-enter |
| `QuestInstance` | 0x665bd3 | Quest instance entry |
| `Revive` | 0x61c5ab | Revive respawn |
| `PvpRevenge` | 0x6555d1 | PvP revenge teleport |
| `ConquestWorldEnter` | 0x5b1d8d | Conquest world entry |
| `NormalDungeonEnter` | 0x5b1bc0 | Normal dungeon entry |
| `EliteDungeonEnter` | 0x5b1c08 | Elite dungeon entry |
| `MatchingDungeonEnter` | 0x5b1be3 | Matchmaking dungeon entry |
| `GuildDungeonEnter` | 0x5b1c50 | Guild dungeon entry |
| `GMDungeonEnter` | 0x5b1c72 | GM dungeon entry |
| `BloodlineDungeonEnter` | 0x5b1c2a | Bloodline dungeon entry |
| `ServerGroupDungeonEnter` | 0x5b1b98 | Cross-server dungeon entry |
| `ServerGroupDungeonExit` | 0x567022 | Cross-server dungeon exit |
| `BloodlineDungeonExit` | 0x567049 | Bloodline dungeon exit |
| `GMDungeonKicked` | 0x681fda | Kicked from GM dungeon |
| `TeleportUseFinishAnimation` | 0x5dced8 | Teleport with finish anim |
| `TeleportWithoutFade` | 0x663329 | Teleport without fade |
| `RemoveActor` | 0x5a7b35 | Actor removal (despawn) |

---

## 10. Architecture Summary

```
                     +---------------------------+
                     |   Netmarble GC2 (HTTPS)   |
                     |  Auth, Billing, Push, SDK  |
                     +---------------------------+
                               |
                     [accessToken, channelAccessToken]
                               |
    +------------------+       |        +----------------------------+
    | Netmarble GMC2   |       |        |    CrashSight (HTTPS)      |
    | /gmc2/v4/const.  |       |        |    Crash Reporting          |
    | Config, URLs     |       |        +----------------------------+
    +------------------+       |
          |                    |
    [LobbyServerAddr,         |
     LobbyServerPort,         |
     logUrl, NMP url]         |
          |                    |
          v                    v
    +-------------------------------------+
    |         LOBBY SERVER (TCP)           |
    |  PktLobbyVersion                     |
    |  PktLobbyLogin (gameToken, tokens)   |
    |  PktLobbyNetmarbleSSecurityVerify    |
    |  PktLobbyServerListRead              |
    |  PktLobbyCharacterListRead           |
    |  PktServerTransfer*                  |
    |  PktLogout                           |
    +-------------------------------------+
          |
    [server address from
     PktLobbyServerReadResult]
          |
          v
    +-------------------------------------+
    |        GAME SERVER (TCP/UDP)         |
    |  PktLogin                            |
    |  PktWorldMoveCast/Start/Finish       |
    |  PktServerExit                       |
    |  PktChatListReadToGameServer         |
    |  PktServerGroupDataNotify            |
    |  PktAppShopConnectNotify             |
    |  Game-specific packets               |
    +-------------------------------------+
          |
          |  (cross-server features)
          v
    +-------------------------------------+
    |        WORLD SERVER (TCP)            |
    |  PktChatListReadToWorldServer        |
    |  PktBroadCastSendWorldServer         |
    +-------------------------------------+
```

### Key Findings

1. **GMC2 is the bootstrap endpoint**: The client fetches `gmc2/v4/constants` first to get all
   runtime configuration including lobby server address, logging endpoints, and platform URLs.

2. **Three-environment model**: Production, Dev, and Alpha environments are selected by
   `ENMSDKZone` (Real/Dev/Alpha), which determines the `apis.netmarble.com` subdomain prefix.

3. **Three-tier server architecture**: Lobby Server (auth, server selection, character management),
   Game Server (gameplay), World Server (cross-server chat and broadcasts).

4. **Lobby server address is dynamic**: `LobbyServerAddr` and `LobbyServerPort` are runtime
   properties, not hardcoded. They come from the GMC2 constants or a subsequent configuration step.

5. **Token chain**: Netmarble SDK produces platform tokens (accessToken, channelAccessToken) which
   are exchanged for game tokens (NMGameToken) used for lobby server authentication. A SessionTicket
   maintains the active session with periodic refresh.

6. **Iris replication**: The game uses Unreal's experimental Iris replication system for its
   net driver, a newer approach compared to traditional UE replication, providing better
   scalability for MMO-style workloads.

7. **PacketDest.csv routing**: A data-driven packet routing table determines which server
   each packet type is sent to (Lobby, Game, or World server).

8. **Server Groups**: Servers are organized into ServerGroups (likely server clusters/regions),
   with features like cross-server dungeons, server transfers, and conquest battles operating
   across server group boundaries.
