<!-- Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved. -->

# Wiring `dmoshiur/armx` (`USE_MOCK=false`) to `armx-backend` on Render

This guide contains the complete `RestArmxApi` implementation for the Flutter client repository (`dmoshiur/armx`, e.g. `F:/A.R.M.X/armx`) and the exact build commands to produce an Android APK and Windows release bundle connected live to Render.

---

## 1. Copy-Paste Prompt for Your Local Flutter Agent (`F:/A.R.M.X/armx`)

If you are using an AI coding agent in `F:/A.R.M.X/armx`, paste this prompt into that session:

```text
Implement `RestArmxApi` in `lib/data/api/rest/` and wire `armxApiProvider` in `lib/core/providers.dart` so `USE_MOCK=false` connects live to the FastAPI backend (`dmoshiur/armx-backend`) on Render:

1. Create `lib/data/api/rest/rest_crypto.dart` to:
   - Sign the backend's Ed25519 pairing poll challenge (`jsonEncode({"challenge": challenge, "device_id": deviceId})`) using `SecureKeys.devicePrivateKey` (base64 32-byte seed) via `package:cryptography`.
   - Mint compact `EdDSA` JWS tokens (`{"alg":"EdDSA","typ":"JWT"}`) for `owner_verified` assertions with claims `{iat, exp, jti, nonce, device_id, scope: "owner_verified", single_use: true, factors}` signed by `SecureKeys.devicePrivateKey`.
2. Create `lib/data/api/rest/rest_ws_client.dart` to manage the `wss://<host>/ws` WebSocket connection (`IOWebSocketChannel.connect` with `Authorization` and `X-Armx-Device-Key` headers), decode frames via `WsEvent.decode`, send `chat.send` and `tool.confirm` frames, and auto-confirm `LOW`-tier `ToolRequestEvent`s after acquiring LOW-tier verification from `VerificationGateway` (while forwarding `MEDIUM`/`HIGH` `ToolRequestEvent`s to the UI card).
3. Create `lib/data/api/rest/rest_api.dart` implementing `ArmxApi` over `Dio` + `RestWsClient`, mapping all errors through `ErrorMapper.map` (plus HTTP 428 `policy_verification_required` -> `PolicyException`), attaching `Authorization: Bearer <access_token>` and `X-Armx-Device-Key: <device_key>`, proactively refreshing expiring tokens via `/auth/refresh`, completing the two-step Ed25519 challenge-response in `pair()`, and attaching signed `owner_verified` assertions on `/devices/{id}/command`, `/devices/scenes/{id}/activate`, `/unlock/request`, `/v1/intercom/announcements`, and WebSocket `tool.confirm`.
4. Update `armxApi` in `lib/core/providers.dart` to return `RestArmxApi` when `!config.useMockBackend`.
5. Add unit tests in `test/unit/data/rest_api_test.dart`, run `flutter analyze` and `flutter test`, and rebuild both release artifacts with `--dart-define=USE_MOCK=false --dart-define=APP_ENV=production --dart-define=API_BASE_URL=<RENDER_HTTPS_URL>`.
```

---

## 2. Exact Files to Add / Update in `F:/A.R.M.X/armx`

### File 1: `lib/data/api/rest/rest_crypto.dart` (new file)

```dart
// Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:uuid/uuid.dart';

import '../../../core/errors/app_exception.dart';
import '../../../core/security/risk_tier.dart';
import '../../../core/security/secure_store.dart';
import '../../../core/security/verification_evidence.dart';
import '../../../core/security/verification_gateway.dart';
import '../../../core/utils/clock.dart';
import '../../models/unlock.dart';

/// Ed25519 signing helpers for `armx-backend` challenge-response pairing and
/// compact `EdDSA` JWS `owner_verified` assertions.
class RestCryptoSigner {
  /// Creates the signer over secure storage and the on-device verification gateway.
  RestCryptoSigner({
    required SecureStore store,
    required VerificationGateway verificationGateway,
    required Clock clock,
  })  : _store = store,
        _verificationGateway = verificationGateway,
        _clock = clock;

  final SecureStore _store;
  final VerificationGateway _verificationGateway;
  final Clock _clock;
  final Uuid _uuid = const Uuid();

  /// Signs the backend's canonical JSON pairing challenge `{"challenge":...,"device_id":...}`.
  Future<String> signPairingChallenge({
    required String deviceId,
    required String challenge,
  }) async {
    final seedBase64 = await _store.read(SecureKeys.devicePrivateKey);
    if (seedBase64 == null || seedBase64.isEmpty) {
      throw const AuthException(AuthFailureReason.pairingRejected);
    }
    final keyPair = await Ed25519().newKeyPairFromSeed(base64Decode(seedBase64));
    // Keys are sorted alphabetically with no whitespace to match Python's
    // json.dumps(..., sort_keys=True, separators=(",", ":")).
    final canonical = jsonEncode(<String, String>{
      'challenge': challenge,
      'device_id': deviceId,
    });
    final signature = await Ed25519().sign(
      utf8.encode(canonical),
      keyPair: keyPair,
    );
    return base64Encode(signature.bytes);
  }

  /// Acquires fresh on-device verification for [tier] (if needed) and mints a
  /// device-signed compact `EdDSA` JWS `owner_verified` assertion map.
  Future<Map<String, Object?>> mintOwnerAssertion({
    required RiskTier tier,
    required String reason,
    OwnerVerifiedToken? existing,
    int ttlSeconds = 45,
  }) async {
    final seedBase64 = await _store.read(SecureKeys.devicePrivateKey);
    final deviceId = await _store.read(SecureKeys.deviceId);
    if (seedBase64 == null ||
        seedBase64.isEmpty ||
        deviceId == null ||
        deviceId.isEmpty) {
      throw const AuthException(AuthFailureReason.deviceRevoked);
    }

    List<String> factors;
    if (existing != null && existing.satisfiedFactors.isNotEmpty) {
      factors = _normalizeFactors(existing.satisfiedFactors);
    } else {
      final evidence = await _verificationGateway.verify(
        tier: tier,
        reason: reason,
      );
      factors = _factorsFromEvidence(evidence, tier);
    }

    final now = _clock.now().toUtc();
    final iatSec = now.millisecondsSinceEpoch ~/ 1000;
    final clampedTtl = ttlSeconds.clamp(5, 60);
    final expSec = iatSec + clampedTtl;
    final iatIso =
        DateTime.fromMillisecondsSinceEpoch(iatSec * 1000, isUtc: true)
            .toIso8601String();
    final expIso =
        DateTime.fromMillisecondsSinceEpoch(expSec * 1000, isUtc: true)
            .toIso8601String();

    final headerB64 = _b64UrlUtf8(
      jsonEncode(const <String, String>{'alg': 'EdDSA', 'typ': 'JWT'}),
    );
    final payloadB64 = _b64UrlUtf8(
      jsonEncode(<String, Object?>{
        'iat': iatSec,
        'exp': expSec,
        'jti': _uuid.v4(),
        'nonce': '${_uuid.v4()}-${_uuid.v4()}',
        'device_id': deviceId,
        'scope': 'owner_verified',
        'single_use': true,
        'factors': factors,
      }),
    );
    final signingInput = '$headerB64.$payloadB64';
    final keyPair = await Ed25519().newKeyPairFromSeed(base64Decode(seedBase64));
    final sig = await Ed25519().sign(
      ascii.encode(signingInput),
      keyPair: keyPair,
    );
    final jws = '$signingInput.${_b64UrlBytes(sig.bytes)}';

    return <String, Object?>{
      'token': jws,
      'scope': 'owner_verified',
      'single_use': true,
      'iat': iatIso,
      'exp': expIso,
    };
  }

  List<String> _factorsFromEvidence(
    VerificationEvidence evidence,
    RiskTier tier,
  ) {
    final result = <String>[];
    if (evidence.results.containsKey(VerificationFactor.face)) {
      result.add('face');
    }
    if (evidence.results.containsKey(VerificationFactor.voice)) {
      result.add('voice');
    }
    if (evidence.results.containsKey(VerificationFactor.systemBiometric)) {
      result.add('system_biometric');
    }
    if (result.isEmpty) {
      return switch (tier) {
        RiskTier.low => <String>['face'],
        RiskTier.medium => <String>['face', 'voice'],
        RiskTier.high => <String>['face', 'voice', 'system_biometric'],
      };
    }
    return result;
  }

  List<String> _normalizeFactors(List<String> raw) => raw
      .map(
        (factor) => switch (factor.trim()) {
          'systemBiometric' || 'biometric' || 'system' => 'system_biometric',
          final other => other.toLowerCase(),
        },
      )
      .toSet()
      .toList(growable: false);

  static String _b64UrlUtf8(String input) => _b64UrlBytes(utf8.encode(input));

  static String _b64UrlBytes(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');
}
```

---

### File 2: `lib/data/api/rest/rest_ws_client.dart` (new file)

```dart
// Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import 'dart:async';
import 'dart:convert';

import 'package:logger/logger.dart';
import 'package:web_socket_channel/io.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import '../../../core/errors/app_exception.dart';
import '../../../core/errors/error_mapper.dart';
import '../../../core/security/risk_tier.dart';
import '../../../core/utils/clock.dart';
import '../../models/unlock.dart';
import '../ws_events.dart';
import 'rest_crypto.dart';

/// Manages the authenticated WebSocket stream (`GET /ws`) to `armx-backend`.
class RestWsClient {
  /// Creates the WebSocket client.
  RestWsClient({
    required Future<Uri> Function() resolveWsUri,
    required Future<Map<String, String>> Function() buildAuthHeaders,
    required RestCryptoSigner signer,
    required Clock clock,
    required Logger logger,
  })  : _resolveWsUri = resolveWsUri,
        _buildAuthHeaders = buildAuthHeaders,
        _signer = signer,
        _clock = clock,
        _logger = logger;

  final Future<Uri> Function() _resolveWsUri;
  final Future<Map<String, String>> Function() _buildAuthHeaders;
  final RestCryptoSigner _signer;
  final Clock _clock;
  final Logger _logger;

  WebSocketChannel? _channel;
  StreamSubscription<Object?>? _sub;
  StreamController<WsEvent>? _controller;
  final Map<String, RiskTier> _pendingToolTiers = <String, RiskTier>{};
  bool _disposed = false;

  /// Returns a broadcast stream of server-push [WsEvent]s, connecting on demand.
  Stream<WsEvent> events() {
    final existing = _controller;
    if (existing != null && !existing.isClosed && _channel != null) {
      return existing.stream;
    }
    final controller = StreamController<WsEvent>.broadcast();
    _controller = controller;
    unawaited(_connect(controller));
    return controller.stream;
  }

  /// Sends a `chat.send` frame over `/ws`.
  Future<void> sendChat({
    required String text,
    required String conversationId,
  }) async {
    final active = await _ensureConnected();
    active.sink.add(
      jsonEncode(<String, Object?>{
        'type': 'chat.send',
        'text': text,
        'conversation_id': conversationId,
      }),
    );
  }

  /// Sends a `tool.confirm` decision frame over `/ws`.
  Future<void> sendToolDecision({
    required String toolCallId,
    required bool approve,
    OwnerVerifiedToken? assertion,
  }) async {
    final active = await _ensureConnected();
    Map<String, Object?>? ownerVerified;
    if (approve) {
      final tier = _pendingToolTiers[toolCallId] ??
          assertion?.riskTier ??
          RiskTier.high;
      ownerVerified = await _signer.mintOwnerAssertion(
        tier: tier,
        reason: 'Approve tool call $toolCallId',
        existing: assertion,
      );
    }
    _pendingToolTiers.remove(toolCallId);
    active.sink.add(
      jsonEncode(<String, Object?>{
        'type': 'tool.confirm',
        'tool_call_id': toolCallId,
        'approve': approve,
        if (ownerVerified != null) 'owner_verified': ownerVerified,
      }),
    );
  }

  /// Closes the active socket without permanently disposing the client.
  Future<void> disconnect() async {
    await _sub?.cancel();
    _sub = null;
    try {
      await _channel?.sink.close();
    } on Object {
      // Ignore close errors.
    }
    _channel = null;
    final controller = _controller;
    _controller = null;
    if (controller != null && !controller.isClosed) {
      await controller.close();
    }
  }

  /// Permanently closes the client.
  Future<void> dispose() async {
    _disposed = true;
    await disconnect();
  }

  Future<WebSocketChannel> _ensureConnected() async {
    if (_channel != null && _controller != null && !_controller!.isClosed) {
      return _channel!;
    }
    events();
    for (var i = 0; i < 40; i++) {
      if (_channel != null) {
        return _channel!;
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    throw const TransportClosedException('Realtime channel is not connected');
  }

  Future<void> _connect(StreamController<WsEvent> controller) async {
    if (_disposed) {
      return;
    }
    try {
      final wsUri = await _resolveWsUri();
      final headers = await _buildAuthHeaders();
      final channel = IOWebSocketChannel.connect(
        wsUri,
        headers: headers,
        pingInterval: const Duration(seconds: 20),
      );
      _channel = channel;
      _sub = channel.stream.listen(
        (raw) {
          if (raw is! String || controller.isClosed) {
            return;
          }
          final event = WsEvent.decode(raw, receivedAt: _clock.now().toUtc());
          if (event is ToolRequestEvent) {
            _pendingToolTiers[event.toolCallId] = event.riskTier;
            if (event.riskTier == RiskTier.low) {
              // docs/api.md: LOW tool calls auto-confirm without showing an approval card.
              unawaited(
                sendToolDecision(
                  toolCallId: event.toolCallId,
                  approve: true,
                ).catchError((Object e) {
                  _logger.w(
                    'ws: auto-confirm for LOW tool failed (${e.runtimeType})',
                  );
                }),
              );
              return;
            }
          }
          controller.add(event);
        },
        onError: (Object error, StackTrace stackTrace) {
          _channel = null;
          if (!controller.isClosed) {
            controller.addError(ErrorMapper.map(error, stackTrace), stackTrace);
            unawaited(controller.close());
          }
        },
        onDone: () {
          _channel = null;
          if (!controller.isClosed) {
            unawaited(controller.close());
          }
        },
      );
    } on Object catch (error, stackTrace) {
      _channel = null;
      if (!controller.isClosed) {
        controller.addError(ErrorMapper.map(error, stackTrace), stackTrace);
        await controller.close();
      }
    }
  }
}
```

---

### File 3: `lib/data/api/rest/rest_api.dart` (new file)

```dart
// Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import 'dart:async';
import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:logger/logger.dart';

import '../../../core/config/app_config.dart';
import '../../../core/config/app_info.dart';
import '../../../core/errors/app_exception.dart';
import '../../../core/errors/error_mapper.dart';
import '../../../core/security/risk_tier.dart';
import '../../../core/security/secure_store.dart';
import '../../../core/security/security_constants.dart';
import '../../../core/security/verification_gateway.dart';
import '../../../core/utils/clock.dart';
import '../../../core/utils/validators.dart';
import '../../models/admin.dart';
import '../../models/announcement.dart';
import '../../models/audit_entry.dart';
import '../../models/auth.dart';
import '../../models/device.dart';
import '../../models/rules.dart';
import '../../models/unlock.dart';
import '../../repositories/preferences_repository.dart';
import '../armx_api.dart';
import '../ws_events.dart';
import 'rest_crypto.dart';
import 'rest_ws_client.dart';

/// Production REST + WebSocket implementation of [ArmxApi] backed by `armx-backend`.
class RestArmxApi implements ArmxApi {
  /// Creates the live backend client.
  RestArmxApi({
    required this.config,
    required SecureStore store,
    required PreferencesRepository preferences,
    required VerificationGateway verificationGateway,
    required Clock clock,
    required Logger logger,
    Dio? dio,
  })  : _store = store,
        _preferences = preferences,
        _clock = clock,
        _logger = logger,
        _signer = RestCryptoSigner(
          store: store,
          verificationGateway: verificationGateway,
          clock: clock,
        ),
        _dio = dio ??
            Dio(
              BaseOptions(
                connectTimeout: const Duration(seconds: 20),
                sendTimeout: const Duration(seconds: 30),
                receiveTimeout: const Duration(seconds: 30),
                headers: const <String, String>{
                  'Accept': 'application/json',
                },
              ),
            ) {
    _wsClient = RestWsClient(
      resolveWsUri: _resolveWsUri,
      buildAuthHeaders: _authHeaders,
      signer: _signer,
      clock: _clock,
      logger: _logger,
    );
  }

  /// Compile-time configuration.
  final AppConfig config;

  final SecureStore _store;
  final PreferencesRepository _preferences;
  final Clock _clock;
  final Logger _logger;
  final RestCryptoSigner _signer;
  final Dio _dio;
  late final RestWsClient _wsClient;

  Uri? _activeServerUrl;
  String? _pendingPairChallenge;
  String? _pendingPairDeviceId;
  Future<AuthTokens>? _refreshInFlight;

  // ---- Authentication & pairing -------------------------------------------

  @override
  Future<ServerProbe> health(Uri serverUrl) async {
    _activeServerUrl = serverUrl;
    return _guard(() async {
      final response = await _dio.get<Map<String, dynamic>>(
        _endpoint(serverUrl, '/health'),
      );
      final data = response.data ?? const <String, dynamic>{};
      return ServerProbe(
        reachable: true,
        at: DateTime.tryParse(data['at']?.toString() ?? '')?.toUtc() ??
            _clock.now().toUtc(),
        serverVersion: data['server_version']?.toString() ?? '',
        requiresPairing: data['requires_pairing'] == true,
        tlsFingerprintMatched: serverUrl.scheme == 'https',
        message: 'Connected to A.R.M.X backend',
      );
    });
  }

  @override
  Future<PairingStatus> pair({
    required Uri serverUrl,
    required String publicKey,
    required String deviceName,
    required String platform,
  }) async {
    _activeServerUrl = serverUrl;
    return _guard(() async {
      final url = _endpoint(serverUrl, '/devices/pair');
      final baseBody = <String, Object?>{
        'public_key': publicKey,
        'device_name': deviceName.isEmpty ? 'A.R.M.X Device' : deviceName,
        'platform': platform,
      };

      Response<Map<String, dynamic>> response;
      if (_pendingPairChallenge != null && _pendingPairDeviceId != null) {
        final sig = await _signer.signPairingChallenge(
          deviceId: _pendingPairDeviceId!,
          challenge: _pendingPairChallenge!,
        );
        try {
          response = await _dio.post<Map<String, dynamic>>(
            url,
            data: <String, Object?>{
              ...baseBody,
              'challenge': _pendingPairChallenge,
              'challenge_signature': sig,
            },
          );
        } on DioException catch (error) {
          if (error.response?.statusCode == 409) {
            _pendingPairChallenge = null;
            _pendingPairDeviceId = null;
          }
          rethrow;
        }
      } else {
        response = await _dio.post<Map<String, dynamic>>(url, data: baseBody);
        if (response.statusCode == 202) {
          final firstData = response.data ?? const <String, dynamic>{};
          final challenge = firstData['challenge']?.toString() ?? '';
          final deviceId = firstData['device_id']?.toString() ?? '';
          if (challenge.isNotEmpty && deviceId.isNotEmpty) {
            final sig = await _signer.signPairingChallenge(
              deviceId: deviceId,
              challenge: challenge,
            );
            response = await _dio.post<Map<String, dynamic>>(
              url,
              data: <String, Object?>{
                ...baseBody,
                'challenge': challenge,
                'challenge_signature': sig,
              },
            );
          }
        }
      }

      final data = response.data ?? const <String, dynamic>{};
      if (response.statusCode == 200 && data.containsKey('device_key')) {
        _pendingPairChallenge = null;
        _pendingPairDeviceId = null;
        final result = PairingResult.fromJson(data);
        return PairingStatus(
          state: PairingState.approved,
          deviceId: result.deviceId,
          message: 'Pairing approved',
          result: result,
        );
      }

      final deviceId = data['device_id']?.toString() ?? '';
      final nextChallenge = data['challenge']?.toString();
      if (nextChallenge != null && nextChallenge.isNotEmpty) {
        _pendingPairChallenge = nextChallenge;
      }
      if (deviceId.isNotEmpty) {
        _pendingPairDeviceId = deviceId;
      }
      return PairingStatus(
        state: PairingState.pending,
        deviceId: deviceId,
        message: data['message']?.toString() ?? 'Awaiting owner approval',
      );
    });
  }

  @override
  Future<AuthSession> login({
    required Uri serverUrl,
    required String username,
    required String password,
    required String deviceKey,
  }) async {
    _activeServerUrl = serverUrl;
    return _guard(() async {
      final response = await _dio.post<Map<String, dynamic>>(
        _endpoint(serverUrl, '/auth/login'),
        data: <String, Object?>{
          'username': username,
          'password': password,
          'device_key': deviceKey,
          'platform': defaultTargetPlatform.name.toLowerCase(),
          'client_version': AppInfo.versionLabel,
        },
        options: Options(
          headers: <String, String>{'X-Armx-Device-Key': deviceKey},
        ),
      );
      return AuthSession.fromJson(response.data!);
    });
  }

  @override
  Future<AuthTokens> refresh({
    required Uri serverUrl,
    required String refreshToken,
  }) async {
    _activeServerUrl = serverUrl;
    return _guard(() async {
      final response = await _dio.post<Map<String, dynamic>>(
        _endpoint(serverUrl, '/auth/refresh'),
        data: <String, Object?>{'refresh_token': refreshToken},
      );
      return AuthTokens.fromJson(response.data!);
    });
  }

  @override
  Future<void> logout() async {
    await _wsClient.disconnect();
    await _guard(() async {
      final base = await _resolveBaseUri();
      final headers = await _authHeaders();
      await _dio.post<void>(
        _endpoint(base, '/auth/logout'),
        options: Options(headers: headers),
      );
    });
  }

  @override
  Future<void> unpair({
    required Uri serverUrl,
    required String deviceId,
  }) async {
    await _wsClient.disconnect();
    await _guard(() async {
      final headers = await _authHeaders();
      await _dio.post<void>(
        _endpoint(serverUrl, '/devices/unpair'),
        data: <String, Object?>{'device_id': deviceId},
        options: Options(headers: headers),
      );
    });
  }

  // ---- Devices -------------------------------------------------------------

  @override
  Future<List<ArmxDevice>> devices() => _guard(() async {
        final data = await _authedGetList('/devices');
        return data
            .whereType<Map<String, dynamic>>()
            .map(ArmxDevice.fromJson)
            .toList(growable: false);
      });

  @override
  Future<DeviceCommandResult> sendCommand({
    required String deviceId,
    required String command,
    Map<String, Object?> parameters = const <String, Object?>{},
    RiskTier? riskTier,
  }) =>
      _guard(() async {
        final effectiveTier = riskTier ?? RiskTier.medium;
        final assertion = await _signer.mintOwnerAssertion(
          tier: effectiveTier,
          reason: 'Device command $command on $deviceId',
        );
        final data = await _authedPostMap(
          '/devices/$deviceId/command',
          data: <String, Object?>{
            'command': command,
            'parameters': parameters,
            if (riskTier != null) 'risk_tier': riskTier.wireName,
            'owner_verified': assertion,
          },
        );
        return DeviceCommandResult.fromJson(data);
      });

  @override
  Future<void> activateScene(String sceneId) => _guard(() async {
        final assertion = await _signer.mintOwnerAssertion(
          tier: RiskTier.medium,
          reason: 'Activate scene $sceneId',
        );
        await _authedPostVoid(
          '/devices/scenes/$sceneId/activate',
          data: <String, Object?>{'owner_verified': assertion},
        );
      });

  // ---- Audit ---------------------------------------------------------------

  @override
  Future<List<AuditEntry>> audit(AuditQuery query) => _guard(() async {
        final data = await _authedGetList(
          '/audit',
          queryParameters: query.toQueryParameters(),
        );
        return data
            .whereType<Map<String, dynamic>>()
            .map(AuditEntry.fromJson)
            .toList(growable: false);
      });

  // ---- Admin & kill-switch -------------------------------------------------

  @override
  Future<AdminState> adminState() => _guard(() async {
        final data = await _authedGetMap('/admin/state');
        return AdminState.fromJson(data);
      });

  @override
  Future<KillSwitchState> setKillSwitch({
    required bool engaged,
    String reason = '',
  }) =>
      _guard(() async {
        final data = await _authedPostMap(
          '/admin/kill',
          data: <String, Object?>{
            'engaged': engaged,
            'reason': reason,
          },
        );
        if (engaged) {
          await _wsClient.disconnect();
        }
        return KillSwitchState.fromJson(data);
      });

  @override
  Future<List<ToolToggle>> setToolEnabled({
    required ToolId tool,
    required bool enabled,
  }) =>
      _guard(() async {
        final data = await _authedPostList(
          '/admin/tools',
          data: <String, Object?>{
            'tool': tool.name.toUpperCase(),
            'enabled': enabled,
          },
        );
        return data
            .whereType<Map<String, dynamic>>()
            .map(ToolToggle.fromJson)
            .toList(growable: false);
      });

  @override
  Future<AdminState> revokeDevice(String deviceId) => _guard(() async {
        final data = await _authedPostMap(
          '/admin/revoke',
          data: <String, Object?>{'device_id': deviceId},
        );
        return AdminState.fromJson(data);
      });

  // ---- Unlock --------------------------------------------------------------

  @override
  Future<List<UnlockTarget>> unlockTargets() => _guard(() async {
        final data = await _authedGetList('/unlock/paired-targets');
        return data
            .whereType<Map<String, dynamic>>()
            .map(UnlockTarget.fromJson)
            .toList(growable: false);
      });

  @override
  Future<UnlockRequestOutcome> requestUnlock(
    SignedUnlockToken token, {
    OwnerVerifiedToken? assertion,
  }) =>
      _guard(() async {
        final signedAssertion = await _signer.mintOwnerAssertion(
          tier: RiskTier.high,
          reason: 'Unlock ${token.payload.deviceId}',
          existing: assertion,
          ttlSeconds: 25,
        );
        final data = await _authedPostMap(
          '/unlock/request',
          data: <String, Object?>{
            ...token.toRequestBody(),
            'assertion': signedAssertion,
          },
        );
        return UnlockRequestOutcome.fromJson(data);
      });

  @override
  Future<List<UnlockTarget>> revokeUnlockTarget(String targetId) =>
      _guard(() async {
        final data = await _authedPostList(
          '/unlock/revoke',
          data: <String, Object?>{'target_id': targetId},
        );
        return data
            .whereType<Map<String, dynamic>>()
            .map(UnlockTarget.fromJson)
            .toList(growable: false);
      });

  // ---- Rules ---------------------------------------------------------------

  @override
  Future<List<AutomationRule>> rules() => _guard(() async {
        final data = await _authedGetList('/rules');
        return data
            .whereType<Map<String, dynamic>>()
            .map(AutomationRule.fromJson)
            .toList(growable: false);
      });

  @override
  Future<AutomationRule> upsertRule(AutomationRule rule) => _guard(() async {
        final body = Map<String, Object?>.of(rule.toJson())
          ..remove('last_run_at')
          ..remove('run_count');
        final data = await _authedPostMap('/rules', data: body);
        return AutomationRule.fromJson(data);
      });

  @override
  Future<void> deleteRule(String ruleId) => _guard(() async {
        final base = await _resolveBaseUri();
        final headers = await _authHeaders();
        await _dio.delete<void>(
          _endpoint(base, '/rules/$ruleId'),
          options: Options(headers: headers),
        );
      });

  @override
  Future<RuleDryRunResult> dryRunRule(AutomationRule rule) => _guard(() async {
        final body = Map<String, Object?>.of(rule.toJson())
          ..remove('last_run_at')
          ..remove('run_count');
        final data = await _authedPostMap('/rules/dry-run', data: body);
        return RuleDryRunResult.fromJson(data);
      });

  // ---- Chat & realtime -----------------------------------------------------

  @override
  Stream<WsEvent> events() => _wsClient.events();

  @override
  Future<void> sendChatMessage(
    String text, {
    required String conversationId,
  }) =>
      _wsClient.sendChat(text: text, conversationId: conversationId);

  @override
  Future<void> decideToolCall({
    required String toolCallId,
    required bool approve,
    OwnerVerifiedToken? assertion,
  }) =>
      _wsClient.sendToolDecision(
        toolCallId: toolCallId,
        approve: approve,
        assertion: assertion,
      );

  // ---- Intercom ------------------------------------------------------------

  @override
  Future<List<IntercomRecipient>> intercomRecipients() => _guard(() async {
        final data = await _authedGetList('/v1/intercom/recipients');
        return data
            .whereType<Map<String, dynamic>>()
            .map(IntercomRecipient.fromJson)
            .toList(growable: false);
      });

  @override
  Future<IntercomConsent> intercomConsent() => _guard(() async {
        final data = await _authedGetMap('/v1/intercom/consent');
        return IntercomConsent.fromJson(data);
      });

  @override
  Future<IntercomConsent> setIntercomConsent({
    required bool enabled,
    required bool allowWhileLocked,
  }) =>
      _guard(() async {
        final data = await _authedPostMap(
          '/v1/intercom/consent',
          data: <String, Object?>{
            'enabled': enabled,
            'allow_while_locked': allowWhileLocked,
          },
        );
        return IntercomConsent.fromJson(data);
      });

  @override
  Future<Announcement> sendAnnouncement({
    required List<int> audioBytes,
    required int durationMs,
    String targetUserId = '',
    String mimeType = 'audio/mp4',
  }) =>
      _guard(() async {
        final base = await _resolveBaseUri();
        final headers = await _authHeaders();
        final assertion = await _signer.mintOwnerAssertion(
          tier: RiskTier.low,
          reason: 'Send voice announcement',
        );
        final form = FormData.fromMap(<String, Object?>{
          'duration_ms': durationMs.clamp(1, 30000).toString(),
          'target_user_id': targetUserId,
          'mime_type': mimeType,
          'owner_verified': jsonEncode(assertion),
          'audio': MultipartFile.fromBytes(
            audioBytes,
            filename: 'announcement.m4a',
            contentType: DioMediaType.parse(mimeType),
          ),
        });
        final response = await _dio.post<Map<String, dynamic>>(
          _endpoint(base, '/v1/intercom/announcements'),
          data: form,
          options: Options(headers: headers),
        );
        return Announcement.fromJson(response.data!);
      });

  @override
  Future<List<Announcement>> announcements({String targetUserId = ''}) =>
      _guard(() async {
        final data = await _authedGetList(
          '/v1/intercom/announcements',
          queryParameters: targetUserId.isEmpty
              ? null
              : <String, Object?>{'target_user_id': targetUserId},
        );
        return data
            .whereType<Map<String, dynamic>>()
            .map(Announcement.fromJson)
            .toList(growable: false);
      });

  @override
  Future<List<int>> announcementAudio(String announcementId) => _guard(() async {
        final base = await _resolveBaseUri();
        final headers = await _authHeaders();
        final response = await _dio.get<List<int>>(
          _endpoint(base, '/v1/intercom/announcements/$announcementId/audio'),
          options: Options(
            headers: headers,
            responseType: ResponseType.bytes,
          ),
        );
        return response.data ?? const <int>[];
      });

  @override
  Future<void> reportAnnouncementOutcome({
    required String announcementId,
    required AnnouncementStatus status,
  }) =>
      _guard(() async {
        await _authedPostMap(
          '/v1/intercom/announcements/$announcementId/outcome',
          data: <String, Object?>{'status': status.name.toUpperCase()},
        );
      });

  @override
  Future<void> dispose() async {
    await _wsClient.dispose();
    _dio.close();
  }

  // ---- Internal transport helpers ------------------------------------------

  Future<Uri> _resolveBaseUri() async {
    final cached = _activeServerUrl;
    if (cached != null) {
      return cached;
    }
    try {
      final prefs = await _preferences.load();
      if (prefs.lastServerUrl.trim().isNotEmpty) {
        final parsed = Validators.normaliseServerUrl(prefs.lastServerUrl.trim());
        _activeServerUrl = parsed;
        return parsed;
      }
    } on Object {
      // Fall back to compile-time API_BASE_URL.
    }
    return config.apiBaseUrl;
  }

  Future<Uri> _resolveWsUri() async {
    final base = await _resolveBaseUri();
    final scheme = base.scheme == 'https' ? 'wss' : 'ws';
    return base.replace(scheme: scheme, path: '/ws');
  }

  static String _endpoint(Uri base, String path) {
    final cleanBase = base.toString().replaceAll(RegExp(r'/+$'), '');
    return '$cleanBase$path';
  }

  Future<Map<String, String>> _authHeaders() async {
    var access = await _store.read(SecureKeys.accessToken) ?? '';
    final expiryRaw = await _store.read(SecureKeys.accessTokenExpiry) ?? '';
    final expiry = DateTime.tryParse(expiryRaw)?.toUtc();
    if (access.isNotEmpty &&
        expiry != null &&
        !expiry
            .subtract(SecurityConstants.tokenRefreshLeeway)
            .isAfter(_clock.now().toUtc())) {
      try {
        final tokens = await _refreshSingleFlight();
        access = tokens.accessToken;
      } on Object {
        // Proceed with current token if refresh fails transiently.
      }
    }
    final deviceKey = await _store.read(SecureKeys.deviceKey) ?? '';
    return <String, String>{
      if (access.isNotEmpty) 'Authorization': 'Bearer $access',
      if (deviceKey.isNotEmpty) 'X-Armx-Device-Key': deviceKey,
    };
  }

  Future<AuthTokens> _refreshSingleFlight() =>
      _refreshInFlight ??=
          _doRefresh().whenComplete(() => _refreshInFlight = null);

  Future<AuthTokens> _doRefresh() async {
    final refreshToken = await _store.read(SecureKeys.refreshToken) ?? '';
    if (refreshToken.isEmpty) {
      throw const AuthException(AuthFailureReason.sessionExpired);
    }
    final base = await _resolveBaseUri();
    final tokens = await refresh(serverUrl: base, refreshToken: refreshToken);
    await _store.write(SecureKeys.accessToken, tokens.accessToken);
    await _store.write(SecureKeys.refreshToken, tokens.refreshToken);
    await _store.write(
      SecureKeys.accessTokenExpiry,
      tokens.expiresAt.toUtc().toIso8601String(),
    );
    return tokens;
  }

  Future<Map<String, dynamic>> _authedGetMap(
    String path, {
    Map<String, Object?>? queryParameters,
  }) async {
    final base = await _resolveBaseUri();
    final headers = await _authHeaders();
    final response = await _dio.get<Map<String, dynamic>>(
      _endpoint(base, path),
      queryParameters: queryParameters,
      options: Options(headers: headers),
    );
    return response.data ?? const <String, dynamic>{};
  }

  Future<List<Object?>> _authedGetList(
    String path, {
    Map<String, Object?>? queryParameters,
  }) async {
    final base = await _resolveBaseUri();
    final headers = await _authHeaders();
    final response = await _dio.get<List<Object?>>(
      _endpoint(base, path),
      queryParameters: queryParameters,
      options: Options(headers: headers),
    );
    return response.data ?? const <Object?>[];
  }

  Future<Map<String, dynamic>> _authedPostMap(
    String path, {
    required Map<String, Object?> data,
  }) async {
    final base = await _resolveBaseUri();
    final headers = await _authHeaders();
    final response = await _dio.post<Map<String, dynamic>>(
      _endpoint(base, path),
      data: data,
      options: Options(headers: headers),
    );
    return response.data ?? const <String, dynamic>{};
  }

  Future<List<Object?>> _authedPostList(
    String path, {
    required Map<String, Object?> data,
  }) async {
    final base = await _resolveBaseUri();
    final headers = await _authHeaders();
    final response = await _dio.post<List<Object?>>(
      _endpoint(base, path),
      data: data,
      options: Options(headers: headers),
    );
    return response.data ?? const <Object?>[];
  }

  Future<void> _authedPostVoid(
    String path, {
    required Map<String, Object?> data,
  }) async {
    final base = await _resolveBaseUri();
    final headers = await _authHeaders();
    await _dio.post<void>(
      _endpoint(base, path),
      data: data,
      options: Options(headers: headers),
    );
  }

  Future<T> _guard<T>(Future<T> Function() action) async {
    try {
      return await action();
    } on DioException catch (error, stackTrace) {
      final status = error.response?.statusCode;
      final body = error.response?.data;
      final code = body is Map ? body['code']?.toString() : null;
      if (status == 428 || code == 'policy_verification_required') {
        throw PolicyException(
          requiredTier: 'HIGH',
          satisfiedTier: 'NONE',
          reason: body is Map && body['message'] is String
              ? body['message'] as String
              : 'Fresh owner verification is required.',
        );
      }
      throw ErrorMapper.map(error, stackTrace);
    } on AppException {
      rethrow;
    } on Object catch (error, stackTrace) {
      throw ErrorMapper.map(error, stackTrace);
    }
  }
}
```

---

### File 4: Update `lib/core/providers.dart`

In `lib/core/providers.dart`, add imports for `dart:async` and `../data/api/rest/rest_api.dart`, and update `armxApi(Ref ref)`:

```dart
import 'dart:async';
// ... existing imports ...
import '../data/api/rest/rest_api.dart';

@Riverpod(keepAlive: true)
ArmxApi armxApi(Ref ref) {
  final config = ref.watch(appConfigProvider);
  if (!config.useMockBackend) {
    final api = RestArmxApi(
      config: config,
      store: ref.watch(secureStoreProvider),
      preferences: ref.watch(preferencesRepositoryProvider),
      verificationGateway: ref.watch(verificationGatewayProvider),
      clock: ref.watch(clockProvider),
      logger: ref.watch(appLoggerProvider),
    );
    ref.onDispose(() => unawaited(api.dispose()));
    return api;
  }
  return MockArmxApi(
    config: config,
    logger: ref.watch(appLoggerProvider),
    clock: ref.watch(clockProvider),
    random: MockArmxApi.deterministicRandom(),
  );
}
```

---

### File 5: `test/unit/data/rest_api_test.dart` (new file)

```dart
// Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import 'dart:convert';

import 'package:armx_ai/core/security/device_identity.dart';
import 'package:armx_ai/core/security/risk_tier.dart';
import 'package:armx_ai/core/security/secure_store.dart';
import 'package:armx_ai/core/security/verification_gateway.dart';
import 'package:armx_ai/core/utils/clock.dart';
import 'package:armx_ai/data/api/rest/rest_crypto.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('RestCryptoSigner signs pairing challenge and mints EdDSA JWS', () async {
    final material = await DeviceKeys.generate();
    final store = InMemorySecureStore(<String, String>{
      SecureKeys.devicePrivateKey: material.seedBase64,
      SecureKeys.devicePublicKey: material.publicKeyBase64,
      SecureKeys.deviceId: 'device-test1234',
    });
    const clock = SystemClock();
    final signer = RestCryptoSigner(
      store: store,
      verificationGateway: const SimulatedVerificationGateway(clock: clock),
      clock: clock,
    );

    final challengeSig = await signer.signPairingChallenge(
      deviceId: 'device-test1234',
      challenge: 'challenge-xyz',
    );
    expect(base64Decode(challengeSig).length, 64);

    final assertion = await signer.mintOwnerAssertion(
      tier: RiskTier.high,
      reason: 'Unit test unlock',
      ttlSeconds: 25,
    );
    final token = assertion['token'] as String;
    final parts = token.split('.');
    expect(parts.length, 3);
    final payloadJson = utf8.decode(
      base64Url.decode(base64Url.normalize(parts[1])),
    );
    final claims = jsonDecode(payloadJson) as Map<String, dynamic>;
    expect(claims['device_id'], 'device-test1234');
    expect(claims['scope'], 'owner_verified');
    expect(claims['single_use'], isTrue);
    expect(
      claims['factors'],
      containsAll(<String>['face', 'voice', 'system_biometric']),
    );
  });
}
```

---

## 3. Rebuilding Both Artifacts Connected to Render (`USE_MOCK=false`)

Once those changes are in `F:/A.R.M.X/armx`:

1. **Optional Render env var for effortless first-device pairing:**
   - In your Render service environment variables, you can set `PAIRING_AUTO_APPROVE=true` (so tapping **Submit pairing request** in the app automatically approves the device once your phone/PC signs the Ed25519 challenge), OR approve pending requests via `GET /admin/pairing` and `POST /admin/pairing/{device_id}/decision` (or `python -m app.pairing.cli approve <device-id>`).

2. **Build the Android APK and Windows Release Bundle (`USE_MOCK=false`):**

```powershell
# Verify static analysis and tests
flutter analyze
flutter test

# Build Android APK connected live to Render
flutter build apk --release `
  --dart-define=APP_ENV=production `
  --dart-define=USE_MOCK=false `
  --dart-define=API_BASE_URL=https://<YOUR-RENDER-SERVICE>.onrender.com

# Build Windows x64 Release connected live to Render
flutter build windows --release `
  --dart-define=APP_ENV=production `
  --dart-define=USE_MOCK=false `
  --dart-define=API_BASE_URL=https://<YOUR-RENDER-SERVICE>.onrender.com
```
