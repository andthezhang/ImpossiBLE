import Foundation

/// Synthetic Nirva wearable (FF transport: CMS + DSS services) for mock mode.
///
/// Implements the minimal firmware command surface needed for the phone-side
/// connect handshake, validated against
/// `nirva_wearable_firmware-offline-file/src/ble_transport/cmd_handler.c`:
///
/// - Wire format (both directions): `[Cmd 2B LE][Len 2B LE][Counter 1B][Payload]`
/// - 0x0001 AUTH        → respond same cmd, same counter, ASCII "NIRVA"
/// - 0x0002 SW_VERSION  → respond version string
/// - 0x000B SYNC_TIME   → no response (firmware sends none)
/// - 0x0010 STREAMING   → data[0]==0x01 start / 0x00 stop, ack [0x01];
///                        streaming emits 0x0102 packets on the DSS data
///                        characteristic: `[02 01][len][ctr][tag][LC3 bytes]`,
///                        one global rolling counter reset to 0 on start,
///                        tag 0x01 = left mic, 0x02 = right mic.
///
/// ponytail: canned zero-filled "LC3" payloads — enough for connect/notify
/// assertions; swap in real LC3 frames when a test decodes audio.
enum NirvaMockProvider {

    static let cmsServiceUUID = "A7D42000-5E2B-4C91-9F3A-8B27D6E14A90"
    static let cmsCmdCharUUID = "A7D42001-5E2B-4C91-9F3A-8B27D6E14A90"
    static let cmsRspCharUUID = "A7D42002-5E2B-4C91-9F3A-8B27D6E14A90"
    static let dssServiceUUID = "A7D41000-5E2B-4C91-9F3A-8B27D6E14A90"
    static let dssDataCharUUID = "A7D41001-5E2B-4C91-9F3A-8B27D6E14A90"
    static let dssCodecCharUUID = "A7D41002-5E2B-4C91-9F3A-8B27D6E14A90"

    /// Two concatenated 10 ms LC3 frames per audio packet (firmware sends
    /// whole frames per notification; 40 B per frame at 16 kHz/32 kbps).
    static let lc3PayloadBytes = 80
    /// One packet per 10 ms, alternating left/right tags — matches the
    /// firmware's per-channel 20 ms cadence.
    static let streamIntervalMs = 10

    struct WriteResult {
        var responses: [Data] = []
        var setStreaming: Bool?
    }

    /// Process a write to the CMS command characteristic.
    static func handleCommand(_ packet: Data) -> WriteResult {
        var result = WriteResult()
        guard packet.count >= 5 else { return result }
        let bytes = [UInt8](packet)
        let cmd = UInt16(bytes[0]) | (UInt16(bytes[1]) << 8)
        let counter = bytes[4]
        let payload = bytes.count > 5 ? Array(bytes[5...]) : []

        switch cmd {
        case 0x0001: // AUTH — echo "NIRVA" with the request counter
            result.responses.append(build(cmd: cmd, counter: counter, payload: Array("NIRVA".utf8)))
        case 0x0002: // READ_SW_VERSION
            result.responses.append(build(cmd: cmd, counter: counter, payload: Array("v0.0.0-impossible-mock".utf8)))
        case 0x0010: // SET_AUDIO_STREAMING
            guard let enable = payload.first, enable == 0x00 || enable == 0x01 else { break }
            result.setStreaming = enable == 0x01
            result.responses.append(build(cmd: cmd, counter: counter, payload: [0x01]))
        default: // SYNC_TIME and the rest: firmware logs and stays silent
            break
        }
        return result
    }

    /// Canned 0x0102 audio streaming packet for the DSS data characteristic.
    static func audioPacket(counter: UInt8, leftChannel: Bool) -> Data {
        var payload: [UInt8] = [leftChannel ? 0x01 : 0x02]
        payload.append(contentsOf: [UInt8](repeating: 0, count: lc3PayloadBytes))
        return build(cmd: 0x0102, counter: counter, payload: payload)
    }

    private static func build(cmd: UInt16, counter: UInt8, payload: [UInt8]) -> Data {
        var packet: [UInt8] = [
            UInt8(cmd & 0xFF), UInt8(cmd >> 8),
            UInt8(payload.count & 0xFF), UInt8((payload.count >> 8) & 0xFF),
            counter,
        ]
        packet.append(contentsOf: payload)
        return Data(packet)
    }

    // MARK: - Device / configuration

    static func makeDevice() -> MockDevice {
        MockDevice(
            name: "Nirva Mock",
            rssi: -40,
            isConnectable: true,
            isEnabled: true,
            advertisedServiceUUIDs: [dssServiceUUID, cmsServiceUUID],
            services: [
                MockService(uuid: cmsServiceUUID, isPrimary: true, characteristics: [
                    MockCharacteristic(uuid: cmsCmdCharUUID, properties: 0x0C), // write + write w/o response
                    MockCharacteristic(
                        uuid: cmsRspCharUUID,
                        properties: 0x10, // notify
                        descriptors: [MockDescriptor(uuid: "2902", value: Data([0x00, 0x00]))]
                    ),
                ]),
                MockService(uuid: dssServiceUUID, isPrimary: true, characteristics: [
                    MockCharacteristic(
                        uuid: dssDataCharUUID,
                        properties: 0x10, // notify
                        descriptors: [MockDescriptor(uuid: "2902", value: Data([0x00, 0x00]))]
                    ),
                    MockCharacteristic(uuid: dssCodecCharUUID, properties: 0x02, value: Data([0x01])),
                ]),
            ]
        )
    }

    static let stockConfiguration = MockConfiguration(
        name: "Nirva Wearable (FF)",
        devices: [makeDevice()],
        isBuiltIn: true
    )
}

/// `ImpossiBLE-Mock --nirva-headless`: serve a single synthetic Nirva
/// wearable with no menu bar UI. For CI / zero-dongle simulator e2e.
enum NirvaHeadless {
    static func run() -> Never {
        let store = MockStore()
        store.devices = [NirvaMockProvider.makeDevice()]

        let server = MockServer(autoStart: false)
        server.store = store

        signal(SIGINT) { _ in exit(0) }
        signal(SIGTERM) { _ in exit(0) }

        server.start {
            NSLog("ImpossiBLE-Mock: nirva headless ready cms=%@ dss=%@",
                  NirvaMockProvider.cmsServiceUUID,
                  NirvaMockProvider.dssServiceUUID)
        }

        RunLoop.main.run()
        fatalError("RunLoop exited unexpectedly")
    }
}
