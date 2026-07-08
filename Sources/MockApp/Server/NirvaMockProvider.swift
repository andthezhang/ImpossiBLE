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
/// - 0x000E LIST        → one or more 0x010E responses with "name,size\n"
///                        lines, then an empty 0x010E terminator.
/// - 0x000F SEND        → 0x010F `[totalSize u32 LE][chunkCount u32 LE]`
///                        (unknown file → [0][0]), then the file's raw DSS
///                        frames as notifications on the DSS characteristic.
/// - 0x0201 QUERY       → full 110-byte unified payload.
/// - 0x0202 SET/ACTION  → firmware-style mask dispatch. QUERY_LFS_FILES
///                        replies on legacy action cmd 0x0093; SEND_LC3_DUMP
///                        acks on 0x0202, emits a 0x010F send plan, then DSS
///                        frames for the oldest advertised synthetic file.
///
/// DSS frame (dss_frame.c): `[SeqID u16 LE][Ts u32 LE][DataType u8][Data][CRC16 LE]`
/// CRC16 = reflected CCITT, poly 0x8408, seed 0xFFFF, over header+data
/// (validated against tests/host/samples/dss_frame_sample_v1.json).
/// Types: 0x01 FILE_BEGIN, 0x02 LC3_DATA (`[0x01][lenL][L][0x02][lenR][R]`),
/// 0x03 FILE_END. Seq starts at 0 per file; totalSize = sum of wire bytes.
///
/// Live streaming uses 40-byte silence frames; sealed offline files use
/// 20-byte 16 kbps frames so Nirva's offline WAV decoder can drain them.
enum NirvaMockProvider {

    static let cmsServiceUUID = "A7D42000-5E2B-4C91-9F3A-8B27D6E14A90"
    static let cmsCmdCharUUID = "A7D42001-5E2B-4C91-9F3A-8B27D6E14A90"
    static let cmsRspCharUUID = "A7D42002-5E2B-4C91-9F3A-8B27D6E14A90"
    static let dssServiceUUID = "A7D41000-5E2B-4C91-9F3A-8B27D6E14A90"
    static let dssDataCharUUID = "A7D41001-5E2B-4C91-9F3A-8B27D6E14A90"
    static let dssCodecCharUUID = "A7D41002-5E2B-4C91-9F3A-8B27D6E14A90"

    /// One packet per 10 ms, alternating left/right tags — matches the
    /// firmware's per-channel 20 ms cadence.
    static let streamIntervalMs = 10
    private static let unifiedPayloadSize = 110
    private static let moduleStatusOffset = 88

    struct WriteResult {
        var responses: [Data] = []
        var setStreaming: Bool?
        /// Raw DSS frames to notify on the DSS data characteristic (offline
        /// file drain after a 0x000F SEND).
        var dssFrames: [Data] = []
    }

    // MARK: - Synthetic offline files

    struct SyntheticFile {
        let name: String
        let frames: [Data]
        var totalSize: UInt32 { UInt32(frames.reduce(0) { $0 + $1.count }) }
        var chunkCount: UInt32 { UInt32(frames.count) }
    }

    /// Two small offline recordings, epochs a few minutes in the past so the
    /// app's oldest-first cursor and capturedAt mapping are exercised.
    /// Regenerated per process launch.
    static let syntheticFiles: [SyntheticFile] = {
        let now = UInt32(Date().timeIntervalSince1970)
        return [
            makeSyntheticFile(epoch: now - 600, lc3FrameCount: 25),
            makeSyntheticFile(epoch: now - 300, lc3FrameCount: 25),
        ]
    }()

    static func makeSyntheticFile(epoch: UInt32, lc3FrameCount: Int) -> SyntheticFile {
        var frames: [Data] = []
        var seq: UInt16 = 0
        frames.append(dssFrame(seq: seq, ts: epoch, type: 0x01, data: []))  // FILE_BEGIN
        for i in 0..<lc3FrameCount {
            // Real liblc3-encoded silence frames so the app's WAV decode is
            // clean; tone frames would also work but silence matches the
            // "quiet recording" fixture intent.
            let left = NirvaMockAudio.offlineSilenceFrames[(i * 2) % NirvaMockAudio.offlineSilenceFrames.count]
            let right = NirvaMockAudio.offlineSilenceFrames[(i * 2 + 1) % NirvaMockAudio.offlineSilenceFrames.count]
            var lc3Data: [UInt8] = [0x01, UInt8(left.count)]
            lc3Data.append(contentsOf: left)
            lc3Data.append(contentsOf: [0x02, UInt8(right.count)])
            lc3Data.append(contentsOf: right)
            seq &+= 1
            frames.append(dssFrame(seq: seq, ts: epoch, type: 0x02, data: lc3Data))
        }
        seq &+= 1
        frames.append(dssFrame(seq: seq, ts: epoch, type: 0x03, data: []))  // FILE_END
        return SyntheticFile(name: "lc3_\(epoch).bin", frames: frames)
    }

    static func dssFrame(seq: UInt16, ts: UInt32, type: UInt8, data: [UInt8]) -> Data {
        var frame: [UInt8] = [
            UInt8(seq & 0xFF), UInt8(seq >> 8),
            UInt8(ts & 0xFF), UInt8((ts >> 8) & 0xFF), UInt8((ts >> 16) & 0xFF), UInt8(ts >> 24),
            type,
        ]
        frame.append(contentsOf: data)
        let crc = crc16CCITT(frame)
        frame.append(UInt8(crc & 0xFF))
        frame.append(UInt8(crc >> 8))
        return Data(frame)
    }

    /// Reflected CRC16-CCITT (poly 0x8408, seed 0xFFFF) — matches Zephyr's
    /// crc16_ccitt used by dss_frame.c.
    static func crc16CCITT(_ bytes: [UInt8]) -> UInt16 {
        var crc: UInt16 = 0xFFFF
        for byte in bytes {
            crc ^= UInt16(byte)
            for _ in 0..<8 {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0x8408 : crc >> 1
            }
        }
        return crc
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
        case 0x000E: // GET_AUDIO_FILE_LIST → 0x010E pages + empty terminator
            let listing = syntheticFiles.map { "\($0.name),\($0.totalSize)\n" }.joined()
            result.responses.append(build(cmd: 0x010E, counter: counter, payload: Array(listing.utf8)))
            result.responses.append(build(cmd: 0x010E, counter: counter, payload: []))
        case 0x000F: // GET_AUDIO_FILE_DATA → 0x010F plan, then DSS frames
            let name = filename(from: payload)
            guard let file = syntheticFiles.first(where: { $0.name == name }) else {
                result.responses.append(build(cmd: 0x010F, counter: counter, payload: u32le(0) + u32le(0)))
                break
            }
            result.responses.append(
                build(cmd: 0x010F, counter: counter, payload: u32le(file.totalSize) + u32le(file.chunkCount))
            )
            result.dssFrames = file.frames
        case 0x0201: // NIRVA_QUERY_PARAMS → packed nirva_payload_t
            result.responses.append(build(cmd: cmd, counter: counter, payload: unifiedPayload()))
        case 0x0202: // NIRVA_SET_PARAMS → mask-triggered actions
            handleUnifiedAction(payload: payload, counter: counter, result: &result)
        default: // SYNC_TIME and the rest: firmware logs and stays silent
            break
        }
        return result
    }

    private static func handleUnifiedAction(payload: [UInt8], counter: UInt8, result: inout WriteResult) {
        var shouldAck = false
        if hasMask(payload, 2) { // SYS_DATE
            shouldAck = true
        }
        if hasMask(payload, 9) { // QUERY_LFS_FILES
            let listing = syntheticFiles.map { "\($0.name),\($0.totalSize)\n" }.joined()
            result.responses.append(build(cmd: 0x0093, counter: counter, payload: Array(listing.utf8)))
            shouldAck = true
        }
        if hasMask(payload, 11) { // START_LC3
            result.setStreaming = true
            shouldAck = true
        }
        if hasMask(payload, 12) { // STOP_LC3
            result.setStreaming = false
            shouldAck = true
        }
        if hasMask(payload, 13) { // SEND_LC3_DUMP
            result.responses.append(build(cmd: 0x0202, counter: counter, payload: [0x01]))
            appendSendPlanAndFrames(for: syntheticFiles.first, counter: counter, result: &result)
        }
        if hasMask(payload, 23) { // QUERY_FW_VER
            result.responses.append(build(cmd: 0x0202, counter: counter, payload: Array("1.1.1+8-impossible-mock".utf8)))
            shouldAck = true
        }
        if shouldAck {
            result.responses.append(build(cmd: 0x0202, counter: counter, payload: []))
        }
    }

    private static func appendSendPlanAndFrames(
        for file: SyntheticFile?,
        counter: UInt8,
        result: inout WriteResult
    ) {
        guard let file else {
            result.responses.append(build(cmd: 0x010F, counter: counter, payload: u32le(0) + u32le(0)))
            return
        }
        result.responses.append(
            build(cmd: 0x010F, counter: counter, payload: u32le(file.totalSize) + u32le(file.chunkCount))
        )
        result.dssFrames = file.frames
    }

    private static func hasMask(_ payload: [UInt8], _ bit: Int) -> Bool {
        let byteIndex = bit / 8
        guard payload.indices.contains(byteIndex) else { return false }
        return (payload[byteIndex] & UInt8(1 << (bit % 8))) != 0
    }

    private static func unifiedPayload() -> [UInt8] {
        var payload = [UInt8](repeating: 0, count: unifiedPayloadSize)
        for bit in 1...24 {
            payload[bit / 8] |= UInt8(1 << (bit % 8))
        }
        payload[moduleStatusOffset] = 1      // mic_is_open
        payload[moduleStatusOffset + 1] = 0  // lc3_is_streaming
        payload[moduleStatusOffset + 2] = 0  // record_is_writing
        return payload
    }

    /// Firmware copies the name up to ',', CR, LF, or NUL (cmd_handler.c
    /// copy_lc3_name_from_payload).
    private static func filename(from payload: [UInt8]) -> String {
        let terminators: Set<UInt8> = [0x2C, 0x0D, 0x0A, 0x00]
        let nameBytes = payload.prefix { !terminators.contains($0) }
        return String(decoding: nameBytes, as: UTF8.self)
    }

    private static func u32le(_ v: UInt32) -> [UInt8] {
        [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8(v >> 24)]
    }

    /// 0x0102 audio streaming packet for the DSS data characteristic.
    /// `lc3` is two concatenated 10 ms frames from `NirvaMockAudio`.
    static func audioPacket(counter: UInt8, leftChannel: Bool, lc3: Data) -> Data {
        var payload: [UInt8] = [leftChannel ? 0x01 : 0x02]
        payload.append(contentsOf: lc3)
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
