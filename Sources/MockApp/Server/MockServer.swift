import Foundation

// Overridable so tests can run against an isolated socket while a real
// provider owns /tmp/impossible.sock. The simulator client library always
// uses the default path.
private let kSocketPath = ProcessInfo.processInfo.environment["IMPOSSIBLE_MOCK_SOCKET"] ?? "/tmp/impossible.sock"

struct SocketClientInfo: Equatable {
    let pid: pid_t
    let processName: String

    var displayText: String {
        "\(processName) (PID \(pid))"
    }

    var messageSuffix: String {
        "pid=\(pid), process=\(processName)"
    }

    var wireValue: [String: Any] {
        [
            "pid": Int(pid),
            "processName": processName,
        ]
    }
}

struct MockNotificationFirehoseConfig {
    let hz: Double
    let payloadBytes: Int
    let maxFrames: Int
}

/// Socket server that implements the ImpossiBLE helper protocol with mock data.
/// Socket reads and protocol state run on `ioQueue`; socket writes run on
/// `writeQueue` so sustained notifications cannot block protocol handling.
final class MockServer: ObservableObject {
    enum Status: Equatable, Sendable {
        case stopped
        case listening
        case clientConnected
    }

    @Published var status: Status = .stopped
    @Published var lastActivity: String = ""
    @Published var trafficActive: Bool = false
    @Published private(set) var connectedClient: SocketClientInfo?
    @Published var connectedDeviceIDs: Set<String> = []
    @Published var pairedDeviceIDs: Set<String> = []

    private let ioQueue = DispatchQueue(label: "impossible.mock.io")
    private let writeQueue = DispatchQueue(label: "impossible.mock.write")
    private let traceNotifications = (ProcessInfo.processInfo.environment["IMPOSSIBLE_TRACE_NOTIFICATIONS"].map { $0 != "0" } ?? false)
        || FileManager.default.fileExists(atPath: "/tmp/impossible-trace-notifications")

    // Guarded by ioQueue
    private var serverFd: Int32 = -1
    private var clientFd: Int32 = -1
    private var clientInfo: SocketClientInfo?
    private var clientGeneration: UInt64 = 0
    private var acceptSource: DispatchSourceRead?
    private var readSource: DispatchSourceRead?
    private var readBuffer = Data()
    private var connectedPeripherals = Set<String>()
    private var pairedPeripherals = Set<String>()
    private var scanActive = false
    private var scanTimer: DispatchSourceTimer?
    private var writtenCharValues: [String: Data] = [:]
    private var writtenDescValues: [String: Data] = [:]
    private var notifyingCharacteristics = Set<String>()
    private var firehoseConfig: MockNotificationFirehoseConfig?
    private var firehoseTimers: [String: DispatchSourceTimer] = [:]
    private var firehoseSequences: [String: UInt64] = [:]
    private var nirvaStreamTimers: [String: DispatchSourceTimer] = [:]
    private var nirvaStreamCounters: [String: (counter: UInt8, leftChannel: Bool)] = [:]
    private var generatedNotificationCount: UInt64 = 0
    private var serializedNotificationCount: UInt64 = 0
    private var serializedNotificationBytes: UInt64 = 0
    private var lastNotificationTraceLog = CFAbsoluteTimeGetCurrent()

    // Guarded by writeQueue
    private var socketNotificationWriteCount: UInt64 = 0
    private var socketNotificationWriteBytes: UInt64 = 0
    private var lastSocketTraceLog = CFAbsoluteTimeGetCurrent()

    weak var store: MockStore?

    private static let serverEnabledKey = "ServerEnabled"

    init(autoStart: Bool = true) {
        if autoStart, UserDefaults.standard.bool(forKey: Self.serverEnabledKey) {
            start()
        }
    }

    func configureNotificationFirehose(_ config: MockNotificationFirehoseConfig?) {
        ioQueue.async { [self] in
            firehoseConfig = config
            if config == nil {
                stopAllFirehoses()
            }
        }
    }

    func start(completion: (() -> Void)? = nil) {
        UserDefaults.standard.set(true, forKey: Self.serverEnabledKey)
        ioQueue.async { [self] in
            defer {
                if let completion {
                    DispatchQueue.main.async(execute: completion)
                }
            }
            guard serverFd < 0 else { return }

            let fd = socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else {
                NSLog("ImpossiBLE-Mock: socket() failed")
                return
            }

            unlink(kSocketPath)

            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            let pathBytes = kSocketPath.utf8CString
            withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
                let raw = UnsafeMutableRawPointer(ptr)
                pathBytes.withUnsafeBufferPointer { buf in
                    raw.copyMemory(from: buf.baseAddress!, byteCount: min(buf.count, 104))
                }
            }

            let bindResult = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    bind(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard bindResult == 0 else {
                NSLog("ImpossiBLE-Mock: bind() failed: %d", errno)
                close(fd)
                return
            }

            guard listen(fd, 2) == 0 else {
                NSLog("ImpossiBLE-Mock: listen() failed")
                close(fd)
                return
            }

            serverFd = fd
            publishStatus(.listening)
            log("Listening")

            let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: ioQueue)
            source.setEventHandler { [weak self] in
                self?.acceptClient()
            }
            source.setCancelHandler {
                close(fd)
            }
            source.resume()
            acceptSource = source
        }
    }

    func stop(completion: (() -> Void)? = nil) {
        UserDefaults.standard.set(false, forKey: Self.serverEnabledKey)
        ioQueue.async { [self] in
            let hadServer = serverFd >= 0

            scanTimer?.cancel()
            scanTimer = nil
            scanActive = false

            readSource?.cancel()
            readSource = nil
            if clientFd >= 0 {
                close(clientFd)
                clientFd = -1
            }
            clientInfo = nil
            publishConnectedClient(nil)
            clientGeneration &+= 1

            acceptSource?.cancel()
            acceptSource = nil
            serverFd = -1

            if hadServer {
                unlink(kSocketPath)
            }

            connectedPeripherals.removeAll()
            pairedPeripherals.removeAll()
            writtenCharValues.removeAll()
            writtenDescValues.removeAll()
            notifyingCharacteristics.removeAll()
            stopAllFirehoses()
            stopAllNirvaStreams()
            readBuffer.removeAll()

            publishDeviceState()
            publishStatus(.stopped)
            log("Stopped")

            if let completion {
                DispatchQueue.main.async {
                    completion()
                }
            }
        }
    }

    // MARK: - Connection (called on ioQueue)

    private func acceptClient() {
        let fd = accept(serverFd, nil, nil)
        guard fd >= 0 else { return }

        if clientFd >= 0 {
            sendConnectionRejected(to: fd)
            close(fd)
            let suffix = clientInfo?.messageSuffix ?? "pid=0, process=unknown"
            log("Rejected additional client; active client \(suffix)")
            return
        }
        clientFd = fd
        clientInfo = peerClientInfo(for: fd)
        publishConnectedClient(clientInfo)
        clientGeneration &+= 1
        let generation = clientGeneration
        readBuffer.removeAll()
        connectedPeripherals.removeAll()
        pairedPeripherals.removeAll()
        writtenCharValues.removeAll()
        writtenDescValues.removeAll()
        notifyingCharacteristics.removeAll()
        stopAllFirehoses()
        stopAllNirvaStreams()
        scanActive = false
        scanTimer?.cancel()
        scanTimer = nil

        publishStatus(.clientConnected)
        let suffix = clientInfo?.messageSuffix ?? "pid=0, process=unknown"
        log("Client connected \(suffix)")

        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: ioQueue)
        source.setEventHandler { [weak self] in
            self?.readFromClient(fd: fd, generation: generation)
        }
        source.setCancelHandler { }
        source.resume()
        readSource = source
    }

    private func readFromClient(fd: Int32, generation: UInt64) {
        var buf = [UInt8](repeating: 0, count: 2048)
        let n = read(fd, &buf, buf.count)
        if n <= 0 {
            guard fd == clientFd, generation == clientGeneration else {
                return
            }
            readSource?.cancel()
            readSource = nil
            close(fd)
            clientFd = -1
            clientInfo = nil
            publishConnectedClient(nil)
            scanTimer?.cancel()
            scanTimer = nil
            scanActive = false
            connectedPeripherals.removeAll()
            pairedPeripherals.removeAll()
            notifyingCharacteristics.removeAll()
            stopAllFirehoses()
            stopAllNirvaStreams()

            publishDeviceState()
            publishStatus(.listening)
            log("Client disconnected")
            return
        }
        readBuffer.append(contentsOf: buf[0..<n])

        while let newlineIndex = readBuffer.firstIndex(of: UInt8(ascii: "\n")) {
            let lineData = readBuffer[readBuffer.startIndex..<newlineIndex]
            readBuffer.removeSubrange(readBuffer.startIndex...newlineIndex)
            if lineData.isEmpty { continue }
            if let msg = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any] {
                handleMessage(msg)
            }
        }
    }

    // MARK: - Send (called on ioQueue)

    private func send(_ msg: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: msg),
              clientFd >= 0 else { return }
        var payload = data
        payload.append(UInt8(ascii: "\n"))
        let fd = clientFd
        let generation = clientGeneration
        let type = msg["type"] as? String ?? ""
        if type == "didUpdateValue" {
            serializedNotificationCount &+= 1
            serializedNotificationBytes &+= UInt64(payload.count)
            traceNotificationStage(
                "serialization",
                count: serializedNotificationCount,
                bytes: serializedNotificationBytes
            )
        }
        enqueueWrite(payload, to: fd, generation: generation, type: type)
    }

    private func sendConnectionRejected(to fd: Int32) {
        let info = clientInfo
        let suffix = info?.messageSuffix ?? "pid=0, process=unknown"
        let msg: [String: Any] = [
            "type": "connectionRejected",
            "code": "clientBusy",
            "message": "another ImpossiBLE client is already connected (\(suffix))",
            "activeClient": info?.wireValue ?? [
                "pid": 0,
                "processName": "unknown",
            ],
            "retry": false,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: msg) else { return }
        var payload = data
        payload.append(UInt8(ascii: "\n"))
        writeBlocking(payload, to: fd)
    }

    private func enqueueWrite(_ payload: Data, to fd: Int32, generation: UInt64, type: String) {
        writeQueue.async { [weak self] in
            guard let self else { return }

            var isCurrentClient = false
            self.ioQueue.sync {
                isCurrentClient = self.clientFd == fd && self.clientGeneration == generation
            }
            guard isCurrentClient else { return }

            guard self.writeBlocking(payload, to: fd) else {
                self.ioQueue.async { [weak self] in
                    guard let self,
                          self.clientFd == fd,
                          self.clientGeneration == generation
                    else { return }
                    self.log("Client write failed")
                    self.readSource?.cancel()
                    self.readSource = nil
                    close(fd)
                    self.clientFd = -1
                    self.clientInfo = nil
                    self.publishConnectedClient(nil)
                    self.clientGeneration &+= 1
                    self.stopAllFirehoses()
                    self.stopAllNirvaStreams()
                    self.publishStatus(.listening)
                }
                return
            }

            if type == "didUpdateValue" {
                self.socketNotificationWriteCount &+= 1
                self.socketNotificationWriteBytes &+= UInt64(payload.count)
                self.traceSocketWriteStage()
            }
        }
    }

    @discardableResult
    private func writeBlocking(_ payload: Data, to fd: Int32) -> Bool {
        var ok = true
        payload.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            var written = 0
            while written < payload.count {
                let n = Darwin.write(fd, base.advanced(by: written), payload.count - written)
                if n < 0, errno == EINTR {
                    continue
                }
                if n <= 0 {
                    ok = false
                    break
                }
                written += n
            }
        }
        return ok
    }

    private func peerClientInfo(for fd: Int32) -> SocketClientInfo? {
        var pid = pid_t(0)
        var len = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0, pid > 0 else {
            return nil
        }

        var nameBuffer = [CChar](repeating: 0, count: 4096)
        let result = proc_name(pid, &nameBuffer, UInt32(nameBuffer.count))
        let processName = result > 0 ? String(cString: nameBuffer) : "unknown"
        return SocketClientInfo(pid: pid, processName: processName)
    }

    func terminateConnectedClient() {
        ioQueue.async { [self] in
            guard let pid = clientInfo?.pid, pid > 0 else { return }
            if Darwin.kill(pid, SIGTERM) == 0 {
                log("Terminating client pid=\(pid)")
            } else {
                log("Failed to terminate client pid=\(pid): errno \(errno)")
            }
        }
    }

    // MARK: - Protocol Handler (called on ioQueue)

    private func handleMessage(_ msg: [String: Any]) {
        guard let type = msg["type"] as? String else { return }

        log("recv: \(type)")

        switch type {
        case "scan":            handleScan(msg)
        case "stopScan":        handleStopScan()
        case "connect":         handleConnect(msg)
        case "cancel":          handleCancel(msg)
        case "discoverServices":           handleDiscoverServices(msg)
        case "discoverIncludedServices":   handleDiscoverIncludedServices(msg)
        case "discoverCharacteristics":    handleDiscoverCharacteristics(msg)
        case "discoverDescriptors":        handleDiscoverDescriptors(msg)
        case "read":            handleRead(msg)
        case "readDescriptor":  handleReadDescriptor(msg)
        case "write":           handleWrite(msg)
        case "writeDescriptor": handleWriteDescriptor(msg)
        case "setNotify":       handleSetNotify(msg)
        case "readRSSI":        handleReadRSSI(msg)
        case "registerForConnectionEvents": break
        case "openL2CAP":       handleOpenL2CAP(msg)
        case "l2capWrite", "l2capClose": break
        default:
            NSLog("ImpossiBLE-Mock: unknown message type: %@", type)
        }
    }

    // MARK: - Helpers for main-thread store access

    private func fetchEnabledDevices() -> [MockDevice] {
        DispatchQueue.main.sync { store?.enabledDevices ?? [] }
    }

    private func fetchDevice(uuid: String) -> MockDevice? {
        DispatchQueue.main.sync { store?.devices.first { $0.id.uuidString == uuid } }
    }

    // MARK: - Scan

    private func handleScan(_ msg: [String: Any]) {
        scanActive = true
        let serviceFilter: [String]? = (msg["services"] as? [String])?.isEmpty == false
            ? msg["services"] as? [String]
            : nil

        sendDiscoveries(serviceFilter: serviceFilter)

        scanTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: ioQueue)
        timer.schedule(deadline: .now() + 1.0, repeating: 2.0)
        timer.setEventHandler { [weak self] in
            guard let self, self.scanActive else { return }
            self.sendDiscoveries(serviceFilter: serviceFilter)
        }
        timer.resume()
        scanTimer = timer
    }

    private func handleStopScan() {
        scanActive = false
        scanTimer?.cancel()
        scanTimer = nil
    }

    private func sendDiscoveries(serviceFilter: [String]?) {
        let devices = fetchEnabledDevices()

        for device in devices {
            let matchesFilter: Bool
            if let filter = serviceFilter {
                let deviceServiceUUIDs = Set(
                    device.advertisedServiceUUIDs.map { $0.uppercased() } +
                    device.services.map { $0.uuid.uppercased() }
                )
                matchesFilter = filter.contains { deviceServiceUUIDs.contains($0.uppercased()) }
            } else {
                matchesFilter = true
            }
            guard matchesFilter else { continue }

            var adv: [String: Any] = [:]
            adv["kCBAdvDataLocalName"] = device.name
            adv["kCBAdvDataIsConnectable"] = device.isConnectable

            let svcUUIDs = device.advertisedServiceUUIDs.isEmpty
                ? device.services.map(\.uuid)
                : device.advertisedServiceUUIDs
            if !svcUUIDs.isEmpty {
                adv["kCBAdvDataServiceUUIDs"] = svcUUIDs
            }
            if let mfg = device.manufacturerData, !mfg.isEmpty {
                adv["kCBAdvDataManufacturerData"] = mfg.base64EncodedString()
            }

            send([
                "type": "didDiscover",
                "id": device.id.uuidString,
                "name": device.name,
                "rssi": device.rssi,
                "adv": adv,
            ])
        }
    }

    // MARK: - Connect / Disconnect

    private func handleConnect(_ msg: [String: Any]) {
        guard let uuidStr = msg["id"] as? String else { return }
        guard let device = fetchDevice(uuid: uuidStr), device.isConnectable else {
            send(["type": "didFailConnect", "id": uuidStr, "error": "Device not connectable"])
            return
        }
        connectedPeripherals.insert(uuidStr)
        publishDeviceState()
        send(["type": "didConnect", "id": uuidStr])
    }

    private func handleCancel(_ msg: [String: Any]) {
        guard let uuidStr = msg["id"] as? String else { return }
        connectedPeripherals.remove(uuidStr)
        pairedPeripherals.remove(uuidStr)
        let removed = notifyingCharacteristics.filter { $0.hasPrefix(uuidStr) }
        notifyingCharacteristics.subtract(removed)
        for charId in removed {
            stopFirehose(for: charId)
        }
        stopNirvaStream(peripheralUUID: uuidStr)
        publishDeviceState()
        send([
            "type": "didDisconnect",
            "id": uuidStr,
            "error": "",
            "timestamp": CFAbsoluteTimeGetCurrent(),
            "isReconnecting": false,
        ])
    }

    // MARK: - Service Discovery

    private func handleDiscoverServices(_ msg: [String: Any]) {
        guard let uuidStr = msg["id"] as? String else { return }
        let rawFilter = msg["services"] as? [String]
        let filterUUIDs: [String]? = (rawFilter?.isEmpty == false) ? rawFilter!.map { $0.uppercased() } : nil

        guard let device = fetchDevice(uuid: uuidStr) else {
            log("discoverServices: device not found for \(uuidStr)")
            send(["type": "didDiscoverServices", "id": uuidStr, "services": [] as [[String: Any]], "error": "Device not found"])
            return
        }

        var servicesPayload: [[String: Any]] = []
        for (idx, svc) in device.services.enumerated() {
            if let filter = filterUUIDs, !filter.contains(svc.uuid.uppercased()) {
                continue
            }
            let shimId = "\(uuidStr):\(svc.uuid):\(idx)"
            servicesPayload.append([
                "id": shimId,
                "uuid": svc.uuid,
                "primary": svc.isPrimary,
            ])
        }

        send([
            "type": "didDiscoverServices",
            "id": uuidStr,
            "services": servicesPayload,
            "error": "",
        ])
    }

    private func handleDiscoverIncludedServices(_ msg: [String: Any]) {
        guard let serviceId = msg["serviceId"] as? String else { return }
        let parts = serviceId.split(separator: ":")
        guard parts.count >= 1 else { return }
        let peripheralUUID = String(parts[0])
        send([
            "type": "didDiscoverIncludedServices",
            "id": peripheralUUID,
            "serviceId": serviceId,
            "includedServices": [] as [[String: Any]],
            "error": "",
        ])
    }

    // MARK: - Characteristic Discovery

    private func handleDiscoverCharacteristics(_ msg: [String: Any]) {
        guard let serviceId = msg["serviceId"] as? String else { return }
        let rawFilter = msg["characteristics"] as? [String]
        let filterUUIDs: [String]? = (rawFilter?.isEmpty == false) ? rawFilter!.map { $0.uppercased() } : nil

        let parts = serviceId.split(separator: ":")
        guard parts.count >= 3 else { return }
        let peripheralUUID = String(parts[0])
        let serviceUUID = String(parts[1])
        let serviceIdx = Int(parts[2]) ?? 0

        guard let device = fetchDevice(uuid: peripheralUUID),
              serviceIdx < device.services.count,
              device.services[serviceIdx].uuid.uppercased() == serviceUUID.uppercased()
        else { return }

        let svc = device.services[serviceIdx]
        var charsPayload: [[String: Any]] = []
        for (idx, ch) in svc.characteristics.enumerated() {
            if let filter = filterUUIDs, !filter.contains(ch.uuid.uppercased()) {
                continue
            }
            let shimId = "\(serviceId):\(ch.uuid):\(idx)"
            charsPayload.append([
                "id": shimId,
                "uuid": ch.uuid,
                "properties": ch.properties,
            ])
        }

        send([
            "type": "didDiscoverCharacteristics",
            "id": peripheralUUID,
            "serviceId": serviceId,
            "characteristics": charsPayload,
            "error": "",
        ])
    }

    // MARK: - Descriptor Discovery

    private func handleDiscoverDescriptors(_ msg: [String: Any]) {
        guard let charId = msg["characteristicId"] as? String else { return }
        let parts = charId.split(separator: ":")
        guard parts.count >= 5 else { return }
        let peripheralUUID = String(parts[0])
        let serviceIdx = Int(parts[2]) ?? 0
        let charIdx = Int(parts[4]) ?? 0

        guard let device = fetchDevice(uuid: peripheralUUID),
              serviceIdx < device.services.count,
              charIdx < device.services[serviceIdx].characteristics.count
        else { return }

        let ch = device.services[serviceIdx].characteristics[charIdx]
        var descriptorsPayload: [[String: Any]] = []
        for (idx, desc) in ch.descriptors.enumerated() {
            let shimId = "\(charId):\(desc.uuid):\(idx)"
            descriptorsPayload.append([
                "id": shimId,
                "uuid": desc.uuid,
            ])
        }

        send([
            "type": "didDiscoverDescriptors",
            "id": peripheralUUID,
            "characteristicId": charId,
            "descriptors": descriptorsPayload,
            "error": "",
        ])
    }

    // MARK: - Read / Write

    private func handleRead(_ msg: [String: Any]) {
        guard let charId = msg["characteristicId"] as? String else { return }
        let parts = charId.split(separator: ":")
        guard parts.count >= 5 else { return }
        let peripheralUUID = String(parts[0])
        let serviceIdx = Int(parts[2]) ?? 0
        let charIdx = Int(parts[4]) ?? 0

        guard checkSecurity(peripheralUUID: peripheralUUID, serviceIdx: serviceIdx, charIdx: charIdx) else {
            sendAuthError(type: "didUpdateValue", peripheralUUID: peripheralUUID, idKey: "characteristicId", idValue: charId)
            return
        }

        let value: Data?
        if let written = writtenCharValues[charId] {
            value = written
        } else if let device = fetchDevice(uuid: peripheralUUID),
                  serviceIdx < device.services.count,
                  charIdx < device.services[serviceIdx].characteristics.count {
            value = device.services[serviceIdx].characteristics[charIdx].value
        } else {
            value = nil
        }

        send([
            "type": "didUpdateValue",
            "id": peripheralUUID,
            "characteristicId": charId,
            "value": value?.base64EncodedString() ?? "",
            "error": "",
        ])
    }

    private func handleWrite(_ msg: [String: Any]) {
        guard let charId = msg["characteristicId"] as? String else { return }
        let parts = charId.split(separator: ":")
        guard parts.count >= 5 else { return }
        let peripheralUUID = String(parts[0])
        let serviceIdx = Int(parts[2]) ?? 0
        let charIdx = Int(parts[4]) ?? 0

        guard checkSecurity(peripheralUUID: peripheralUUID, serviceIdx: serviceIdx, charIdx: charIdx) else {
            sendAuthError(type: "didWriteValue", peripheralUUID: peripheralUUID, idKey: "characteristicId", idValue: charId)
            return
        }

        if let b64 = msg["value"] as? String, !b64.isEmpty {
            writtenCharValues[charId] = Data(base64Encoded: b64)
        } else {
            writtenCharValues[charId] = Data()
        }

        let writeType = (msg["writeType"] as? Int) ?? 0
        if writeType == 0 {
            send([
                "type": "didWriteValue",
                "id": peripheralUUID,
                "characteristicId": charId,
                "error": "",
            ])
        }

        if String(parts[3]).uppercased() == NirvaMockProvider.cmsCmdCharUUID {
            handleNirvaCommand(peripheralUUID: peripheralUUID, packet: writtenCharValues[charId] ?? Data())
        }
    }

    // MARK: - Nirva provider (stateful request → notify)

    private func handleNirvaCommand(peripheralUUID: String, packet: Data) {
        let result = NirvaMockProvider.handleCommand(packet)
        for response in result.responses {
            nirvaNotify(peripheralUUID: peripheralUUID, charUUID: NirvaMockProvider.cmsRspCharUUID, value: response)
        }
        if let streaming = result.setStreaming {
            if streaming {
                startNirvaStream(peripheralUUID: peripheralUUID)
            } else {
                stopNirvaStream(peripheralUUID: peripheralUUID)
            }
        }
    }

    /// Notify a characteristic (by UUID) on a device, if the client subscribed.
    private func nirvaNotify(peripheralUUID: String, charUUID: String, value: Data) {
        guard let device = fetchDevice(uuid: peripheralUUID) else { return }
        for (svcIdx, svc) in device.services.enumerated() {
            for (charIdx, ch) in svc.characteristics.enumerated()
            where ch.uuid.uppercased() == charUUID {
                let charId = "\(peripheralUUID):\(svc.uuid):\(svcIdx):\(ch.uuid):\(charIdx)"
                guard notifyingCharacteristics.contains(charId) else { return }
                send([
                    "type": "didUpdateValue",
                    "id": peripheralUUID,
                    "characteristicId": charId,
                    "value": value.base64EncodedString(),
                    "error": "",
                ])
                return
            }
        }
    }

    private func startNirvaStream(peripheralUUID: String) {
        stopNirvaStream(peripheralUUID: peripheralUUID)
        nirvaStreamCounters[peripheralUUID] = (counter: 0, leftChannel: true)

        let timer = DispatchSource.makeTimerSource(queue: ioQueue)
        let interval = DispatchTimeInterval.milliseconds(NirvaMockProvider.streamIntervalMs)
        timer.schedule(deadline: .now() + interval, repeating: interval, leeway: .milliseconds(1))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            guard self.clientFd >= 0,
                  self.connectedPeripherals.contains(peripheralUUID),
                  var state = self.nirvaStreamCounters[peripheralUUID]
            else {
                self.stopNirvaStream(peripheralUUID: peripheralUUID)
                return
            }
            let packet = NirvaMockProvider.audioPacket(counter: state.counter, leftChannel: state.leftChannel)
            state.counter &+= 1
            state.leftChannel.toggle()
            self.nirvaStreamCounters[peripheralUUID] = state
            self.nirvaNotify(peripheralUUID: peripheralUUID, charUUID: NirvaMockProvider.dssDataCharUUID, value: packet)
        }
        nirvaStreamTimers[peripheralUUID] = timer
        timer.resume()
        log("nirva stream start \(peripheralUUID)")
    }

    private func stopNirvaStream(peripheralUUID: String) {
        if let timer = nirvaStreamTimers.removeValue(forKey: peripheralUUID) {
            timer.cancel()
        }
        nirvaStreamCounters.removeValue(forKey: peripheralUUID)
    }

    private func stopAllNirvaStreams() {
        for timer in nirvaStreamTimers.values {
            timer.cancel()
        }
        nirvaStreamTimers.removeAll()
        nirvaStreamCounters.removeAll()
    }

    private func handleReadDescriptor(_ msg: [String: Any]) {
        guard let descId = msg["descriptorId"] as? String else { return }
        let parts = descId.split(separator: ":")
        guard parts.count >= 5 else { return }
        let peripheralUUID = String(parts[0])
        let serviceIdx = Int(parts[2]) ?? 0
        let charIdx = Int(parts[4]) ?? 0
        let descIdx: Int
        if parts.count >= 7 {
            descIdx = Int(parts[6]) ?? 0
        } else {
            descIdx = 0
        }

        let value: Data?
        if let written = writtenDescValues[descId] {
            value = written
        } else if let device = fetchDevice(uuid: peripheralUUID),
                  serviceIdx < device.services.count,
                  charIdx < device.services[serviceIdx].characteristics.count,
                  descIdx < device.services[serviceIdx].characteristics[charIdx].descriptors.count {
            value = device.services[serviceIdx].characteristics[charIdx].descriptors[descIdx].value
        } else {
            value = nil
        }

        send([
            "type": "didUpdateDescriptorValue",
            "id": peripheralUUID,
            "descriptorId": descId,
            "value": NSNull(),
            "valueB64": value?.base64EncodedString() ?? "",
            "error": "",
        ])
    }

    private func handleWriteDescriptor(_ msg: [String: Any]) {
        guard let descId = msg["descriptorId"] as? String else { return }
        let parts = descId.split(separator: ":")
        guard parts.count >= 1 else { return }
        let peripheralUUID = String(parts[0])

        if let b64 = msg["value"] as? String, !b64.isEmpty {
            writtenDescValues[descId] = Data(base64Encoded: b64)
        }

        send([
            "type": "didWriteDescriptorValue",
            "id": peripheralUUID,
            "descriptorId": descId,
            "error": "",
        ])
    }

    // MARK: - Notify

    private func handleSetNotify(_ msg: [String: Any]) {
        guard let charId = msg["characteristicId"] as? String else { return }
        let enabled: Bool
        if let b = msg["enabled"] as? Bool {
            enabled = b
        } else if let n = msg["enabled"] as? Int {
            enabled = n != 0
        } else {
            return
        }

        let parts = charId.split(separator: ":")
        guard parts.count >= 1 else { return }
        let peripheralUUID = String(parts[0])

        if enabled {
            notifyingCharacteristics.insert(charId)
            startFirehoseIfConfigured(for: charId, peripheralUUID: peripheralUUID)
        } else {
            notifyingCharacteristics.remove(charId)
            stopFirehose(for: charId)
        }

        send([
            "type": "didUpdateNotification",
            "id": peripheralUUID,
            "characteristicId": charId,
            "enabled": enabled,
            "error": "",
        ])
    }

    private func startFirehoseIfConfigured(for charId: String, peripheralUUID: String) {
        guard let config = firehoseConfig else { return }
        stopFirehose(for: charId)

        firehoseSequences[charId] = 0
        let timer = DispatchSource.makeTimerSource(queue: ioQueue)
        let interval = max(1, Int((1.0 / config.hz) * 1_000_000_000))
        timer.schedule(
            deadline: .now(),
            repeating: .nanoseconds(interval),
            leeway: .milliseconds(1)
        )
        timer.setEventHandler { [weak self] in
            self?.emitFirehoseNotification(
                charId: charId,
                peripheralUUID: peripheralUUID,
                config: config
            )
        }
        firehoseTimers[charId] = timer
        timer.resume()
        log("firehose start \(charId)")
    }

    private func emitFirehoseNotification(
        charId: String,
        peripheralUUID: String,
        config: MockNotificationFirehoseConfig
    ) {
        guard clientFd >= 0, notifyingCharacteristics.contains(charId) else {
            stopFirehose(for: charId)
            return
        }

        let sequence = firehoseSequences[charId] ?? 0
        if sequence >= UInt64(config.maxFrames) {
            stopFirehose(for: charId)
            log("firehose complete \(charId) frames=\(config.maxFrames)")
            return
        }

        firehoseSequences[charId] = sequence &+ 1
        generatedNotificationCount &+= 1
        traceNotificationStage("corebluetooth_callback", count: generatedNotificationCount, bytes: 0)

        send([
            "type": "didUpdateValue",
            "id": peripheralUUID,
            "characteristicId": charId,
            "value": firehosePayload(sequence: sequence, byteCount: config.payloadBytes).base64EncodedString(),
            "error": "",
        ])
    }

    private func stopFirehose(for charId: String) {
        if let timer = firehoseTimers.removeValue(forKey: charId) {
            timer.cancel()
        }
        firehoseSequences.removeValue(forKey: charId)
    }

    private func stopAllFirehoses() {
        for timer in firehoseTimers.values {
            timer.cancel()
        }
        firehoseTimers.removeAll()
        firehoseSequences.removeAll()
    }

    private func firehosePayload(sequence: UInt64, byteCount: Int) -> Data {
        let count = max(8, byteCount)
        var data = Data(repeating: 0, count: count)
        data.withUnsafeMutableBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return
            }
            var littleEndian = sequence.littleEndian
            withUnsafeBytes(of: &littleEndian) { sequenceBytes in
                for idx in 0..<min(8, sequenceBytes.count) {
                    base[idx] = sequenceBytes[idx]
                }
            }
            if count > 8 {
                for idx in 8..<count {
                    base[idx] = UInt8((Int(sequence) + idx) & 0xff)
                }
            }
        }
        return data
    }

    // MARK: - RSSI

    private func handleReadRSSI(_ msg: [String: Any]) {
        guard let uuidStr = msg["id"] as? String else { return }
        let device = fetchDevice(uuid: uuidStr)

        send([
            "type": "didReadRSSI",
            "id": uuidStr,
            "rssi": device?.rssi ?? -50,
            "error": "",
        ])
    }

    // MARK: - L2CAP (not supported)

    private func handleOpenL2CAP(_ msg: [String: Any]) {
        guard let uuidStr = msg["id"] as? String else { return }
        send([
            "type": "didOpenL2CAP",
            "id": uuidStr,
            "channelId": "",
            "psm": 0,
            "error": "L2CAP is not supported in mock mode",
        ])
    }

    // MARK: - Security

    private func checkSecurity(peripheralUUID: String, serviceIdx: Int, charIdx: Int) -> Bool {
        guard let device = fetchDevice(uuid: peripheralUUID),
              serviceIdx < device.services.count,
              charIdx < device.services[serviceIdx].characteristics.count
        else { return true }

        let characteristic = device.services[serviceIdx].characteristics[charIdx]
        guard characteristic.securityLevel == .encryptionRequired else { return true }
        guard !pairedPeripherals.contains(peripheralUUID) else { return true }

        switch device.pairingMode {
            case .none:
                return true
            case .justWorks:
                pairedPeripherals.insert(peripheralUUID)
                publishDeviceState()
                log("Auto-paired (Just Works): \(device.name)")
                return true
            case .passkey:
                return false
        }
    }

    private func sendAuthError(type: String, peripheralUUID: String, idKey: String, idValue: String) {
        send([
            "type": type,
            "id": peripheralUUID,
            idKey: idValue,
            "value": "",
            "error": "Insufficient authentication",
            "errorDomain": "CBATTErrorDomain",
            "errorCode": 5,
        ])
    }

    // MARK: - Utilities

    private func publishStatus(_ newStatus: Status) {
        DispatchQueue.main.async { [weak self] in
            self?.status = newStatus
        }
    }

    private func publishConnectedClient(_ client: SocketClientInfo?) {
        DispatchQueue.main.async { [weak self] in
            self?.connectedClient = client
        }
    }

    private func publishDeviceState() {
        let connected = connectedPeripherals
        let paired = pairedPeripherals
        DispatchQueue.main.async { [weak self] in
            self?.connectedDeviceIDs = connected
            self?.pairedDeviceIDs = paired
        }
    }

    private func traceNotificationStage(_ stage: String, count: UInt64, bytes: UInt64) {
        guard traceNotifications else { return }
        let now = CFAbsoluteTimeGetCurrent()
        guard count == 1 || now - lastNotificationTraceLog >= 1 else { return }
        lastNotificationTraceLog = now
        NSLog(
            "ImpossiBLE-Mock: notification_trace stage=%@ count=%llu bytes=%llu",
            stage,
            count,
            bytes
        )
    }

    private func traceSocketWriteStage() {
        guard traceNotifications else { return }
        let now = CFAbsoluteTimeGetCurrent()
        guard socketNotificationWriteCount == 1 || now - lastSocketTraceLog >= 1 else { return }
        lastSocketTraceLog = now
        NSLog(
            "ImpossiBLE-Mock: notification_trace stage=socket_write count=%llu bytes=%llu",
            socketNotificationWriteCount,
            socketNotificationWriteBytes
        )
    }

    private var pulseWorkItem: DispatchWorkItem?

    private func log(_ message: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.lastActivity = message
            self.pulseTraffic()
        }
    }

    private func pulseTraffic() {
        pulseWorkItem?.cancel()
        trafficActive = true
        let item = DispatchWorkItem { [weak self] in
            self?.trafficActive = false
        }
        pulseWorkItem = item
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3, execute: item)
    }
}
