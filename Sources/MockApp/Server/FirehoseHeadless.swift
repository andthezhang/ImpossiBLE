import Foundation

enum FirehoseHeadless {
    private static let serviceUUID = "FFF0"
    private static let characteristicUUID = "FFF1"

    static func run() -> Never {
        let hz = doubleOption("--hz", environmentKey: "IMPOSSIBLE_FIREHOSE_HZ", defaultValue: 100)
        let payloadBytes = intOption("--bytes", environmentKey: "IMPOSSIBLE_FIREHOSE_BYTES", defaultValue: 166)
        let seconds = intOption("--seconds", environmentKey: "IMPOSSIBLE_FIREHOSE_SECONDS", defaultValue: 300)
        let maxFrames = intOption("--frames", environmentKey: "IMPOSSIBLE_FIREHOSE_FRAMES", defaultValue: Int(hz) * seconds)

        let store = MockStore()
        store.devices = [makeDevice()]

        let server = MockServer(autoStart: false)
        server.store = store
        server.configureNotificationFirehose(
            MockNotificationFirehoseConfig(
                hz: hz,
                payloadBytes: payloadBytes,
                maxFrames: maxFrames
            )
        )

        signal(SIGINT) { _ in exit(0) }
        signal(SIGTERM) { _ in exit(0) }

        server.start {
            NSLog(
                "ImpossiBLE-Mock: firehose headless ready service=%@ characteristic=%@ hz=%.2f bytes=%d frames=%d",
                serviceUUID,
                characteristicUUID,
                hz,
                payloadBytes,
                maxFrames
            )
        }

        RunLoop.main.run()
        fatalError("RunLoop exited unexpectedly")
    }

    private static func makeDevice() -> MockDevice {
        MockDevice(
            name: "ImpossiBLE Firehose",
            rssi: -42,
            isConnectable: true,
            isEnabled: true,
            advertisedServiceUUIDs: [serviceUUID],
            manufacturerData: nil,
            pairingMode: .none,
            passkey: "",
            services: [
                MockService(
                    uuid: serviceUUID,
                    isPrimary: true,
                    characteristics: [
                        MockCharacteristic(
                            uuid: characteristicUUID,
                            properties: 0x12,
                            value: Data(repeating: 0, count: 166),
                            securityLevel: .none,
                            descriptors: [
                                MockDescriptor(uuid: "2902", value: nil)
                            ]
                        )
                    ]
                )
            ]
        )
    }

    private static func intOption(_ flag: String, environmentKey: String, defaultValue: Int) -> Int {
        if let value = commandLineValue(after: flag), let parsed = Int(value), parsed > 0 {
            return parsed
        }
        if let value = ProcessInfo.processInfo.environment[environmentKey], let parsed = Int(value), parsed > 0 {
            return parsed
        }
        return defaultValue
    }

    private static func doubleOption(_ flag: String, environmentKey: String, defaultValue: Double) -> Double {
        if let value = commandLineValue(after: flag), let parsed = Double(value), parsed > 0 {
            return parsed
        }
        if let value = ProcessInfo.processInfo.environment[environmentKey], let parsed = Double(value), parsed > 0 {
            return parsed
        }
        return defaultValue
    }

    private static func commandLineValue(after flag: String) -> String? {
        let args = CommandLine.arguments
        guard let index = args.firstIndex(of: flag), args.indices.contains(index + 1) else {
            return nil
        }
        return args[index + 1]
    }
}
