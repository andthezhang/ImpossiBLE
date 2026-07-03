import CoreBluetooth
@testable import ImpossiBLE
import XCTest

#if targetEnvironment(simulator)
final class NotificationThroughputTests: XCTestCase {
    func testFirehoseNotificationsAreLosslessThroughSwizzledCentral() throws {
        guard firehoseTestsEnabled() else {
            throw XCTSkip("Set IMPOSSIBLE_RUN_FIREHOSE_TESTS=1 with the headless mock firehose running.")
        }

        let expectedFrames = intConfig(
            environmentKey: "IMPOSSIBLE_FIREHOSE_EXPECTED_FRAMES",
            filePath: "/tmp/impossible-firehose-expected-frames",
            defaultValue: 30_000
        )
        let timeout = TimeInterval(intConfig(
            environmentKey: "IMPOSSIBLE_FIREHOSE_TIMEOUT",
            filePath: "/tmp/impossible-firehose-timeout",
            defaultValue: 330
        ))

        let delegate = FirehoseCentralDelegate(expectedFrames: expectedFrames)
        let queue = DispatchQueue(label: "impossible.tests.firehose.central")
        let central = CBCentralManager(delegate: delegate, queue: queue)
        delegate.central = central

        let setupResult = XCTWaiter.wait(
            for: [
                delegate.poweredOnExpectation,
                delegate.discoveredExpectation,
                delegate.connectedExpectation,
                delegate.servicesExpectation,
                delegate.characteristicsExpectation,
                delegate.notifyingExpectation,
            ],
            timeout: 30,
            enforceOrder: false
        )
        guard setupResult == .completed else {
            XCTFail("Firehose setup did not complete: \(setupResult)")
            return
        }

        let firehoseResult = XCTWaiter.wait(for: [delegate.allFramesExpectation], timeout: timeout)
        queue.sync {
            delegate.stop()
        }

        let snapshot = queue.sync {
            delegate.snapshot()
        }

        XCTAssertEqual(firehoseResult, .completed, "Timed out waiting for firehose frames")
        XCTAssertEqual(snapshot.received, expectedFrames)
        XCTAssertTrue(snapshot.sequenceErrors.isEmpty, snapshot.sequenceErrors.joined(separator: "\n"))
    }

    private func firehoseTestsEnabled() -> Bool {
        ProcessInfo.processInfo.environment["IMPOSSIBLE_RUN_FIREHOSE_TESTS"] == "1"
            || FileManager.default.fileExists(atPath: "/tmp/impossible-run-firehose-tests")
    }

    private func intConfig(environmentKey: String, filePath: String, defaultValue: Int) -> Int {
        if let value = ProcessInfo.processInfo.environment[environmentKey],
           let parsed = Int(value.trimmingCharacters(in: .whitespacesAndNewlines)),
           parsed > 0 {
            return parsed
        }
        if let contents = try? String(contentsOfFile: filePath),
           let parsed = Int(contents.trimmingCharacters(in: .whitespacesAndNewlines)),
           parsed > 0 {
            return parsed
        }
        return defaultValue
    }
}

private final class FirehoseCentralDelegate: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    let poweredOnExpectation = XCTestExpectation(description: "central powered on")
    let discoveredExpectation = XCTestExpectation(description: "firehose peripheral discovered")
    let connectedExpectation = XCTestExpectation(description: "firehose peripheral connected")
    let servicesExpectation = XCTestExpectation(description: "firehose service discovered")
    let characteristicsExpectation = XCTestExpectation(description: "firehose characteristic discovered")
    let notifyingExpectation = XCTestExpectation(description: "firehose notifications enabled")
    let allFramesExpectation = XCTestExpectation(description: "all firehose frames received")

    weak var central: CBCentralManager?

    private let serviceUUID = CBUUID(string: "FFF0")
    private let characteristicUUID = CBUUID(string: "FFF1")
    private let expectedFrames: Int
    private var peripheral: CBPeripheral?
    private var characteristic: CBCharacteristic?
    private var receivedFrames = 0
    private var nextSequence: UInt64 = 0
    private var sequenceErrors: [String] = []

    init(expectedFrames: Int) {
        self.expectedFrames = expectedFrames
        super.init()
        poweredOnExpectation.assertForOverFulfill = false
        discoveredExpectation.assertForOverFulfill = false
        connectedExpectation.assertForOverFulfill = false
        servicesExpectation.assertForOverFulfill = false
        characteristicsExpectation.assertForOverFulfill = false
        notifyingExpectation.assertForOverFulfill = false
        allFramesExpectation.assertForOverFulfill = false
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else { return }
        poweredOnExpectation.fulfill()
        central.scanForPeripherals(
            withServices: [serviceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        guard self.peripheral == nil else { return }
        self.peripheral = peripheral
        peripheral.delegate = self
        discoveredExpectation.fulfill()
        central.stopScan()
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        connectedExpectation.fulfill()
        peripheral.discoverServices([serviceUUID])
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil,
              let service = peripheral.services?.first(where: { $0.uuid == serviceUUID })
        else {
            sequenceErrors.append("service discovery failed: \(error?.localizedDescription ?? "missing service")")
            return
        }
        servicesExpectation.fulfill()
        peripheral.discoverCharacteristics([characteristicUUID], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard error == nil,
              let characteristic = service.characteristics?.first(where: { $0.uuid == characteristicUUID })
        else {
            sequenceErrors.append("characteristic discovery failed: \(error?.localizedDescription ?? "missing characteristic")")
            return
        }
        self.characteristic = characteristic
        characteristicsExpectation.fulfill()
        peripheral.setNotifyValue(true, for: characteristic)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateNotificationStateFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard error == nil else {
            sequenceErrors.append("notify enable failed: \(error?.localizedDescription ?? "unknown error")")
            return
        }
        notifyingExpectation.fulfill()
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil else {
            sequenceErrors.append("notification error: \(error?.localizedDescription ?? "unknown error")")
            return
        }
        guard let value = characteristic.value, value.count >= 8 else {
            sequenceErrors.append("notification had invalid payload length")
            return
        }

        let sequence = value.prefix(8).enumerated().reduce(UInt64(0)) { partial, item in
            partial | (UInt64(item.element) << UInt64(item.offset * 8))
        }
        if sequence != nextSequence {
            if sequenceErrors.count < 20 {
                sequenceErrors.append("expected sequence \(nextSequence), got \(sequence)")
            }
            nextSequence = sequence &+ 1
        } else {
            nextSequence &+= 1
        }

        receivedFrames += 1
        if receivedFrames % 1_000 == 0 {
            NSLog("ImpossiBLETests: firehose received=%d sequence=%llu", receivedFrames, sequence)
        }
        if receivedFrames == expectedFrames {
            allFramesExpectation.fulfill()
        }
    }

    func stop() {
        if let peripheral, let characteristic {
            peripheral.setNotifyValue(false, for: characteristic)
        }
        if let peripheral {
            central?.cancelPeripheralConnection(peripheral)
        }
        central?.stopScan()
    }

    func snapshot() -> (received: Int, sequenceErrors: [String]) {
        (receivedFrames, sequenceErrors)
    }
}
#endif
