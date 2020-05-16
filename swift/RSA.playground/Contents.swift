import CommonCrypto
import Foundation

extension Int {
    var bcd: [UInt8] {
        var d: [UInt8] = []
        var n = self
        while n > 0 {
            let (q, r) = n.quotientAndRemainder(dividingBy: 100)
            let (hundreds, tens) = r.quotientAndRemainder(dividingBy: 10)
            d.append(UInt8((hundreds << 4) | tens))
            n = q
        }
        return d.isEmpty ? [0] : d.reversed()
    }
}

let fldDigitShift: UInt8 = 6
let fldDigitMask: UInt16 = 0b111 << fldDigitShift
let fldNumsecondsShift: UInt16 = 0
let fldNumsecondsMask: UInt16 = 0b11 << fldNumsecondsShift

class Token {
    let serial: [UInt8]
    let seed: [UInt8]
    let pin: [UInt8] = Array(repeating: 0, count: 8)
    let flags: UInt = 17369
    let currentDate: () -> Date

    init?(serial: String, seed: String, currentDate: @escaping () -> Date = { Date() }) {
        guard let serial = Int(serial)?.bcd else {
            return nil
        }
        self.serial = serial

        var d: [UInt8] = []
        for hex in seed.components(separatedBy: ":").map({ UInt8($0, radix: 16) }) {
            guard let hex = hex else { return nil }
            d.append(hex)
        }
        self.seed = d

        self.currentDate = currentDate
    }

    var code: [UInt8] {
        let date = dateComponents
        let bcdTime = self.bcdTime(date: date)

        var key1 = seed
        var key0 = key(from: Array(bcdTime[0..<2]))
        key0 = encrypt(data: key0, with: key1)

        key1 = key(from: Array(bcdTime[0..<3]))
        key1 = encrypt(data: key1, with: key0)

        key0 = key(from: Array(bcdTime[0..<4]))
        key0 = encrypt(data: key0, with: key1)

        key1 = key(from: Array(bcdTime[0..<5]))
        key1 = encrypt(data: key1, with: key0)

        key0 = key(from: Array(bcdTime[0..<8]))
        key0 = encrypt(data: key0, with: key1)

        let offset: Int
        switch interval {
        case .thirtySeconds:
            offset = {
                var i = 0
                if date.minute! % 2 == 1 {
                    i |= 0b1000
                }
                if date.minute! >= 30 {
                    i |= 0b0100
                }
                return i
            }()
        case .oneMinute:
            offset = (date.minute! & 0b11) << 2
        }

        let len = (UInt16(flags) & fldDigitMask) >> fldDigitShift

        let raw: [Int] = {
            String(
                Data(key0[offset..<offset+4])
                    .withUnsafeBytes { $0.load(as: UInt32.self) }
                    .bigEndian
                ).map { $0.wholeNumberValue! }.suffix(Int(len + 1))
        }()

        return zip(
            raw,
            (0..<raw.count).map { Int($0 < pin.count ? pin[$0] : 0) }
        ).map { UInt8($0 + $1) }
    }

    var dateComponents: DateComponents {
        Calendar.current.dateComponents(
            in: TimeZone(identifier: "UTC")!,
            from: currentDate()
        )
    }

    private func bcdTime(date: DateComponents) -> [UInt8] {
        return [
            (date.year! % 100).bcd,
            ((date.year! / 100) % 100).bcd,
            date.month!.bcd,
            date.day!.bcd,
            date.hour!.bcd,
            (date.minute! & Int(minuteMask)).bcd,
            [0],
            [0],
        ].flatMap { $0 }
    }

    private var minuteMask: UInt8 {
        switch interval {
        case .thirtySeconds: return ~0b01
        case .oneMinute: return ~0b11
        }
    }

    enum Interval { case thirtySeconds, oneMinute }
    private var interval: Interval {
        if (UInt16(flags) & fldNumsecondsMask) >> fldNumsecondsShift == 0 {
            return .thirtySeconds
        } else {
            return .oneMinute
        }
    }

    func key(from bcdTime: [UInt8]) -> [UInt8] {
        var key: [UInt8] = Array(repeating: 0, count: 16)

        for i in 0..<16 {
            let byte: UInt8
            switch i {
            case 0...7:
                byte = (i < bcdTime.count) ? bcdTime[i] : 0xAA
            case 8...11:
                byte = serial[i-6]
            case 12...15:
                byte = 0xBB
            default:
                fatalError()
            }
            key[i] = byte
        }

        return key
    }

    func encrypt(data: [UInt8], with key: [UInt8]) -> [UInt8] {
        let key = Data(key)
        let data = Data(data)
        var encrypted = Data(count: data.count)

        encrypted.withUnsafeMutableBytes { encrypted in
            key.withUnsafeBytes { key in
                data.withUnsafeBytes { data in
                    var bytesLength = 0
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCKeySizeAES128|kCCBlockSizeAES128|kCCContextSizeAES128),
                        key.baseAddress,
                        key.count,
                        nil,
                        data.baseAddress,
                        data.count,
                        encrypted.baseAddress,
                        encrypted.count,
                        &bytesLength
                    )
                }
            }
        }

        return Array(encrypted)
    }

}

let token = Token(
    serial: "",
    seed: ""
)!
print(token.code.map { String($0) }.joined())
