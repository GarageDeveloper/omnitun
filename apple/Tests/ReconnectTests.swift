import XCTest
@testable import Omnitun

final class ReconnectTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let paris = UpSessions.Entry(id: "paris", direct: false, split: true)

    private func up(_ version: String, minutesAgo: Double, _ sessions: [UpSessions.Entry]) -> UpSessions {
        UpSessions(version: version, at: now.addingTimeInterval(-minutesAgo * 60), sessions: sessions)
    }

    func testReconnectsAfterAnUpdate() {
        XCTAssertEqual(AppModel.toResume(up("0.4.3", minutesAgo: 1, [paris]), version: "0.4.4", now: now), [paris])
    }

    func testNothingWithoutAnUpdate() {
        XCTAssertNil(AppModel.toResume(up("0.4.4", minutesAgo: 1, [paris]), version: "0.4.4", now: now))
    }

    func testNothingFromLongAgo() {
        XCTAssertNil(AppModel.toResume(up("0.4.3", minutesAgo: 20, [paris]), version: "0.4.4", now: now))
        XCTAssertNil(AppModel.toResume(up("0.4.3", minutesAgo: -5, [paris]), version: "0.4.4", now: now), "dated in the future")
    }

    func testNothingRecorded() {
        XCTAssertNil(AppModel.toResume(nil, version: "0.4.4", now: now))
        XCTAssertNil(AppModel.toResume(up("0.4.3", minutesAgo: 1, []), version: "0.4.4", now: now))
        XCTAssertNil(AppModel.toResume(up("0.4.3", minutesAgo: 1, [paris]), version: nil, now: now), "a build without a version")
    }

    func testAChainBringsBackWhatItGoesThrough() {
        let office = UpSessions.Entry(id: "office", direct: false, split: false)
        let home = UpSessions.Entry(id: "home", direct: false, split: false)
        let via = { (id: String) in id == "office" ? ["home"] : [] }
        XCTAssertEqual(AppModel.resumable([home, office], known: ["home", "office"], via: via), [office])
        let alone = UpSessions.Entry(id: "office", direct: true, split: false)
        XCTAssertEqual(AppModel.resumable([home, alone], known: ["home", "office"], via: via), [home, alone], "connected directly")
    }

    func testDeletedProfilesAreSkipped() {
        XCTAssertEqual(AppModel.resumable([paris], known: [], via: { _ in [] }), [])
    }
}
