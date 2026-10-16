//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest
import Crypto
@testable import CryptoExtras

// Test Vectors are coming from https://tools.ietf.org/html/rfc7914
class ScryptTests: XCTestCase {
    struct RFCTestVector: Codable {
        var inputSecret: [UInt8]
        var salt: [UInt8]
        var rounds: Int
        var blockSize: Int
        var parallelism: Int
        var outputLength: Int
        var derivedKey: [UInt8]

        enum CodingKeys: String, CodingKey {
            case inputSecret = "P"
            case salt = "S"
            case rounds = "N"
            case blockSize = "r"
            case parallelism = "p"
            case outputLength = "dkLen"
            case derivedKey = "DK"
        }
    }

    func oneshotTesting(_ vector: RFCTestVector) throws {
        let (contiguousInput, discontiguousInput) = vector.inputSecret.asDataProtocols()
        let (contiguousSalt, discontiguousSalt) = vector.salt.asDataProtocols()

        let DK1 = try KDF.Scrypt.deriveKey(from: contiguousInput, salt: contiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let DK2 = try KDF.Scrypt.deriveKey(from: discontiguousInput, salt: contiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let DK3 = try KDF.Scrypt.deriveKey(from: contiguousInput, salt: discontiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let DK4 = try KDF.Scrypt.deriveKey(from: discontiguousInput, salt: discontiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let expectedDK = SymmetricKey(data: vector.derivedKey)
        XCTAssertEqual(DK1, expectedDK)
        XCTAssertEqual(DK2, expectedDK)
        XCTAssertEqual(DK3, expectedDK)
        XCTAssertEqual(DK4, expectedDK)
    }

    func testRFCVector(_ vector: RFCTestVector) throws {
        try oneshotTesting(vector)
    }

    func testRfcTestVectors() throws {
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "rfc-7914-scrypt") }
        let vectors = try orFail { try decoder.decode([RFCTestVector].self) }

        for vector in vectors {
            try orFail { try self.testRFCVector(vector) }
        }
    }

    func testMaxMemoryIsEnforced() throws {
        XCTAssertThrowsError(try KDF.Scrypt.deriveKey(from: [UInt8](), salt: [UInt8](), outputByteCount: 32, rounds: 16, blockSize: 1, parallelism: 1, maxMemory: 1024))
        XCTAssertThrowsError(try KDF.Scrypt.deriveKey(from: [UInt8](), salt: [UInt8](), outputByteCount: 32, rounds: 16, blockSize: 1, parallelism: 1, maxMemory: -1))
        XCTAssertNoThrow(try KDF.Scrypt.deriveKey(from: [UInt8](), salt: [UInt8](), outputByteCount: 32, rounds: 16, blockSize: 1, parallelism: 1, maxMemory: 128 * 1 * (16 + 1 + 1)))
    }

    func testInvalidParametersThrow() throws {
        for (rounds, blockSize, parallelism) in [(-16, 1, 1), (16, -1, 1), (16, 1, -1), (0, 1, 1), (16, 0, 1), (16, 1, 0)] {
            XCTAssertThrowsError(try KDF.Scrypt.deriveKey(from: [UInt8](), salt: [UInt8](), outputByteCount: 32, rounds: rounds, blockSize: blockSize, parallelism: parallelism))
        }
        XCTAssertThrowsError(try KDF.Scrypt.deriveKey(from: [UInt8](), salt: [UInt8](), outputByteCount: -1, rounds: 16, blockSize: 1, parallelism: 1))
    }

    func testDefaultMemoryLimitDoesNotOverflow() throws {
        for (rounds, blockSize, parallelism) in [(Int.max, 1, 1), (1 << 32, Int.max / 64, 1), (2, 1, Int.max)] {
            XCTAssertThrowsError(try KDF.Scrypt.deriveKey(from: [UInt8](), salt: [UInt8](), outputByteCount: 32, rounds: rounds, blockSize: blockSize, parallelism: parallelism))
        }
    }

    func testDefaultMemoryLimitFitsLargeBlockSize() throws {
        // Needs 128 * r * (N + p + 1) bytes, more than 128 * N * r * p when N * p is small.
        XCTAssertNoThrow(try KDF.Scrypt.deriveKey(from: [UInt8](), salt: [UInt8](), outputByteCount: 32, rounds: 2, blockSize: 1024, parallelism: 1))
    }
}
