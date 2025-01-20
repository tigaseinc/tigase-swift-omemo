//
// SignalSessionCipher.swift
//
// TigaseSwift OMEMO
// Copyright (C) 2019 "Tigase, Inc." <office@tigase.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. Look for COPYING file in the top folder.
// If not, see https://www.gnu.org/licenses/.
//

import Foundation
import libsignal

open class SignalSessionCipher {
    
    private let cipher: OpaquePointer;
    private let context: SignalContext;
    private let address: SignalAddress;
    
    public init(withAddress address: SignalAddress, andContext context: SignalContext) throws {
        guard let storage = context.storage else {
            fatalError("Storage not initialized")
        }
        var cipher: OpaquePointer?;
        self.address = address;
        guard let error = SignalError.from(code: session_cipher_create(&cipher, storage.storeContext, self.address.address, context.globalContext)) else {
            self.context = context;
            self.cipher = cipher!;
            return;
        }
        throw error;
    }
    
    deinit {
        session_cipher_free(cipher);
    }
    
    func encrypt(data: Data) throws -> Key {
        var message: OpaquePointer?;
        guard let error = data.withUnsafeBytes({ (bytes) -> SignalError? in
            return SignalError.from(code : session_cipher_encrypt(cipher, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), data.count, &message));
        }) else {
            let serialized = ciphertext_message_get_serialized(message);
            let result = Data(bytes: signal_buffer_data(serialized), count: signal_buffer_len(serialized));
            
            defer {
                signal_type_unref(message);
            }
            return Key(key: result, deviceId: address.deviceId, prekey: ciphertext_message_get_type(message) == CIPHERTEXT_PREKEY_TYPE);
        }
        throw error;
    }
 
    func decrypt(key: Key) throws -> Data {
        if key.prekey {
            return try decryptPreKeyMessage(key: key);
        } else {
            return try decryptSignalMessage(key: key);
        }
    }
    
    private func decryptPreKeyMessage(key: Key) throws -> Data {
        let decryptedPreKeySignalMessage = try key.key.withUnsafeBytes({ (bytes) throws -> OpaquePointer in
            var output: OpaquePointer?;
            var preKeySignalMessage: OpaquePointer?;
            
            guard let error = SignalError.from(code: pre_key_signal_message_deserialize(&preKeySignalMessage, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), key.key.count, self.context.globalContext)) else {
                defer {
                    signal_type_unref(preKeySignalMessage);
                }
                guard let error = SignalError.from(code: session_cipher_decrypt_pre_key_signal_message(cipher, preKeySignalMessage, nil, &output)) else {
                    return output!;
                }
                throw error;
            }
            throw error;
        })
        defer {
            signal_buffer_free(decryptedPreKeySignalMessage);
        }
        return Data(bytes: signal_buffer_data(decryptedPreKeySignalMessage), count: signal_buffer_len(decryptedPreKeySignalMessage));
    }
    
    private func decryptSignalMessage(key: Key) throws -> Data {
        let descryptedSignalMessage = try key.key.withUnsafeBytes({ (bytes) throws -> OpaquePointer in
            var output: OpaquePointer?;
            var signalMessage: OpaquePointer?;
            guard let error = SignalError.from(code: signal_message_deserialize(&signalMessage, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), key.key.count, self.context.globalContext)) else {
                defer {
                    signal_type_unref(signalMessage);
                }
                guard let error = SignalError.from(code: session_cipher_decrypt_signal_message(cipher, signalMessage, nil, &output)) else {
                    return output!;
                }
                throw error;
            }
            throw error;
        });
        defer {
            signal_buffer_free(descryptedSignalMessage);
        }
        return Data(bytes: signal_buffer_data(descryptedSignalMessage), count: signal_buffer_len(descryptedSignalMessage));
    }
    
    public struct Key: Equatable, Hashable {
        
        public let key: Data;
        public let deviceId: Int32;
        public let prekey: Bool;
        
        public init(key: Data, deviceId: Int32, prekey: Bool) {
            self.key = key;
            self.deviceId = deviceId;
            self.prekey = prekey;
        }
        
    }
    
}
