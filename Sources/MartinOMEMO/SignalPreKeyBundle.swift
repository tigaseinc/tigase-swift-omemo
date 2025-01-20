//
// SignalPreKeyBundle.swift
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

class SignalPreKeyBundle {
    
    let bundle: OpaquePointer;
    
    public init(registrationId: UInt32, deviceId: Int32, preKey: OMEMOModule.OMEMOPreKey, bundle: OMEMOModule.OMEMOBundle) throws {
        let preKeyPublic = try SignalIdentityKey(data: preKey.data);
        let signedPreKeyPublic = try SignalIdentityKey(data: bundle.signedPreKeyPublic)
        let identityKey = try SignalIdentityKey(data: bundle.identityKey);
        
        var bundlePtr: OpaquePointer?;
        guard let error = bundle.signature.withUnsafeBytes({ (bytes) -> SignalError? in
            return SignalError.from(code: session_pre_key_bundle_create(&bundlePtr, registrationId, deviceId, preKey.preKeyId, preKeyPublic.publicKeyPointer, bundle.signedPreKeyId, signedPreKeyPublic.publicKeyPointer, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bundle.signature.count, identityKey.publicKeyPointer));
        }) else {
            self.bundle = bundlePtr!;
            return;
        }
        
        throw error;
        
    }
 
    deinit {
        signal_type_unref(bundle);
    }
    
}
