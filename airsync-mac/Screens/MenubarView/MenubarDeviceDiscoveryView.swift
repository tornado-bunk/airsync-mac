//
//  MenubarDeviceDiscoveryView.swift
//  AirSync
//
//  Created by Sameera Sandakelum on 2026-05-07.
//

import SwiftUI

struct MenubarDeviceDiscoveryView: View {
    @ObservedObject private var udpDiscovery = UDPDiscoveryManager.shared
    @ObservedObject private var quickConnectManager = QuickConnectManager.shared
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            let devices = udpDiscovery.discoveredDevices
            if !devices.isEmpty {
                Text("Nearby Devices")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 4)
                
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        let lastConnected = quickConnectManager.getLastConnectedDevice()
                        ForEach(devices) { device in
                            DeviceCard(
                                device: device,
                                isLastConnected: lastConnected?.name == device.name && (lastConnected != nil && device.ips.contains(lastConnected!.ipAddress)),
                                isCompact: true,
                                connectAction: {
                                    quickConnectManager.connect(to: device)
                                },
                                namespace: nil
                            )
                        }
                    }
                    .padding(.vertical, 4)
                    .padding(.horizontal, 4)
                }
            }
        }
    }
}

#Preview {
    MenubarDeviceDiscoveryView()
        .frame(width: 320)
        .background(Color.black.opacity(0.8))
}
