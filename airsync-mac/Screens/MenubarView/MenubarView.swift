//
//  MenubarView.swift
//  AirSync
//
//  Created by Sameera Sandakelum on 2025-08-08.
//

import SwiftUI

struct MenubarView: View {
    @Environment(\.openWindow) var openWindow
    @StateObject private var appState = AppState.shared
    @AppStorage("hasPairedDeviceOnce") private var hasPairedDeviceOnce: Bool = false
    private var appDelegate: AppDelegate? { AppDelegate.shared }

    private func focus(window: NSWindow) {
    if window.isMiniaturized { window.deminiaturize(nil) }
    window.collectionBehavior.insert(.moveToActiveSpace)
    NSApp.unhide(nil)
    NSApp.activate(ignoringOtherApps: true)
    window.makeKeyAndOrderFront(nil)
    window.orderFrontRegardless()
    }

    private func openAndFocusMainWindow() {

        DispatchQueue.main.async {
            if let window = self.appDelegate?.mainWindow {
                // Reuse the existing window
                window.makeKeyAndOrderFront(nil)
            } else {
                // Trigger creation
                self.openWindow(id: "main")
            }

            // Bring app + window to the front once
            NSApp.activate(ignoringOtherApps: true)
        }
    }



    private func getDeviceName() -> String {
        appState.device?.name ?? "Ready"
    }

    private let minWidthTabs: CGFloat = 360
    private let toolButtonSize: CGFloat = 42

    var body: some View {
        VStack(spacing: 6) {
            // Arrow (if needed, but usually we just want it on the top segment)
            ZStack(alignment: .top) {
                PopoverArrow()
                    .fill(.ultraThinMaterial)
                    .frame(width: 16, height: 8)
                    .offset(y: -8)
                    .applyGlassViewIfAvailable() // Match the style
                
                TopSegmentView(
                    toolButtonSize: toolButtonSize,
                    openAndFocusMainWindow: openAndFocusMainWindow
                )
            }
            .padding(.top, 8)
            
            DiscoverySegmentView()
            
//            StatusSegmentView()
            
            MediaSegmentView()
            
            NotificationsSegmentView()
        }
        .padding(.horizontal, 24)
        .padding(.bottom, 24)
        .frame(width: minWidthTabs + 48)
        .environment(\.controlActiveState, .active)
        .onAppear {
            appState.isMenubarWindowOpen = true
        }
        .onDisappear {
            appState.isMenubarWindowOpen = false
        }
    }
}

#Preview {
    MenubarView()
}
