import SwiftUI

struct TrustedNetworksSettingsView: View {
    @ObservedObject private var store = TrustedLANNetwork.shared
    @ObservedObject private var relay = AirBridgeClient.shared
    @ObservedObject private var server = WebSocketServer.shared
    @State private var networkName = ""
    @State private var adding = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if store.isEnrolling {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(L("networks.checking")).font(.callout)
                }
                .accessibilityElement(children: .combine)
            } else if !store.status.hasPrefix("Recognized:") && store.status != "Unknown network · using Airbridge" {
                Text(store.status).font(.caption).foregroundStyle(.secondary)
            }
            if store.networks.isEmpty {
                Text(L("networks.empty")).foregroundStyle(.secondary)
            }
            ForEach(store.networks) { network in
                TrustedNetworkSettingsRow(network: network, current: store.currentNetworkIDs.contains(network.id))
            }
            if adding {
                Divider()
                TextField(L("networks.name"), text: $networkName)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: networkName) { _, value in
                        if value.utf16.count > 80 {
                            var clipped = value
                            while clipped.utf16.count > 80 { clipped.removeLast() }
                            networkName = clipped
                        }
                    }
                    .onSubmit { addNetwork() }
                HStack {
                    Spacer()
                    Button(L("networks.cancel")) { adding = false; networkName = "" }
                    Button(L("networks.addShort")) { addNetwork() }
                        .disabled(!canAdd)
                }
            } else {
                Button { adding = true } label: {
                    Label(L("networks.add"), systemImage: "plus")
                }
                .disabled(store.isEnrolling || (relay.connectionState != .relayActive && !server.hasActiveLocalSession()))
            }
        }
        .onAppear { store.refresh() }
        .onChange(of: store.isEnrolling) { _, enrolling in
            if enrolling { adding = false; networkName = "" }
        }
    }

    private var canAdd: Bool {
        !networkName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !store.isEnrolling &&
            (relay.connectionState == .relayActive || server.hasActiveLocalSession())
    }

    private func addNetwork() {
        guard canAdd else { return }
        store.beginEnrollment(name: networkName)
    }
}

private struct TrustedNetworkSettingsRow: View {
    let network: TrustedNetwork
    let current: Bool
    @State private var editing = false
    @State private var name = ""
    @State private var confirmingRemoval = false

    var body: some View {
        HStack(spacing: 10) {
            if editing {
                TextField(L("networks.name"), text: $name).textFieldStyle(.roundedBorder)
                Button(L("networks.cancel")) { editing = false }
                Button(L("networks.save")) {
                    TrustedLANNetwork.shared.rename(network.id, name: name)
                    editing = false
                }
                .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || name.utf16.count > 80)
            } else {
                Image(systemName: "network").foregroundStyle(current ? Color.accentColor : .secondary)
                Text(network.name).lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 8)
                if current { Text(L("networks.current")).font(.caption).foregroundStyle(.secondary) }
                Menu {
                    Button(L("networks.rename")) { name = network.name; editing = true }
                    Button(L("networks.remove"), role: .destructive) { confirmingRemoval = true }
                } label: {
                    Image(systemName: "ellipsis")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel(L("networks.actions") + " " + network.name)
            }
        }
        .padding(.vertical, 4)
        .confirmationDialog(L("networks.removeQuestion"), isPresented: $confirmingRemoval, titleVisibility: .visible) {
            Button(L("networks.remove"), role: .destructive) { TrustedLANNetwork.shared.remove(network.id) }
        }
    }
}
