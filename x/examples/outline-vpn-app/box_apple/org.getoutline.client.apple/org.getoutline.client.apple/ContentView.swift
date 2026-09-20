//
//  ContentView.swift
//  org.getoutline.client.apple
//
//  Created by Daniel LaCosse on 3/5/24.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        WebView(url: URL(string: "http://localhost:8080/")!)
    }
}

#Preview {
    ContentView()
}
