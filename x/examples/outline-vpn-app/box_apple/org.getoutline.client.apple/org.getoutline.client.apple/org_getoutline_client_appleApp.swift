//
//  org_getoutline_client_appleApp.swift
//  org.getoutline.client.apple
//
//  Created by Daniel LaCosse on 3/5/24.
//

import SwiftUI
import Foundation
import Fullstack_app
import UIKit

@main
struct org_getoutline_client_appleApp: App {
    init() {
        Thread.detachNewThread {
            Fullstack_app.Fullstack_appStart()
        }
        NSLog("started web server!")
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
