package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/Jigsaw-Code/outline-sdk/x/config"
	"github.com/Jigsaw-Code/outline-sdk/x/mobileproxy"
	"github.com/a-h/templ"
)

var appAddress = "[::1]:8080"
var proxyAddress = "[::1]:8181"
var systemAddress = "[::1]:8282"

var proxyDisconnectTimeoutSecond = 5
var systemTunnelEndpoint = fmt.Sprintf("%s/vpn/", systemAddress)

type VPNController struct {
	ID     string
	Proxy  *mobileproxy.Proxy
	Config VPNConfig
}

type VPNConfig struct {
	Source string
	Target string
}

func Start() {
	vpn := VPNController{ID: ""}

	http.Handle("/", templ.Handler(serverView()))
	http.Handle("/connection/ss://<my-shadowsocks-key>", http.HandlerFunc(vpn.handleConnectionEndpoint))
	http.Handle("/disconnection/ss://<my-shadowsocks-key>", http.HandlerFunc(vpn.handleDisconnectionEndpoint))

	http.ListenAndServe(appAddress, nil)
}

func (vpn *VPNController) handleConnectionEndpoint(responseWriter http.ResponseWriter, request *http.Request) {
	proxyDialer, err := config.NewStreamDialer(request.URL.Path)

	if err != nil {
		http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
		return
	}

	proxy, err := mobileproxy.RunProxy(proxyAddress, &mobileproxy.StreamDialer{proxyDialer})

	if err != nil {
		http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
		return
	}

	vpn.Proxy = proxy
	vpn.Config = VPNConfig{Source: "*", Target: proxyAddress}

	// TODO: implement system vpn tunnel service
	// => POST /vpn { config: { source: "	", target: "	" } }
	// create a new vpn configuration, return ID
	// => PATCH /vpn/:id { start: true }
	// update vpn configuration, including turn it on or off

	// => apple box uses VPN API
	// => kotlin box uses SSH tunnel (for now)

	// ! these boxes will be reusable across VPN apps !

	if vpn.ID == "" {
		payload, err := json.Marshal(vpn.Config)
		response, err := http.Post(systemTunnelEndpoint, "application/json", bytes.NewReader(payload))

		if err != nil {
			log.Fatal(err)
		}

		body, err := io.ReadAll(response.Body)
		if err != nil {
			log.Fatalln(err)
		}

		vpn.ID = string(body)
	} else {
		toggleConnection(*vpn, true)
	}

	writeTemplate(disconnectionButton, responseWriter)
}

func (vpn *VPNController) handleDisconnectionEndpoint(responseWriter http.ResponseWriter, _ *http.Request) {
	toggleConnection(*vpn, false)

	vpn.Proxy.Stop(proxyDisconnectTimeoutSecond)

	writeTemplate(connectionButton, responseWriter)
}

// TODO: template arguments
func writeTemplate(template func() templ.Component, writer io.Writer) {
	component := template()
	component.Render(context.Background(), writer)
}

func toggleConnection(vpn VPNController, state bool) {
	payload, err := json.Marshal(map[string]interface{}{
		"start": state,
	})
	if err != nil {
		log.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodPut, systemTunnelEndpoint+vpn.ID, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{}
	client.Do(request)
}
