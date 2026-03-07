# SOAX Client

SOAX is a provider of Residential, Mobile, and Datacenter proxy services. This document describes how to use its API.

## Key Concepts

* **Account:** User account, tied to the email you use to log in. You need to have your identity verified in order to enable the account.
* **API Key:** Unique key tied to your account, used in the API calls. You can find it under USER > Profile. Keep it secret.
* **Package:** Proxy packages give you access to the proxy service. Packages can be of various types based on where the proxy lives, including Residential, Mobile, Datacenter. The service website has a [list of available locations](https://soax.com/proxies/locations).
* **Package ID:** A unique 6-digit identifier shown on each package in the package list UI. Used in proxy requests.
* **Package Key:** Unique key tied to a specific package you have purchased. It shows up as "Password" in the web UI, under "QUICK ACCESS". Used in the REST API and proxy requests. Keep it secret.

## SOAX Proxy API

SOAX supports both HTTP CONNECT proxies and SOCKS5 proxies. In both cases it
uses basic authentication ("username:password"), where the password is the Package Key, and the username is a configuration string specifying the parameters of the connection.

Proxy string:

```txt
package-<package_id>[-country-<country_iso>[-isp-<isp_name>][-region-<region_name>[-city-<city_name>]]][-sessionid-<session_id>-[sessionlength-<session_length>]]:<package_key>@proxy.soax.com:5000
```

The `isp_name`,`region_name` and `city_name` must be ones returned by the REST API. They may contain spaces, which should be replaced with `+` (e.g. `new+york`).

For more details, see [Sticky sessions](https://helpcenter.soax.com/en/articles/6723733-sticky-sessions).

It's helpful to use <https://checker.soax.com/api/ipinfo> to verify the location information of the proxy.

Here is an example of using SOCKS5 to connect from Germany:

```console
$ curl --proxy "socks5h://package-${SOAX_PACKAGE_ID}-country-de-isp-o2+deutschland:${SOAX_PACKAGE_KEY}@proxy.soax.com:5000" https://checker.soax.com/api/ipinfo

{"status":true,"reason":"","data":{"carrier":"O2 Deutschland","city":"Leipzig","country_code":"DE","country_name":"Germany","ip":"<redacted>","isp":"O2 Deutschland","region":"Saxony"}}
```

Here is the same request using HTTP CONNECT:

```console
$ curl --proxy "https://package-${SOAX_PACKAGE_ID}-country-de-isp-o2+deutschland:${SOAX_PACKAGE_KEY}@proxy.soax.com:5000" https://checker.soax.com/api/ipinfo

{"status":true,"reason":"","data":{"carrier":"O2 Deutschland","city":"Wuppertal","country_code":"DE","country_name":"Germany","ip":"176.1.206.77","isp":"O2 Deutschland","region":"North Rhine-Westphalia"}}
```

HTTP CONNECT is preferable because it can be done over HTTPS, which hides your credentials. That is not the case for SOCKS5. However, SOAX only supports TCP using HTTP CONNECT. For UDP, you will have to use SOCKS5 (see [HTTP vs SOCKS5 vs HTTPS: Which proxy protocol should you use?](https://helpcenter.soax.com/en/articles/7241369-http-vs-socks5-vs-https-which-proxy-protocol-should-you-use))

### Sessions

It's very important to use sessions in order to ensure your requests are using the same proxy. By default, you will get a different proxy for each request.

To use the same proxy, create a session by passing a `sessionid` and `sessionlength`, in seconds. Changing the session ID changes the proxy used. When session length expires, you may get a new proxy.

For advanced session parameters, see [Understanding session parameters](https://helpcenter.soax.com/en/articles/9939557-understanding-session-parameters).

## SOAX REST API

[API Reference](https://helpcenter.soax.com/en/collections/3470979-api).

API calls require both an API key, tied to the account, and a Package key, tied to the purchased package.

Note that the APIs for mobile and residential packages differ a bit.

### Get list of mobile carriers

This is for Mobile packages only.

[Reference](https://helpcenter.soax.com/en/articles/6228381-getting-a-list-of-mobile-carriers)

Request format:

```txt
https://api.soax.com/api/get-country-operators?api_key=<api_key>&package_key=<package_key>&country_iso=<country_iso>[&region=<region_name>[&city=<city_name>]]
```

Here is an example of listing the mobile ISPs in Russia:

```console
$ curl "https://api.soax.com/api/get-country-operators?api_key=$SOAX_API_KEY&package_key=$SOAX_PACKAGE_KEY&country_iso=ru"

["pjsc megafon","mts pjsc","tele2 russia","beeline","rostelecom","jsc ufanet","edinos","ekaterinburg-2000","tbank jsc","er-telecom","t-mob","mcs","dom.ru","sberbank-telecom","llc sp abaza telecom","s.u.e. dpr republic operator of networks","tattelecom","edinos ltd.","invest mobile","isp balzer-telecom","innovation solutions center ltd.","novokuznetsk telecom","mobile trend","ooo network of data-centers selectel","dagnet","jv a-mobile","llc alfa-mobile","zao aquafon-gsm","ooo vtc-mobile"]
```

### Get list of residential ISPs

This is for Residential packages only. The official documentation refers to them as "WiFi ISPs".

[Reference](https://helpcenter.soax.com/en/articles/6228391-getting-a-list-of-wifi-isps)

Request format:

```txt
https://api.soax.com/api/get-country-isp?api_key=<api_key>&package_key=<package_key>&country_iso=<country_iso>[&region=<region_name>[&city=<city_name>]]
```

### Get list of regions

[Reference](https://helpcenter.soax.com/en/articles/6227864-getting-a-list-of-regions)

Request format:

```txt
https://api.soax.com/api/get-country-regions?api_key=<api_key>&package_key=<package_key>&country_iso=<country_iso>&conn_type=<conn_type>[&provider=<provider>]
```

The `conn_type` parameter specifies the connection type. It must be `wifi` for Residential packages and `mobile` for Mobile packages.

Here is an example of listing regions in Iran:

```console
$ curl  "https://api.soax.com/api/get-country-regions?api_key=$SOAX_API_KEY&package_key=$SOAX_PACKAGE_KEY&country_iso=ir&conn_type=mobile"

["tehran","razavi khorasan","fars","isfahan","khuzestan","east azerbaijan province","alborz province","mazandaran","west azerbaijan province","gilan province","qom province"]
```

### Get list of cities

[Reference](https://helpcenter.soax.com/en/articles/6228092-getting-a-list-of-cities)

Request format:

```txt
https://api.soax.com/api/get-country-cities?api_key=<api_key>&package_key=<package_key>&country_iso=<country_iso>&conn_type=<conn_type>[&provider=<provider_name>[&region=<region_name>]]
```

The `conn_type` parameter specifies the connection type. It must be `wifi` for Residential packages and `mobile` for Mobile packages.

## Testing

Unit tests use a mock server and run with `go test ./...`.

Integration tests against the live SOAX API are in `api_integration_test.go` and require credentials:

```sh
SOAX_API_KEY=<api_key> SOAX_PACKAGE_KEY=<package_key> go test -run TestLiveAPI -v
```

Note that `TestLiveAPI_GetResidentialISPs` requires a Residential package and will fail with a Mobile package, and `TestLiveAPI_GetMobileISPs` requires a Mobile package and will fail with a Residential package.
