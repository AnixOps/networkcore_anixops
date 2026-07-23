use config_core::{
    parse_config_document, CoreConfigurationService, CoreSubscriptionService,
    CONFIG_LISTENER_BIND_PORT_INVALID_CODE, CONFIG_LISTENER_NETWORK_UNSUPPORTED_CODE,
    CONFIG_LISTENER_ROUTE_CONFLICT_CODE, CONFIG_LISTENER_ROUTE_MISSING_CODE,
    CONFIG_MIGRATION_UNSUPPORTED_CODE, CONFIG_NODE_HOST_EMPTY_CODE, CONFIG_NODE_PORT_INVALID_CODE,
    CONFIG_PARSE_FAILED_CODE, CONFIG_PROFILE_CONFLICT_CODE, CONFIG_PROFILE_EMPTY_CODE,
    CONFIG_PROFILE_MISSING_CODE, CONFIG_ROUTE_PROXY_NODE_MISSING_CODE,
    CONFIG_SCHEMA_UNSUPPORTED_CODE, CURRENT_SCHEMA_VERSION, SUBSCRIPTION_FETCH_UNSUPPORTED_CODE,
    SUBSCRIPTION_LINK_UNSUPPORTED_CODE, SUBSCRIPTION_PARSE_FAILED_CODE,
    SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
};
use control_domain::{
    ConfigurationService, Diagnostic, ListenerKind, ListenerNetwork, ListenerRoute, MetadataEntry,
    OperatingSystem, PlatformCapabilities, Protocol, RawSubscription, RouteAction, SchemaVersion,
    SubscriptionService, SubscriptionSource, NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE,
    NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE, NODE_METADATA_HYSTERIA2_OBFS_PASSWORD,
    NODE_METADATA_HYSTERIA2_OBFS_TYPE, NODE_METADATA_HYSTERIA2_PASSWORD,
    NODE_METADATA_HYSTERIA2_SERVER_PORTS, NODE_METADATA_SHADOWSOCKS_METHOD,
    NODE_METADATA_SHADOWSOCKS_PASSWORD, NODE_METADATA_SOURCE_FORMAT, NODE_METADATA_TLS_ALPN,
    NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256, NODE_METADATA_TLS_INSECURE,
    NODE_METADATA_TLS_SERVER_NAME, NODE_METADATA_TROJAN_PASSWORD,
    NODE_METADATA_TUIC_CONGESTION_CONTROL, NODE_METADATA_TUIC_PASSWORD, NODE_METADATA_TUIC_UUID,
    NODE_METADATA_VLESS_UUID, NODE_METADATA_VMESS_UUID,
};

#[test]
fn normalizes_profile_list_from_minimal_toml() {
    let service = CoreConfigurationService::new();
    let snapshot = service
        .normalize(
            r#"
schema_version = 1
profiles = ["default", "work"]
"#,
            &capabilities(),
        )
        .expect("minimal config should normalize");

    assert_eq!(snapshot.version, SchemaVersion::new(CURRENT_SCHEMA_VERSION));
    assert_eq!(
        snapshot.profiles,
        vec!["default".to_string(), "work".to_string()]
    );
    assert!(snapshot.listeners.is_empty());
    assert!(snapshot.nodes.is_empty());
    assert!(snapshot.policies.is_empty());
    assert!(snapshot.dns.is_empty());
    assert!(snapshot.plugins.is_empty());
}

#[test]
fn normalizes_listener_node_and_route_subset_from_toml() {
    let service = CoreConfigurationService::new();
    let snapshot = service
        .normalize(
            r#"
schema_version = 1
profile = "default"

[[nodes]]
id = "node-1"
name = "Local SOCKS"
protocol = "socks"
host = "127.0.0.1"
port = 1081
tags = ["local", "  dev  ", ""]

[[routes]]
id = "default-route"
default_action = "proxy"
default_node = "node-1"

[[listeners]]
id = "loopback-socks"
enabled = true
kind = "socks"
bind_host = "127.0.0.1"
bind_port = 1080
network = "tcp"
route = "default-route"
tags = ["local"]
metadata = { owner = "user" }
"#,
            &capabilities(),
        )
        .expect("listener/node/route config should normalize");

    assert_eq!(snapshot.listeners.len(), 1);
    let listener = &snapshot.listeners[0];
    assert_eq!(listener.id, "loopback-socks");
    assert!(listener.enabled);
    assert_eq!(listener.kind, ListenerKind::Socks);
    assert_eq!(listener.bind.host, "127.0.0.1");
    assert_eq!(listener.bind.port, 1080);
    assert_eq!(listener.network, ListenerNetwork::Tcp);
    assert_eq!(
        listener.route,
        ListenerRoute::RuleSet {
            rule_set_id: "default-route".to_string()
        }
    );
    assert_eq!(listener.metadata[0].key, "owner");

    assert_eq!(snapshot.nodes.len(), 1);
    let node = &snapshot.nodes[0];
    assert_eq!(node.id, "node-1");
    assert_eq!(node.name, "Local SOCKS");
    assert_eq!(node.protocol, Protocol::Socks);
    assert_eq!(node.endpoint.host, "127.0.0.1");
    assert_eq!(node.endpoint.port, 1081);
    assert_eq!(node.tags, vec!["local".to_string(), "dev".to_string()]);
    assert!(node.metadata.is_empty());

    assert_eq!(snapshot.policies.len(), 1);
    assert_eq!(snapshot.policies[0].id, "default-route");
    assert!(snapshot.policies[0].rules.is_empty());
    assert_eq!(
        snapshot.policies[0].default_action,
        RouteAction::Proxy {
            node_id: "node-1".to_string()
        }
    );
}

#[test]
fn parses_single_shadowsocks_url_subscription_into_node_catalog() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "manual-url".to_string(),
        content: "ss://YWVzLTI1Ni1nY206ZjQzYzBlZWUtMTNiOS00ZjA3LWJlYzktZDRiNzQ0MTQxNTAz@82.47.34.99:11111#%E9%A6%99%E6%B8%AF".to_string(),
    };

    let document = service
        .parse(&raw)
        .expect("ss url should parse into a subscription document");
    let catalog = service
        .normalize(&document)
        .expect("ss url document should normalize");

    assert_eq!(catalog.nodes.len(), 1);
    let node = &catalog.nodes[0];
    assert_eq!(node.id, "ss-82-47-34-99-11111");
    assert_eq!(node.name, "香港");
    assert_eq!(node.protocol, Protocol::Shadowsocks);
    assert_eq!(node.endpoint.host, "82.47.34.99");
    assert_eq!(node.endpoint.port, 11111);
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_METHOD,
        "aes-256-gcm",
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_PASSWORD,
        "f43c0eee-13b9-4f07-bec9-d4b744141503",
    );
}

#[test]
fn parses_base64_plaintext_link_list_subscription() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "base64-list".to_string(),
        content: "c3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2WmpRek16QmxaV1V0TVROaU9TMDBaakEzTFdKbFl6a3RaRFJpTnpRME1UUXhOVEF6QDgyLjQ3LjM0Ljk5OjExMTExI0hLCg==".to_string(),
    };

    let document = service.parse(&raw).expect("base64 link list should parse");

    assert_eq!(document.nodes.len(), 1);
    assert_eq!(document.nodes[0].name, "HK");
}

#[test]
fn parses_single_trojan_url_subscription_into_node_catalog() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "trojan-url".to_string(),
        content: "trojan://pa%40ss@example.com:443?sni=edge.example.com#HK%20Trojan".to_string(),
    };

    let document = service
        .parse(&raw)
        .expect("trojan url should parse into a subscription document");
    let catalog = service
        .normalize(&document)
        .expect("trojan url document should normalize");

    assert_eq!(catalog.nodes.len(), 1);
    let node = &catalog.nodes[0];
    assert_eq!(node.id, "trojan-example-com-443");
    assert_eq!(node.name, "HK Trojan");
    assert_eq!(node.protocol, Protocol::Trojan);
    assert_eq!(node.endpoint.host, "example.com");
    assert_eq!(node.endpoint.port, 443);
    assert_eq!(
        node.tags,
        vec!["subscription".to_string(), "trojan".to_string()]
    );
    assert_metadata(&node.metadata, NODE_METADATA_TROJAN_PASSWORD, "pa@ss");
    assert_metadata(&node.metadata, NODE_METADATA_SOURCE_FORMAT, "trojan-url");
    assert_metadata(&node.metadata, "subscription.source_id", "trojan-url");
}

#[test]
fn parses_single_vless_url_subscription_into_node_catalog() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "vless-url".to_string(),
        content:
            "vless://2f4d1d6d-7fd5-4a0f-90f0-1d3fb2fb5f1d@example.net:443?encryption=none&type=tcp#US%20VLESS"
                .to_string(),
    };

    let document = service
        .parse(&raw)
        .expect("vless url should parse into a subscription document");
    assert!(document.diagnostics.is_empty());
    let catalog = service
        .normalize(&document)
        .expect("vless url document should normalize");

    assert_eq!(catalog.nodes.len(), 1);
    assert!(catalog.rules.is_empty());
    let node = &catalog.nodes[0];
    assert_eq!(node.id, "vless-example-net-443");
    assert_eq!(node.name, "US VLESS");
    assert_eq!(node.protocol, Protocol::Vless);
    assert_eq!(node.endpoint.host, "example.net");
    assert_eq!(node.endpoint.port, 443);
    assert_eq!(
        node.tags,
        vec!["subscription".to_string(), "vless".to_string()]
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_VLESS_UUID,
        "2f4d1d6d-7fd5-4a0f-90f0-1d3fb2fb5f1d",
    );
    assert_metadata(&node.metadata, NODE_METADATA_SOURCE_FORMAT, "vless-url");
    assert_metadata(&node.metadata, "subscription.source_id", "vless-url");
}

#[test]
fn parses_single_vmess_url_subscription_into_node_catalog() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "vmess-url".to_string(),
        content: concat!(
            "vmess://",
            "eyJ2IjoiMiIsInBzIjoiSlAgVk1lc3MiLCJhZGQiOiJlZGdlLmV4YW1wbGUu",
            "bmV0IiwicG9ydCI6IjQ0MyIsImlkIjoiN2YwZjNmOTUtN2Q4My00YmIyLWJm",
            "ODQtMmYyZTdlMmE4ZDJkIiwiYWlkIjoiMCIsIm5ldCI6InRjcCIsInR5cGUi",
            "OiJub25lIiwiaG9zdCI6IiIsInBhdGgiOiIiLCJ0bHMiOiJ0bHMifQ=="
        )
        .to_string(),
    };

    let document = service
        .parse(&raw)
        .expect("vmess url should parse into a subscription document");
    assert!(document.diagnostics.is_empty());
    let catalog = service
        .normalize(&document)
        .expect("vmess url document should normalize");

    assert_eq!(catalog.nodes.len(), 1);
    assert!(catalog.rules.is_empty());
    let node = &catalog.nodes[0];
    assert_eq!(node.id, "vmess-edge-example-net-443");
    assert_eq!(node.name, "JP VMess");
    assert_eq!(node.protocol, Protocol::Vmess);
    assert_eq!(node.endpoint.host, "edge.example.net");
    assert_eq!(node.endpoint.port, 443);
    assert_eq!(
        node.tags,
        vec!["subscription".to_string(), "vmess".to_string()]
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_VMESS_UUID,
        "7f0f3f95-7d83-4bb2-bf84-2f2e7e2a8d2d",
    );
    assert_metadata(&node.metadata, NODE_METADATA_SOURCE_FORMAT, "vmess-url");
    assert_metadata(&node.metadata, "subscription.source_id", "vmess-url");
}

#[test]
fn parses_clash_yaml_subscription_into_node_catalog() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "clash-yaml".to_string(),
        content: r#"
proxies:
  - name: HK Clash
    type: ss
    server: 82.47.34.99
    port: 11111
    cipher: aes-256-gcm
    password: f43c0eee-13b9-4f07-bec9-d4b744141503
proxy-groups: []
rules: []
"#
        .to_string(),
    };

    let document = service
        .parse(&raw)
        .expect("clash yaml should parse into a subscription document");
    assert!(document.diagnostics.is_empty());
    let catalog = service
        .normalize(&document)
        .expect("clash yaml document should normalize");

    assert_eq!(catalog.nodes.len(), 1);
    assert!(catalog.rules.is_empty());
    let node = &catalog.nodes[0];
    assert_eq!(node.id, "clash-ss-hk-clash");
    assert_eq!(node.name, "HK Clash");
    assert_eq!(node.protocol, Protocol::Shadowsocks);
    assert_eq!(node.endpoint.host, "82.47.34.99");
    assert_eq!(node.endpoint.port, 11111);
    assert_eq!(
        node.tags,
        vec![
            "subscription".to_string(),
            "clash-yaml".to_string(),
            "ss".to_string()
        ]
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_METHOD,
        "aes-256-gcm",
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_PASSWORD,
        "f43c0eee-13b9-4f07-bec9-d4b744141503",
    );
    assert_metadata(&node.metadata, NODE_METADATA_SOURCE_FORMAT, "clash-yaml");
    assert_metadata(&node.metadata, "subscription.source_id", "clash-yaml");
}

#[test]
fn parses_sing_box_json_subscription_into_node_catalog() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "sing-box-json".to_string(),
        content: r#"
{
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "shadowsocks",
      "tag": "HK sing-box",
      "server": "82.47.34.99",
      "server_port": 11111,
      "method": "aes-256-gcm",
      "password": "f43c0eee-13b9-4f07-bec9-d4b744141503"
    }
  ]
}
"#
        .to_string(),
    };

    let document = service
        .parse(&raw)
        .expect("sing-box json should parse into a subscription document");
    assert!(document.diagnostics.is_empty());
    let catalog = service
        .normalize(&document)
        .expect("sing-box json document should normalize");

    assert_eq!(catalog.nodes.len(), 1);
    assert!(catalog.rules.is_empty());
    let node = &catalog.nodes[0];
    assert_eq!(node.id, "sing-box-ss-hk-sing-box");
    assert_eq!(node.name, "HK sing-box");
    assert_eq!(node.protocol, Protocol::Shadowsocks);
    assert_eq!(node.endpoint.host, "82.47.34.99");
    assert_eq!(node.endpoint.port, 11111);
    assert_eq!(
        node.tags,
        vec![
            "subscription".to_string(),
            "sing-box-json".to_string(),
            "ss".to_string()
        ]
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_METHOD,
        "aes-256-gcm",
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_PASSWORD,
        "f43c0eee-13b9-4f07-bec9-d4b744141503",
    );
    assert_metadata(&node.metadata, NODE_METADATA_SOURCE_FORMAT, "sing-box-json");
    assert_metadata(&node.metadata, "subscription.source_id", "sing-box-json");
}

#[test]
fn parses_hysteria2_and_tuic_share_links_with_quic_tls_options() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "quic-share-links".to_string(),
        content: concat!(
            "hysteria2://hy2%2Dpassword@edge.example.test:443?mport=2000-2002&sni=cdn.example.test&alpn=h3%2Ch2&insecure=1&pinSHA256=pin-A&obfs=gecko&obfs-password=mask&minPacketSize=512&maxPacketSize=1200#Hysteria%202\n",
            "tuic://00000000-0000-0000-0000-000000000001:tuic%2Dpassword@tuic.example.test:443?sni=cdn.tuic.example.test&alpn=h3&allowInsecure=1&congestion_control=bbr#TUIC%20Node"
        )
        .to_string(),
    };

    let document = service
        .parse(&raw)
        .expect("Hysteria2 and TUIC share links should parse");
    let catalog = service
        .normalize(&document)
        .expect("QUIC share link document should normalize");

    assert_eq!(catalog.nodes.len(), 2);
    let hysteria2 = &catalog.nodes[0];
    assert_eq!(hysteria2.id, "hysteria2-edge-example-test-443");
    assert_eq!(hysteria2.name, "Hysteria 2");
    assert_eq!(hysteria2.protocol, Protocol::Hysteria2);
    assert_eq!(hysteria2.endpoint.host, "edge.example.test");
    assert_eq!(hysteria2.endpoint.port, 443);
    assert_eq!(
        hysteria2.tags,
        vec!["subscription".to_string(), "hysteria2".to_string()]
    );
    assert_metadata(
        &hysteria2.metadata,
        NODE_METADATA_HYSTERIA2_PASSWORD,
        "hy2-password",
    );
    assert_metadata(
        &hysteria2.metadata,
        NODE_METADATA_HYSTERIA2_SERVER_PORTS,
        "2000:2002",
    );
    assert_metadata(
        &hysteria2.metadata,
        NODE_METADATA_HYSTERIA2_OBFS_TYPE,
        "gecko",
    );
    assert_metadata(
        &hysteria2.metadata,
        NODE_METADATA_HYSTERIA2_OBFS_PASSWORD,
        "mask",
    );
    assert_metadata(
        &hysteria2.metadata,
        NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE,
        "512",
    );
    assert_metadata(
        &hysteria2.metadata,
        NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE,
        "1200",
    );
    assert_metadata(
        &hysteria2.metadata,
        NODE_METADATA_TLS_SERVER_NAME,
        "cdn.example.test",
    );
    assert_metadata(&hysteria2.metadata, NODE_METADATA_TLS_INSECURE, "true");
    assert_metadata(&hysteria2.metadata, NODE_METADATA_TLS_ALPN, "h3,h2");
    assert_metadata(
        &hysteria2.metadata,
        NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256,
        "pin-A",
    );
    assert_metadata(
        &hysteria2.metadata,
        NODE_METADATA_SOURCE_FORMAT,
        "hysteria2-url",
    );
    assert_metadata(
        &hysteria2.metadata,
        "subscription.source_id",
        "quic-share-links",
    );

    let tuic = &catalog.nodes[1];
    assert_eq!(tuic.id, "tuic-tuic-example-test-443");
    assert_eq!(tuic.name, "TUIC Node");
    assert_eq!(tuic.protocol, Protocol::Tuic);
    assert_metadata(
        &tuic.metadata,
        NODE_METADATA_TUIC_UUID,
        "00000000-0000-0000-0000-000000000001",
    );
    assert_metadata(&tuic.metadata, NODE_METADATA_TUIC_PASSWORD, "tuic-password");
    assert_metadata(&tuic.metadata, NODE_METADATA_TUIC_CONGESTION_CONTROL, "bbr");
    assert_metadata(
        &tuic.metadata,
        NODE_METADATA_TLS_SERVER_NAME,
        "cdn.tuic.example.test",
    );
    assert_metadata(&tuic.metadata, NODE_METADATA_TLS_INSECURE, "true");
    assert_metadata(&tuic.metadata, NODE_METADATA_TLS_ALPN, "h3");
    assert_metadata(&tuic.metadata, NODE_METADATA_SOURCE_FORMAT, "tuic-url");
    assert_metadata(&tuic.metadata, "subscription.source_id", "quic-share-links");
}

#[test]
fn parses_hysteria2_and_tuic_sing_box_outbounds_into_node_catalog() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "sing-box-quic".to_string(),
        content: r#"
{
  "outbounds": [
    {
      "type": "hysteria2",
      "tag": "Hysteria2 JSON",
      "server": "hy2.example.test",
      "server_ports": ["3000:3002"],
      "password": "hy2-password",
      "obfs": {
        "type": "gecko",
        "password": "mask",
        "min_packet_size": 512,
        "max_packet_size": 1200
      },
      "tls": {
        "server_name": "cdn.hy2.example.test",
        "insecure": true,
        "alpn": ["h3", "h2"],
        "certificate_public_key_sha256": ["pin-A"]
      }
    },
    {
      "type": "tuic",
      "tag": "TUIC JSON",
      "server": "tuic.example.test",
      "server_port": 443,
      "uuid": "00000000-0000-0000-0000-000000000002",
      "password": "tuic-password",
      "congestion_control": "bbr",
      "tls": {
        "server_name": "cdn.tuic.example.test",
        "alpn": "h3"
      }
    }
  ]
}
"#
        .to_string(),
    };

    let document = service
        .parse(&raw)
        .expect("sing-box QUIC outbounds should parse");
    let catalog = service
        .normalize(&document)
        .expect("sing-box QUIC document should normalize");

    assert_eq!(catalog.nodes.len(), 2);
    let hysteria2 = &catalog.nodes[0];
    assert_eq!(hysteria2.id, "sing-box-hysteria2-hysteria2-json");
    assert_eq!(hysteria2.endpoint.port, 3000);
    assert_eq!(hysteria2.protocol, Protocol::Hysteria2);
    assert_metadata(
        &hysteria2.metadata,
        NODE_METADATA_HYSTERIA2_SERVER_PORTS,
        "3000:3002",
    );
    assert_metadata(
        &hysteria2.metadata,
        NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256,
        "pin-A",
    );
    assert_metadata(
        &hysteria2.metadata,
        "subscription.source_id",
        "sing-box-quic",
    );

    let tuic = &catalog.nodes[1];
    assert_eq!(tuic.id, "sing-box-tuic-tuic-json");
    assert_eq!(tuic.protocol, Protocol::Tuic);
    assert_metadata(
        &tuic.metadata,
        NODE_METADATA_TUIC_UUID,
        "00000000-0000-0000-0000-000000000002",
    );
    assert_metadata(&tuic.metadata, NODE_METADATA_TUIC_CONGESTION_CONTROL, "bbr");
    assert_metadata(&tuic.metadata, NODE_METADATA_TLS_INSECURE, "false");
}

#[test]
fn parses_quantumult_x_proxy_line_subscription_into_node_catalog() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "quantumult-x-proxy-line".to_string(),
        content: r#"
[general]
profile_img_url = https://example.invalid/profile.png

[server_local]
shadowsocks=82.47.34.99:11111, method=aes-256-gcm, password="f43c0eee-13b9-4f07-bec9-d4b744141503", tag=HK Quantumult X

[policy]
static=Proxy, HK Quantumult X
"#
        .to_string(),
    };

    let document = service
        .parse(&raw)
        .expect("quantumult x proxy lines should parse into a subscription document");
    assert!(document.diagnostics.is_empty());
    let catalog = service
        .normalize(&document)
        .expect("quantumult x proxy document should normalize");

    assert_eq!(catalog.nodes.len(), 1);
    assert!(catalog.rules.is_empty());
    let node = &catalog.nodes[0];
    assert_eq!(node.id, "quantumult-x-ss-hk-quantumult-x");
    assert_eq!(node.name, "HK Quantumult X");
    assert_eq!(node.protocol, Protocol::Shadowsocks);
    assert_eq!(node.endpoint.host, "82.47.34.99");
    assert_eq!(node.endpoint.port, 11111);
    assert_eq!(
        node.tags,
        vec![
            "subscription".to_string(),
            "quantumult-x-proxy-line".to_string(),
            "ss".to_string()
        ]
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_METHOD,
        "aes-256-gcm",
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_PASSWORD,
        "f43c0eee-13b9-4f07-bec9-d4b744141503",
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SOURCE_FORMAT,
        "quantumult-x-proxy-line",
    );
    assert_metadata(
        &node.metadata,
        "subscription.source_id",
        "quantumult-x-proxy-line",
    );
}

#[test]
fn parses_loon_proxy_line_subscription_into_node_catalog() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "loon-proxy-line".to_string(),
        content: r#"
[General]
loglevel = notify

[Proxy]
HK Loon = Shadowsocks, 82.47.34.99, 11111, aes-256-gcm, "f43c0eee-13b9-4f07-bec9-d4b744141503"

[Proxy Group]
Proxy = select, HK Loon
"#
        .to_string(),
    };

    let document = service
        .parse(&raw)
        .expect("loon proxy lines should parse into a subscription document");
    assert!(document.diagnostics.is_empty());
    let catalog = service
        .normalize(&document)
        .expect("loon proxy document should normalize");

    assert_eq!(catalog.nodes.len(), 1);
    assert!(catalog.rules.is_empty());
    let node = &catalog.nodes[0];
    assert_eq!(node.id, "loon-ss-hk-loon");
    assert_eq!(node.name, "HK Loon");
    assert_eq!(node.protocol, Protocol::Shadowsocks);
    assert_eq!(node.endpoint.host, "82.47.34.99");
    assert_eq!(node.endpoint.port, 11111);
    assert_eq!(
        node.tags,
        vec![
            "subscription".to_string(),
            "loon-proxy-line".to_string(),
            "ss".to_string()
        ]
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_METHOD,
        "aes-256-gcm",
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_PASSWORD,
        "f43c0eee-13b9-4f07-bec9-d4b744141503",
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SOURCE_FORMAT,
        "loon-proxy-line",
    );
    assert_metadata(&node.metadata, "subscription.source_id", "loon-proxy-line");
}

#[test]
fn parses_surge_proxy_line_subscription_into_node_catalog() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "surge-proxy-line".to_string(),
        content: r#"
[General]
loglevel = notify

[Proxy]
HK Surge = ss, 82.47.34.99, 11111, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141503

[Proxy Group]
Proxy = select, HK Surge
"#
        .to_string(),
    };

    let document = service
        .parse(&raw)
        .expect("surge proxy lines should parse into a subscription document");
    assert!(document.diagnostics.is_empty());
    let catalog = service
        .normalize(&document)
        .expect("surge proxy document should normalize");

    assert_eq!(catalog.nodes.len(), 1);
    assert!(catalog.rules.is_empty());
    let node = &catalog.nodes[0];
    assert_eq!(node.id, "surge-ss-hk-surge");
    assert_eq!(node.name, "HK Surge");
    assert_eq!(node.protocol, Protocol::Shadowsocks);
    assert_eq!(node.endpoint.host, "82.47.34.99");
    assert_eq!(node.endpoint.port, 11111);
    assert_eq!(
        node.tags,
        vec![
            "subscription".to_string(),
            "surge-proxy-line".to_string(),
            "ss".to_string()
        ]
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_METHOD,
        "aes-256-gcm",
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SHADOWSOCKS_PASSWORD,
        "f43c0eee-13b9-4f07-bec9-d4b744141503",
    );
    assert_metadata(
        &node.metadata,
        NODE_METADATA_SOURCE_FORMAT,
        "surge-proxy-line",
    );
    assert_metadata(&node.metadata, "subscription.source_id", "surge-proxy-line");
}

#[test]
fn unsupported_proxy_link_returns_stable_subscription_diagnostic() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "unsupported".to_string(),
        content: "wireguard://example".to_string(),
    };

    let error = service
        .parse(&raw)
        .expect_err("unsupported proxy link should fail");

    assert_eq!(error.code, SUBSCRIPTION_LINK_UNSUPPORTED_CODE);
}

#[test]
fn malformed_shadowsocks_link_returns_stable_subscription_diagnostic() {
    let service = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: "bad-ss".to_string(),
        content: "ss://not-valid".to_string(),
    };

    let error = service
        .parse(&raw)
        .expect_err("malformed ss link should fail");

    assert_eq!(error.code, SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE);
}

#[test]
fn listener_can_embed_default_route_action() {
    let service = CoreConfigurationService::new();
    let snapshot = service
        .normalize(
            r#"
profiles = ["default"]

[[listeners]]
id = "direct-loopback"
enabled = false
kind = "local_tcp"
bind_host = "::1"
bind_port = 8080
network = "tcp_udp"
route_action = "direct"
"#,
            &capabilities(),
        )
        .expect("listener default action should normalize");

    assert_eq!(snapshot.listeners.len(), 1);
    assert!(!snapshot.listeners[0].enabled);
    assert_eq!(snapshot.listeners[0].kind, ListenerKind::LocalTcp);
    assert_eq!(snapshot.listeners[0].network, ListenerNetwork::TcpUdp);
    assert_eq!(
        snapshot.listeners[0].route,
        ListenerRoute::DefaultAction(RouteAction::Direct)
    );
}

#[test]
fn accepts_singular_profile_shortcut() {
    let document = parse_config_document(
        r#"
schema_version = 1
profile = "default"
"#,
    )
    .expect("singular profile should parse");

    assert_eq!(document.profiles, vec!["default".to_string()]);
    assert!(document.listeners.is_empty());
    assert!(document.nodes.is_empty());
    assert!(document.routes.is_empty());
}

#[test]
fn missing_profile_returns_stable_diagnostic() {
    let service = CoreConfigurationService::new();

    let diagnostics = service.validate("schema_version = 1", &capabilities());

    assert_diagnostic(&diagnostics, CONFIG_PROFILE_MISSING_CODE);
}

#[test]
fn empty_profile_returns_stable_diagnostic() {
    let service = CoreConfigurationService::new();

    let diagnostics = service.validate("profiles = [\"default\", \"   \"]", &capabilities());

    assert_diagnostic(&diagnostics, CONFIG_PROFILE_EMPTY_CODE);
}

#[test]
fn conflicting_profile_shapes_return_stable_diagnostic() {
    let service = CoreConfigurationService::new();
    let diagnostics = service.validate(
        r#"
profile = "default"
profiles = ["work"]
"#,
        &capabilities(),
    );

    assert_diagnostic(&diagnostics, CONFIG_PROFILE_CONFLICT_CODE);
}

#[test]
fn unsupported_schema_version_returns_domain_error() {
    let service = CoreConfigurationService::new();

    let error = service
        .normalize(
            r#"
schema_version = 2
profiles = ["default"]
"#,
            &capabilities(),
        )
        .expect_err("unsupported schema should fail");

    assert_eq!(error.code, CONFIG_SCHEMA_UNSUPPORTED_CODE);
}

#[test]
fn invalid_listener_network_returns_stable_diagnostic() {
    let service = CoreConfigurationService::new();
    let diagnostics = service.validate(
        r#"
profiles = ["default"]

[[listeners]]
id = "bad-listener"
kind = "socks"
bind_host = "127.0.0.1"
bind_port = 1080
network = "quic"
route_action = "direct"
"#,
        &capabilities(),
    );

    assert_diagnostic(&diagnostics, CONFIG_LISTENER_NETWORK_UNSUPPORTED_CODE);
}

#[test]
fn listener_route_shape_errors_return_stable_diagnostics() {
    let service = CoreConfigurationService::new();
    let missing = service.validate(
        r#"
profiles = ["default"]

[[listeners]]
id = "missing-route"
kind = "socks"
bind_host = "127.0.0.1"
bind_port = 1080
network = "tcp"
"#,
        &capabilities(),
    );
    assert_diagnostic(&missing, CONFIG_LISTENER_ROUTE_MISSING_CODE);

    let conflict = service.validate(
        r#"
profiles = ["default"]

[[listeners]]
id = "conflicting-route"
kind = "socks"
bind_host = "127.0.0.1"
bind_port = 1080
network = "tcp"
route = "default"
route_action = "direct"
"#,
        &capabilities(),
    );
    assert_diagnostic(&conflict, CONFIG_LISTENER_ROUTE_CONFLICT_CODE);
}

#[test]
fn invalid_ports_and_empty_node_host_return_stable_diagnostics() {
    let service = CoreConfigurationService::new();
    let invalid_listener_port = service.validate(
        r#"
profiles = ["default"]

[[listeners]]
id = "bad-port"
kind = "socks"
bind_host = "127.0.0.1"
bind_port = 65536
network = "tcp"
route_action = "direct"
"#,
        &capabilities(),
    );
    assert_diagnostic(
        &invalid_listener_port,
        CONFIG_LISTENER_BIND_PORT_INVALID_CODE,
    );

    let empty_node_host = service.validate(
        r#"
profiles = ["default"]

[[nodes]]
id = "node-1"
protocol = "socks"
host = "   "
port = 1081
"#,
        &capabilities(),
    );
    assert_diagnostic(&empty_node_host, CONFIG_NODE_HOST_EMPTY_CODE);

    let invalid_node_port = service.validate(
        r#"
profiles = ["default"]

[[nodes]]
id = "node-1"
protocol = "socks"
host = "127.0.0.1"
port = 0
"#,
        &capabilities(),
    );
    assert_diagnostic(&invalid_node_port, CONFIG_NODE_PORT_INVALID_CODE);
}

#[test]
fn proxy_route_without_node_returns_stable_diagnostic() {
    let service = CoreConfigurationService::new();
    let diagnostics = service.validate(
        r#"
profiles = ["default"]

[[routes]]
id = "default"
default_action = "proxy"
"#,
        &capabilities(),
    );

    assert_diagnostic(&diagnostics, CONFIG_ROUTE_PROXY_NODE_MISSING_CODE);
}

#[test]
fn parse_failure_diagnostic_does_not_leak_secret_values() {
    let service = CoreConfigurationService::new();
    let diagnostics = service.validate(
        r#"
token = "super-secret-token"
profiles = [
"#,
        &capabilities(),
    );

    assert_diagnostic(&diagnostics, CONFIG_PARSE_FAILED_CODE);
    assert!(diagnostics.iter().all(|diagnostic| {
        !diagnostic.message.contains("super-secret-token")
            && !diagnostic.message.contains("token =")
    }));
}

#[test]
fn migrate_preserves_same_version_and_rejects_cross_version() {
    let service = CoreConfigurationService::new();
    let raw_config = "profiles = [\"default\"]";

    let unchanged = service
        .migrate(
            raw_config,
            SchemaVersion::new(CURRENT_SCHEMA_VERSION),
            SchemaVersion::new(CURRENT_SCHEMA_VERSION),
        )
        .expect("same version migration should be identity");

    assert_eq!(unchanged, raw_config);

    let error = service
        .migrate(
            raw_config,
            SchemaVersion::new(CURRENT_SCHEMA_VERSION),
            SchemaVersion::new(CURRENT_SCHEMA_VERSION + 1),
        )
        .expect_err("cross-version migration should be explicit");

    assert_eq!(error.code, CONFIG_MIGRATION_UNSUPPORTED_CODE);
}

#[test]
fn fetches_inline_subscription_source_without_network() {
    let service = CoreSubscriptionService::new();
    let inline_payload = concat!(
        "inline:[[nodes]]\n",
        "id = \"node-1\"\n",
        "protocol = \"socks\"\n",
        "host = \"127.0.0.1\"\n",
        "port = 1081\n",
    );

    let raw = service
        .fetch(&SubscriptionSource {
            id: "inline-dev".to_string(),
            location: inline_payload.to_string(),
        })
        .expect("inline subscription should fetch from source metadata");

    assert_eq!(raw.source_id, "inline-dev");
    assert!(raw.content.contains("[[nodes]]"));
}

#[test]
fn parses_subscription_nodes_and_routes_from_toml() {
    let service = CoreSubscriptionService::new();
    let document = service
        .parse(&RawSubscription {
            source_id: "inline-dev".to_string(),
            content: r#"
[[nodes]]
id = "node-1"
name = "Subscription SOCKS"
protocol = "socks"
host = "127.0.0.1"
port = 1081
tags = ["subscription"]

[[routes]]
id = "subscription-default"
default_action = "proxy"
default_node = "node-1"
"#
            .to_string(),
        })
        .expect("subscription payload should parse");

    assert_eq!(document.nodes.len(), 1);
    assert_eq!(document.nodes[0].id, "node-1");
    assert_eq!(document.nodes[0].name, "Subscription SOCKS");
    assert_eq!(document.nodes[0].protocol, Protocol::Socks);
    assert_eq!(document.nodes[0].endpoint.port, 1081);
    assert_eq!(document.nodes[0].tags, vec!["subscription".to_string()]);
    assert_eq!(document.rules.len(), 1);
    assert_eq!(document.rules[0].id, "subscription-default");
    assert_eq!(
        document.rules[0].default_action,
        RouteAction::Proxy {
            node_id: "node-1".to_string()
        }
    );
    assert!(document.diagnostics.is_empty());

    let catalog = service
        .normalize(&document)
        .expect("subscription document should normalize into a catalog");

    assert_eq!(catalog.nodes, document.nodes);
    assert_eq!(catalog.rules, document.rules);
}

#[test]
fn unsupported_subscription_location_returns_stable_error_without_leaking_secret() {
    let service = CoreSubscriptionService::new();

    let error = service
        .fetch(&SubscriptionSource {
            id: "remote-dev".to_string(),
            location: "https://example.invalid/sub?token=super-secret-token".to_string(),
        })
        .expect_err("remote fetch is intentionally unsupported by config-core");

    assert_eq!(error.code, SUBSCRIPTION_FETCH_UNSUPPORTED_CODE);
    assert!(!error.message.contains("super-secret-token"));
    assert!(!error.message.contains("https://example.invalid"));
}

#[test]
fn subscription_parse_failure_does_not_leak_secret_values() {
    let service = CoreSubscriptionService::new();

    let error = service
        .parse(&RawSubscription {
            source_id: "inline-secret".to_string(),
            content: "token = \"super-secret-token\"\nnodes = [".to_string(),
        })
        .expect_err("invalid subscription TOML should fail");

    assert_eq!(error.code, SUBSCRIPTION_PARSE_FAILED_CODE);
    assert!(!error.message.contains("super-secret-token"));
    assert!(!error.message.contains("token ="));
}

fn capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        os: OperatingSystem::Linux,
        supports_tunnel: true,
        supports_mitm: true,
        supports_embedded_runtime: true,
    }
}

fn assert_diagnostic(diagnostics: &[Diagnostic], code: &str) {
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.code == code),
        "missing diagnostic {code}: {diagnostics:?}"
    );
}

fn assert_metadata(metadata: &[MetadataEntry], key: &str, value: &str) {
    assert!(
        metadata
            .iter()
            .any(|entry| entry.key == key && entry.value == value),
        "missing metadata {key}={value}: {metadata:?}"
    );
}
