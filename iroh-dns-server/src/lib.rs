//! A DNS server and pkarr relay

#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod config;
pub mod dns;
pub mod http;
pub mod metrics;
pub mod server;
pub mod state;
mod store;
mod util;

// Re-export to be able to construct your own dns-server
pub use store::ZoneStore;

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use anyhow::Result;
    use hickory_resolver::{
        config::{NameServerConfig, ResolverConfig},
        Resolver,
    };
    use hickory_server::proto::xfer::Protocol;
    use iroh::{
        discovery::pkarr::PkarrRelayClient,
        dns::{DnsResolver, ResolverExt},
        node_info::NodeInfo,
        SecretKey,
    };
    use pkarr::{PkarrClient, SignedPacket};
    use testresult::TestResult;
    use url::Url;

    use crate::{
        config::BootstrapOption,
        server::Server,
        store::{PacketSource, ZoneStoreOptions},
        util::PublicKeyBytes,
        ZoneStore,
    };

    #[tokio::test]
    async fn pkarr_publish_dns_resolve() -> Result<()> {
        iroh_test::logging::setup_multithreaded();
        let (server, nameserver, http_url) = Server::spawn_for_tests().await?;
        let pkarr_relay_url = {
            let mut url = http_url.clone();
            url.set_path("/pkarr");
            url
        };
        let signed_packet = {
            use pkarr::dns;
            let keypair = pkarr::Keypair::random();
            let mut packet = dns::Packet::new_reply(0);
            // record at root
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi0".try_into()?),
            ));
            // record at level one
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("_hello").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi1".try_into()?),
            ));
            // record at level two
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("_hello.world").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi2".try_into()?),
            ));
            // multiple records for same name
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("multiple").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi3".try_into()?),
            ));
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("multiple").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi4".try_into()?),
            ));
            // record of type A
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::A(Ipv4Addr::LOCALHOST.into()),
            ));
            // record of type AAAA
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("foo.bar.baz").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::AAAA(Ipv6Addr::LOCALHOST.into()),
            ));
            SignedPacket::from_packet(&keypair, &packet)?
        };
        let pkarr_client = pkarr::PkarrRelayClient::new(pkarr::RelaySettings {
            relays: vec![pkarr_relay_url.to_string()],
            ..Default::default()
        })?;
        pkarr_client.as_async().publish(&signed_packet).await?;

        use hickory_server::proto::rr::Name;
        let pubkey = signed_packet.public_key().to_z32();
        let resolver = test_resolver(nameserver);

        // resolve root record
        let name = Name::from_utf8(format!("{pubkey}."))?;
        let res = resolver.txt_lookup(name).await?;
        let records = res.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi0".to_string()]);

        // resolve level one record
        let name = Name::from_utf8(format!("_hello.{pubkey}."))?;
        let res = resolver.txt_lookup(name).await?;
        let records = res.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi1".to_string()]);

        // resolve level two record
        let name = Name::from_utf8(format!("_hello.world.{pubkey}."))?;
        let res = resolver.txt_lookup(name).await?;
        let records = res.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi2".to_string()]);

        // resolve multiple records for same name
        let name = Name::from_utf8(format!("multiple.{pubkey}."))?;
        let res = resolver.txt_lookup(name).await?;
        let records = res.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi3".to_string(), "hi4".to_string()]);

        // resolve A record
        let name = Name::from_utf8(format!("{pubkey}."))?;
        let res = resolver.ipv4_lookup(name).await?;
        let records = res.iter().map(|t| t.0).collect::<Vec<_>>();
        assert_eq!(records, vec![Ipv4Addr::LOCALHOST]);

        // resolve AAAA record
        let name = Name::from_utf8(format!("foo.bar.baz.{pubkey}."))?;
        let res = resolver.ipv6_lookup(name).await?;
        let records = res.iter().map(|t| t.0).collect::<Vec<_>>();
        assert_eq!(records, vec![Ipv6Addr::LOCALHOST]);

        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn integration_smoke() -> Result<()> {
        iroh_test::logging::setup_multithreaded();
        let (server, nameserver, http_url) = Server::spawn_for_tests().await?;

        let pkarr_relay = {
            let mut url = http_url.clone();
            url.set_path("/pkarr");
            url
        };

        let origin = "irohdns.example.";

        let secret_key = SecretKey::generate(rand::thread_rng());
        let node_id = secret_key.public();
        let relay_url: Url = "https://relay.example.".parse()?;
        let pkarr = PkarrRelayClient::new(pkarr_relay);
        let node_info = NodeInfo::new(node_id, Some(relay_url.clone()), Default::default());
        let signed_packet = node_info.to_pkarr_signed_packet(&secret_key, 30)?;

        pkarr.publish(&signed_packet).await?;

        let resolver = test_resolver(nameserver);
        let res = resolver.lookup_by_id(&node_id, origin).await?;

        assert_eq!(res.node_id, node_id);
        assert_eq!(res.relay_url.map(Url::from), Some(relay_url));

        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn store_eviction() -> TestResult<()> {
        iroh_test::logging::setup_multithreaded();
        let options = ZoneStoreOptions {
            eviction: Duration::from_millis(100),
            eviction_interval: Duration::from_millis(100),
            max_batch_time: Duration::from_millis(100),
            ..Default::default()
        };
        let store = ZoneStore::in_memory(options)?;

        // create a signed packet
        let signed_packet = random_signed_packet()?;
        let key = PublicKeyBytes::from_signed_packet(&signed_packet);

        store
            .insert(signed_packet, PacketSource::PkarrPublish)
            .await?;

        tokio::time::sleep(Duration::from_secs(1)).await;
        for _ in 0..10 {
            let entry = store.get_signed_packet(&key).await?;
            if entry.is_none() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        panic!("store did not evict packet");
    }

    #[tokio::test]
    async fn integration_mainline() -> Result<()> {
        iroh_test::logging::setup_multithreaded();

        // run a mainline testnet
        let testnet = pkarr::mainline::dht::Testnet::new(5);
        let bootstrap = testnet.bootstrap.clone();

        // spawn our server with mainline support
        let (server, nameserver, _http_url) =
            Server::spawn_for_tests_with_options(Some(BootstrapOption::Custom(bootstrap)), None)
                .await?;

        let origin = "irohdns.example.";

        // create a signed packet
        let secret_key = SecretKey::generate(rand::thread_rng());
        let node_id = secret_key.public();
        let relay_url: Url = "https://relay.example.".parse()?;
        let node_info = NodeInfo::new(node_id, Some(relay_url.clone()), Default::default());
        let signed_packet = node_info.to_pkarr_signed_packet(&secret_key, 30)?;

        // publish the signed packet to our DHT
        let pkarr = PkarrClient::builder()
            .dht_settings(pkarr::mainline::dht::DhtSettings {
                bootstrap: Some(testnet.bootstrap),
                ..Default::default()
            })
            .build()?;
        pkarr.publish(&signed_packet)?;

        // resolve via DNS from our server, which will lookup from our DHT
        let resolver = test_resolver(nameserver);
        let res = resolver.lookup_by_id(&node_id, origin).await?;

        assert_eq!(res.node_id, node_id);
        assert_eq!(res.relay_url.map(Url::from), Some(relay_url));

        server.shutdown().await?;
        for mut node in testnet.nodes {
            node.shutdown()?;
        }
        Ok(())
    }

    fn test_resolver(nameserver: SocketAddr) -> DnsResolver {
        let mut config = ResolverConfig::new();
        let nameserver_config = NameServerConfig::new(nameserver, Protocol::Udp);
        config.add_name_server(nameserver_config);
        Resolver::tokio(config, Default::default())
    }

    fn random_signed_packet() -> Result<SignedPacket> {
        let secret_key = SecretKey::generate(rand::thread_rng());
        let node_id = secret_key.public();
        let relay_url: Url = "https://relay.example.".parse()?;
        let node_info = NodeInfo::new(node_id, Some(relay_url.clone()), Default::default());
        node_info.to_pkarr_signed_packet(&secret_key, 30)
    }
}
