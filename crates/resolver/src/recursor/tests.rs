use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use test_support::{MockNetworkHandler, MockProvider, MockRecord, MockResponseSection, subscribe};
use tokio::time as TokioTime;

use super::{Recursor, RecursorError, RecursorMode, RecursorOptions, is_subzone};
use crate::{
    cache::TtlConfig,
    config::ResolverOpts,
    net::{NetError, runtime::TokioRuntimeProvider, xfer::Protocol},
    proto::{
        op::{Message, Query, ResponseCode},
        rr::{Name, Record, RecordType},
    },
    recursor::QNameMinimization,
};

#[cfg(all(feature = "serde", feature = "__tls"))]
mod authenticated_dot;

#[cfg(all(feature = "serde", feature = "__quic"))]
mod authenticated_doq;

#[tokio::test]
async fn recursor_connection_deduplication() -> Result<(), NetError> {
    subscribe();

    let query_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let dup_query_name = Name::from_ascii("host.hickory-dns-dup.testing.")?;
    let (provider, options) = test_fixture()?;
    let recursor = Recursor::with_options(&[ROOT_IP], options, provider.clone())?;

    // This test is inspecting the number of new TCP connection calls for each nameserver.
    // If deduplication is working correctly, there should be one for each after the
    // first query (because the handler returns truncated messages), and there should
    // still be one for each after the second query, particularly to the leaf IP which
    // is used in two separate zones.
    for query in [query_name, dup_query_name] {
        let response = recursor
            .resolve(Query::new(query, RecordType::A), Instant::now(), false)
            .await?;

        assert_eq!(response.response_code, ResponseCode::NoError);

        assert_eq!(
            provider.count_new_connection_calls(ROOT_IP, Protocol::Tcp),
            1
        );
        assert_eq!(
            provider.count_new_connection_calls(TLD_IP, Protocol::Tcp),
            1
        );
        assert_eq!(
            provider.count_new_connection_calls(LEAF_IP, Protocol::Tcp),
            1
        );
    }

    Ok(())
}

#[tokio::test]
async fn recursor_connection_deduplication_non_cached() -> Result<(), NetError> {
    subscribe();

    let query_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let dup_query_name = Name::from_ascii("host.hickory-dns-dup.testing.")?;
    let (provider, options) = test_fixture()?;
    let recursor = Recursor::with_options(
        &[ROOT_IP],
        RecursorOptions {
            ns_cache_size: 1,
            ..options
        },
        provider.clone(),
    )?;

    let response = recursor
        .resolve(Query::new(query_name, RecordType::A), Instant::now(), false)
        .await?;

    assert_eq!(response.response_code, ResponseCode::NoError);
    assert_eq!(
        provider.count_new_connection_calls(ROOT_IP, Protocol::Tcp),
        1
    );
    assert_eq!(
        provider.count_new_connection_calls(TLD_IP, Protocol::Tcp),
        1
    );
    assert_eq!(
        provider.count_new_connection_calls(LEAF_IP, Protocol::Tcp),
        1
    );

    // With the ns_cache_size set to 1, we should see new connections for the TLD
    // and leaf queries because the NameServer objects have dropped out of the
    // connection cache.
    let response = recursor
        .resolve(
            Query::new(dup_query_name, RecordType::A),
            Instant::now(),
            false,
        )
        .await
        .unwrap();

    assert_eq!(response.response_code, ResponseCode::NoError);
    // Roots aren't subject to cache expiration
    assert_eq!(
        provider.count_new_connection_calls(ROOT_IP, Protocol::Tcp),
        1
    );
    assert_eq!(
        provider.count_new_connection_calls(TLD_IP, Protocol::Tcp),
        2
    );
    assert_eq!(
        provider.count_new_connection_calls(LEAF_IP, Protocol::Tcp),
        2
    );

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn name_server_cache_ttl() -> Result<(), NetError> {
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let zone_ttl = 60;
    let recursor = ns_cache_test_fixture(zone_ttl, zone_ttl, TtlConfig::default(), false)?;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Query the names again after pausing for 2 * the zone ttl, which should
    // force the recursor to discard the cached zone and query again.  The TLD
    // server will return a different nameserver on the second query which will
    // in turn provide different answers to the A queries.
    let _ = TokioTime::advance(Duration::from_secs((zone_ttl * 2) as u64)).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_2));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_2));

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn name_server_cache_ttl_clamp_min() -> Result<(), NetError> {
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let zone_ttl = 60;
    let recursor_min_ttl: u32 = 240;
    let recursor_max_ttl = 86400;

    assert!(zone_ttl * 2 < recursor_min_ttl); // test pre-requisite
    let opts = ResolverOpts {
        positive_min_ttl: Some(Duration::from_secs(recursor_min_ttl as u64)),
        positive_max_ttl: Some(Duration::from_secs(recursor_max_ttl)),
        ..ResolverOpts::default()
    };

    let recursor = ns_cache_test_fixture(zone_ttl, zone_ttl, TtlConfig::from_opts(&opts), false)?;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Wait for longer than the zone ttl, but less than the recursor_min_ttl to make sure
    // the cache was clamped.  The A queries should return the same results as above.
    let _ = TokioTime::advance(Duration::from_secs(u64::from(zone_ttl * 2))).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Wait for recursor_min_ttl seconds, which should cause the NS cache to expire.
    let _ = TokioTime::advance(Duration::from_secs(recursor_min_ttl as u64)).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_2));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_2));

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn name_server_cache_ttl_clamp_max() -> Result<(), NetError> {
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let zone_ttl: u32 = 3600;
    let recursor_min_ttl = 1;
    let recursor_max_ttl = 60;

    assert!(zone_ttl > recursor_max_ttl * 2); // test pre-requisite

    let opts = ResolverOpts {
        positive_min_ttl: Some(Duration::from_secs(recursor_min_ttl)),
        positive_max_ttl: Some(Duration::from_secs(recursor_max_ttl as u64)),
        ..ResolverOpts::default()
    };

    let recursor = ns_cache_test_fixture(zone_ttl, zone_ttl, TtlConfig::from_opts(&opts), false)?;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Wait for longer than the recursor_max_ttl, but less than the zone ttl to make
    // sure the max clamp is respected.
    let _ = TokioTime::advance(Duration::from_secs(u64::from(recursor_max_ttl * 2))).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_2));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_2));

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn name_server_cache_ttl_glue() -> Result<(), NetError> {
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let zone_ttl = 60;
    let ns_ttl = 15;

    assert!(zone_ttl > ns_ttl * 2); // test pre-requisite
    let recursor = ns_cache_test_fixture(zone_ttl, ns_ttl, TtlConfig::default(), false)?;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Query the names again after pausing for 2 * the NS record (zone) ttl.
    // The cache lifetime is derived from the NS record TTL, not the glue
    // record TTL, so we must wait past zone_ttl for the entry to expire and
    // force the recursor to re-query the TLD server.  The TLD server will
    // return a different nameserver on the second query which will in turn
    // provide different answers to the A queries.
    let _ = TokioTime::advance(Duration::from_secs((zone_ttl * 2) as u64)).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_2));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_2));

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn name_server_cache_ttl_glue_off_domain() -> Result<(), NetError> {
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let zone_ttl = 60;
    let ns_ttl = 15;

    assert!(zone_ttl > ns_ttl * 2); // test pre-requisite
    // Use ns.otherdomain.testing. as the authoritative name server for this test.
    let recursor = ns_cache_test_fixture(zone_ttl, ns_ttl, TtlConfig::default(), true)?;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_1));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_1));

    // Query the names again after pausing for 2 * the ns record ttl, which should
    // force the recursor to discard the cached zone and query again.  The TLD
    // server will return a different nameserver on the second query which will
    // in turn provide different answers to the A queries.
    let _ = TokioTime::advance(Duration::from_secs((ns_ttl * 2) as u64)).await;

    let response = ttl_lookup(&recursor, &query_1_name).await?;
    assert!(validate_response(response, &query_1_name, target_1_ip_2));

    let response = ttl_lookup(&recursor, &query_2_name).await?;
    assert!(validate_response(response, &query_2_name, target_2_ip_2));

    Ok(())
}

#[tokio::test]
async fn ns_pool_zone_name_test() -> Result<(), NetError> {
    subscribe();

    let query_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let nx_query_name = Name::from_ascii("invalid.hickory-dns.testing.")?;
    let delegated_query_name = Name::from_ascii("host.delegated.hickory-dns.testing.")?;
    let ent_query_name = Name::from_ascii("ent.hickory-dns.testing.")?;
    let ent_delegated_query_name = Name::from_ascii("host.delegated.ent.hickory-dns.testing.")?;

    let tld_zone = Name::from_ascii("testing.")?;
    let tld_ns = Name::from_ascii("testing.testing.")?;
    let leaf_zone = Name::from_ascii("hickory-dns.testing.")?;
    let leaf_ns = Name::from_ascii("ns.hickory-dns.testing.")?;
    let delegated_leaf_zone = Name::from_ascii("delegated.hickory-dns.testing.")?;
    let delegated_leaf_ns = Name::from_ascii("ns.delegated.hickory-dns.testing.")?;
    let ent_delegated_leaf_zone = Name::from_ascii("delegated.ent.hickory-dns.testing.")?;
    let ent_delegated_leaf_ns = Name::from_ascii("ns.delegated.ent.hickory-dns.testing.")?;

    let responses = vec![
        MockRecord::ns(ROOT_IP, &tld_zone, &tld_ns),
        MockRecord::a(ROOT_IP, &tld_ns, TLD_IP)
            .with_query_name(&tld_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(TLD_IP, &leaf_zone, &leaf_ns),
        MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
            .with_query_name(&leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(LEAF_IP, &delegated_leaf_zone, &delegated_leaf_ns),
        MockRecord::a(LEAF_IP, &delegated_leaf_ns, DELEGATED_LEAF_IP)
            .with_query_name(&delegated_leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(LEAF_IP, &ent_delegated_leaf_zone, &ent_delegated_leaf_ns),
        MockRecord::a(LEAF_IP, &ent_delegated_leaf_ns, ENT_DELEGATED_LEAF_IP)
            .with_query_name(&ent_delegated_leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::a(LEAF_IP, &query_name, LEAF_IP),
        MockRecord::a(LEAF_IP, &ent_query_name, LEAF_IP),
        MockRecord::a(DELEGATED_LEAF_IP, &delegated_query_name, DELEGATED_LEAF_IP),
        MockRecord::a(
            ENT_DELEGATED_LEAF_IP,
            &ent_delegated_query_name,
            ENT_DELEGATED_LEAF_IP,
        ),
    ];

    let recursor_no_cache = Recursor::with_options(
        &[ROOT_IP],
        RecursorOptions {
            deny_server: Vec::new(),
            ns_cache_size: 1,
            ..RecursorOptions::default()
        },
        MockProvider::new(MockNetworkHandler::new(responses.clone())),
    )?;

    let recursor_cache = Recursor::with_options(
        &[ROOT_IP],
        RecursorOptions {
            deny_server: Vec::new(),
            ns_cache_size: 1024,
            ..RecursorOptions::default()
        },
        MockProvider::new(MockNetworkHandler::new(responses.clone())),
    )?;

    for recursor in [recursor_no_cache, recursor_cache] {
        assert_eq!(
            get_zone_name(&recursor, &query_name).await?,
            Some(leaf_zone.clone())
        );
        assert_eq!(
            get_zone_name(&recursor, &leaf_zone).await?,
            Some(leaf_zone.clone())
        );
        assert_eq!(
            get_zone_name(&recursor, &nx_query_name).await?,
            Some(leaf_zone.clone())
        );
        assert_eq!(
            get_zone_name(&recursor, &delegated_query_name).await?,
            Some(delegated_leaf_zone.clone())
        );
        assert_eq!(
            get_zone_name(&recursor, &ent_query_name).await?,
            Some(leaf_zone.clone())
        );
        assert_eq!(
            get_zone_name(&recursor, &ent_delegated_query_name).await?,
            Some(ent_delegated_leaf_zone.clone())
        );

        // Sanity check - IPs are correct
        assert!(validate_response(
            ttl_lookup(&recursor, &query_name).await?,
            &query_name,
            LEAF_IP
        ));
        assert!(validate_response(
            ttl_lookup(&recursor, &delegated_query_name).await?,
            &delegated_query_name,
            DELEGATED_LEAF_IP
        ));
        assert!(validate_response(
            ttl_lookup(&recursor, &ent_delegated_query_name).await?,
            &ent_delegated_query_name,
            ENT_DELEGATED_LEAF_IP
        ));
    }

    Ok(())
}

#[tokio::test]
async fn ns_pool_zone_name_nxdomain_at_ent() -> Result<(), NetError> {
    subscribe();

    let query_name = Name::from_ascii("host.ent.hickory-dns.testing.")?;
    let ent_name = Name::from_ascii("ent.hickory-dns.testing.")?;

    let tld_zone = Name::from_ascii("testing.")?;
    let tld_ns = Name::from_ascii("testing.testing.")?;
    let leaf_zone = Name::from_ascii("hickory-dns.testing.")?;
    let leaf_ns = Name::from_ascii("ns.hickory-dns.testing.")?;

    let responses = vec![
        MockRecord::ns(ROOT_IP, &tld_zone, &tld_ns),
        MockRecord::a(ROOT_IP, &tld_ns, TLD_IP)
            .with_query_name(&tld_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(TLD_IP, &leaf_zone, &leaf_ns),
        MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
            .with_query_name(&leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::soa(LEAF_IP, &leaf_zone, &leaf_ns, &leaf_ns)
            .with_query_name(&ent_name)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Authority),
        MockRecord::soa(LEAF_IP, &leaf_zone, &leaf_ns, &leaf_ns)
            .with_query_name(&query_name)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Authority),
        MockRecord::a(LEAF_IP, &query_name, LEAF_IP),
    ];

    let nxdomain_at_ent = Box::new(move |_, _, message: &mut Message| {
        if let Some(query) = message.queries.first() {
            if query.name == ent_name && query.query_type == RecordType::NS {
                let mut error_message =
                    Message::error_msg(message.id, message.op_code, ResponseCode::NXDomain);
                error_message.add_authorities(message.authorities.drain(..));
                *message = error_message;
            }
        }
    });

    let recursor_no_cache = Recursor::with_options(
        &[ROOT_IP],
        RecursorOptions {
            deny_server: Vec::new(),
            ns_cache_size: 1,
            qname_minimization: QNameMinimization::Relaxed,
            ..RecursorOptions::default()
        },
        MockProvider::new(
            MockNetworkHandler::new(responses.clone()).with_mutation(nxdomain_at_ent.clone()),
        ),
    )?;

    let recursor_cache = Recursor::with_options(
        &[ROOT_IP],
        RecursorOptions {
            deny_server: Vec::new(),
            ns_cache_size: 1024,
            qname_minimization: QNameMinimization::Relaxed,
            ..RecursorOptions::default()
        },
        MockProvider::new(
            MockNetworkHandler::new(responses.clone()).with_mutation(nxdomain_at_ent),
        ),
    )?;

    for recursor in [recursor_no_cache, recursor_cache] {
        assert_eq!(
            get_zone_name(&recursor, &query_name).await?,
            Some(leaf_zone.clone())
        );

        // Sanity check - IPs are correct
        assert!(validate_response(
            ttl_lookup(&recursor, &query_name).await?,
            &query_name,
            LEAF_IP
        ));
    }

    Ok(())
}

#[tokio::test]
async fn not_fully_qualified_domain_name_in_query() -> Result<(), NetError> {
    subscribe();

    let j_root_servers_net_ip = IpAddr::from([192, 58, 128, 30]);
    let recursor = Recursor::with_options(
        &[j_root_servers_net_ip],
        RecursorOptions::default(),
        TokioRuntimeProvider::default(),
    )?;

    let name = Name::from_ascii("example.com")?;
    assert!(!name.is_fqdn());
    let query = Query::new(name, RecordType::A);
    let res = recursor
        .resolve(query, Instant::now(), false)
        .await
        .unwrap_err();
    assert!(res.to_string().contains("fully qualified"));

    Ok(())
}

#[tokio::test]
async fn cache_negative_responses() -> Result<(), NetError> {
    subscribe();

    let exists_name = Name::from_ascii("exists.hickory-dns.testing.")?;
    let no_exist_name = Name::from_ascii("doesnotexist.hickory-dns.testing.")?;

    let tld_zone = Name::from_ascii("testing.")?;
    let tld_ns = Name::from_ascii("testing.testing.")?;
    let leaf_zone = Name::from_ascii("hickory-dns.testing.")?;
    let leaf_ns = Name::from_ascii("ns.hickory-dns.testing.")?;

    let responses = vec![
        MockRecord::ns(ROOT_IP, &tld_zone, &tld_ns),
        MockRecord::a(ROOT_IP, &tld_ns, TLD_IP)
            .with_query_name(&tld_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(TLD_IP, &leaf_zone, &leaf_ns),
        MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
            .with_query_name(&leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::a(LEAF_IP, &exists_name, LEAF_IP),
        MockRecord::soa(LEAF_IP, &leaf_ns, &leaf_zone, &leaf_ns)
            .with_query_name(&no_exist_name)
            .with_query_type(RecordType::A)
            .with_ttl(3600),
        MockRecord::soa(LEAF_IP, &leaf_ns, &leaf_zone, &leaf_ns)
            .with_query_name(&no_exist_name)
            .with_query_type(RecordType::NS)
            .with_ttl(3600),
    ];

    let provider = MockProvider::new(MockNetworkHandler::new(responses));
    let recursor = Recursor::with_options(
        &[ROOT_IP],
        RecursorOptions {
            deny_server: Vec::new(), // We use addresses in the default deny filters.
            ..RecursorOptions::default()
        },
        provider.clone(),
    )?;

    for _ in 0..2 {
        let response = recursor
            .resolve(
                Query::new(no_exist_name.clone(), RecordType::A),
                Instant::now(),
                false,
            )
            .await;
        assert!(response.is_err());

        assert_eq!(
            provider
                .queries(&LEAF_IP)
                .iter()
                .filter(|x| x.name == no_exist_name && x.query_type == RecordType::A)
                .count(),
            1,
        );
    }

    Ok(())
}

#[tokio::test]
async fn nxdomain_with_ns_records_short_circuits() -> Result<(), NetError> {
    subscribe();

    let no_exist_name = Name::from_ascii("www.doesnotexist.hickory-dns.testing.")?;
    let no_exist_cut = Name::from_ascii("doesnotexist.hickory-dns.testing.")?;

    let tld_zone = Name::from_ascii("testing.")?;
    let tld_ns = Name::from_ascii("testing.testing.")?;
    let leaf_zone = Name::from_ascii("hickory-dns.testing.")?;
    let leaf_ns = Name::from_ascii("ns.hickory-dns.testing.")?;
    let bogus_ns = Name::from_ascii("ns.doesnotexist.hickory-dns.testing.")?;

    let responses = vec![
        MockRecord::ns(ROOT_IP, &tld_zone, &tld_ns),
        MockRecord::a(ROOT_IP, &tld_ns, TLD_IP)
            .with_query_name(&tld_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(TLD_IP, &leaf_zone, &leaf_ns),
        MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
            .with_query_name(&leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        // The zone cut probe gets an NXDOMAIN whose authority section carries NS records
        // alongside the SOA.
        MockRecord::soa(LEAF_IP, &leaf_ns, &leaf_zone, &leaf_ns)
            .with_query_name(&no_exist_cut)
            .with_query_type(RecordType::NS)
            .with_ttl(3600),
        MockRecord::ns(LEAF_IP, &leaf_zone, &bogus_ns)
            .with_query_name(&no_exist_cut)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Authority),
    ];

    let cut = no_exist_cut.clone();
    let handler = MockNetworkHandler::new(responses).with_mutation(Box::new(
        move |_destination: IpAddr, _protocol: Protocol, message: &mut Message| {
            if message.queries[0].name == cut {
                message.metadata.response_code = ResponseCode::NXDomain;
            }
        },
    ));

    let provider = MockProvider::new(handler);
    let recursor = Recursor::with_options(
        &[ROOT_IP],
        RecursorOptions {
            deny_server: Vec::new(), // We use addresses in the default deny filters.
            ..RecursorOptions::default()
        },
        provider.clone(),
    )?;

    let error = recursor
        .resolve(
            Query::new(no_exist_name.clone(), RecordType::A),
            Instant::now(),
            false,
        )
        .await
        .unwrap_err();
    assert!(error.is_nx_domain());

    // Per RFC 8020 nothing below the NXDOMAIN name exists, so no further probe is made.
    assert_eq!(
        provider
            .queries(&LEAF_IP)
            .iter()
            .filter(|x| x.name == no_exist_name)
            .count(),
        0,
    );

    Ok(())
}

#[test]
fn is_subzone_test() {
    use core::str::FromStr;

    assert!(is_subzone(
        &Name::from_str(".").unwrap(),
        &Name::from_str("com.").unwrap(),
    ));
    assert!(is_subzone(
        &Name::from_str("com.").unwrap(),
        &Name::from_str("example.com.").unwrap(),
    ));
    assert!(is_subzone(
        &Name::from_str("example.com.").unwrap(),
        &Name::from_str("host.example.com.").unwrap(),
    ));
    assert!(is_subzone(
        &Name::from_str("example.com.").unwrap(),
        &Name::from_str("host.multilevel.example.com.").unwrap(),
    ));
    assert!(!is_subzone(
        &Name::from_str("").unwrap(),
        &Name::from_str("example.com.").unwrap(),
    ));
    assert!(!is_subzone(
        &Name::from_str("com.").unwrap(),
        &Name::from_str("example.net.").unwrap(),
    ));
    assert!(!is_subzone(
        &Name::from_str("example.com.").unwrap(),
        &Name::from_str("otherdomain.com.").unwrap(),
    ));
    assert!(!is_subzone(
        &Name::from_str("com").unwrap(),
        &Name::from_str("example.com.").unwrap(),
    ));
}

async fn get_zone_name(
    recursor: &Recursor<MockProvider>,
    query: &Name,
) -> Result<Option<Name>, NetError> {
    match recursor.mode {
        RecursorMode::NonValidating { ref handle } => {
            let ns_pool = handle
                .ns_pool_for_name(query.clone(), Instant::now(), 0)
                .await?
                .1;
            Ok(ns_pool.zone().cloned())
        }
        #[cfg(feature = "__dnssec")]
        _ => panic!("test doesn't support validating mode"),
    }
}

fn ns_cache_test_fixture(
    zone_ttl: u32,
    ns_ttl: u32,
    ttl_config: TtlConfig,
    off_domain: bool,
) -> Result<Recursor<MockProvider>, RecursorError> {
    subscribe();
    let query_1_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_2_name = Name::from_ascii("host2.hickory-dns.testing.")?;

    let tld_zone = Name::from_ascii("testing.")?;
    let tld_ns = Name::from_ascii("testing.testing.")?;
    let leaf_zone = Name::from_ascii("hickory-dns.testing.")?;
    let leaf_ns = Name::from_ascii("ns.hickory-dns.testing.")?;
    let off_domain_zone = Name::from_ascii("otherdomain.testing.")?;
    let off_domain_ns = Name::from_ascii("ns.otherdomain.testing.")?;
    let off_domain_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 5, 1));
    let leaf_2_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 1));
    let target_1_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_1_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let target_2_ip_1 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let target_2_ip_2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    let mut responses = vec![
        MockRecord::ns(ROOT_IP, &tld_zone, &tld_ns),
        MockRecord::a(ROOT_IP, &tld_ns, TLD_IP)
            .with_query_name(&tld_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::a(LEAF_IP, &query_1_name, target_1_ip_1).with_ttl(0),
        MockRecord::a(leaf_2_ip, &query_1_name, target_1_ip_2).with_ttl(0),
        MockRecord::a(LEAF_IP, &query_2_name, target_2_ip_1).with_ttl(0),
        MockRecord::a(leaf_2_ip, &query_2_name, target_2_ip_2).with_ttl(0),
    ];

    // Off domain here refers to a zone (hickory-dns.testing.) with an authoritative name server
    // in a completely unrelated zone (otherdomain.testing.)  ns_pool_for_zone collects these
    // addresses differently, so we need a separate test to ensure the TTL tracking code is
    // working in all cases.
    if off_domain {
        responses.append(
            &mut [
                MockRecord::ns(TLD_IP, &leaf_zone, &off_domain_ns).with_ttl(zone_ttl),
                MockRecord::ns(TLD_IP, &off_domain_zone, &off_domain_ns).with_ttl(zone_ttl),
                MockRecord::a(TLD_IP, &off_domain_ns, off_domain_ip)
                    .with_query_name(&off_domain_zone)
                    .with_query_type(RecordType::NS)
                    .with_section(MockResponseSection::Additional)
                    .with_ttl(zone_ttl),
                MockRecord::soa(
                    off_domain_ip,
                    &off_domain_ns,
                    &off_domain_zone,
                    &off_domain_ns,
                )
                .with_query_name(&off_domain_ns)
                .with_query_type(RecordType::NS),
                MockRecord::a(off_domain_ip, &off_domain_ns, LEAF_IP).with_ttl(ns_ttl),
            ]
            .into_iter()
            .collect::<Vec<MockRecord>>(),
        );
    } else {
        responses.append(
            &mut [
                MockRecord::ns(TLD_IP, &leaf_zone, &leaf_ns).with_ttl(zone_ttl),
                MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
                    .with_query_name(&leaf_zone)
                    .with_query_type(RecordType::NS)
                    .with_section(MockResponseSection::Additional)
                    .with_ttl(ns_ttl),
            ]
            .into_iter()
            .collect::<Vec<MockRecord>>(),
        );
    }

    let counter = Arc::new(AtomicU8::new(0));

    let handler = MockNetworkHandler::new(responses).with_mutation(Box::new(
        move |destination: IpAddr, _protocol: Protocol, msg: &mut Message| {
            let leaf_ns = leaf_ns.clone();
            let query_name = &msg.queries[0].name;
            let query_type = msg.queries[0].query_type;

            if !off_domain {
                if destination == TLD_IP && *query_name == leaf_zone && query_type == RecordType::NS
                {
                    let count = counter.fetch_add(1, Ordering::Relaxed);
                    if count > 0 {
                        msg.additionals.clear();
                        msg.add_additional(Record::from_rdata(leaf_ns, ns_ttl, leaf_2_ip.into()));
                    }
                }
            } else if destination == off_domain_ip
                && *query_name == off_domain_ns
                && query_type == RecordType::A
            {
                let count = counter.fetch_add(1, Ordering::Relaxed);
                if count > 0 {
                    msg.answers.clear();
                    msg.add_answer(Record::from_rdata(leaf_ns, zone_ttl, leaf_2_ip.into()));
                }
            }
        },
    ));

    Recursor::with_options(
        &[ROOT_IP],
        RecursorOptions {
            deny_server: Vec::new(),
            cache_policy: ttl_config,
            ..RecursorOptions::default()
        },
        MockProvider::new(handler),
    )
}

async fn ttl_lookup(
    recursor: &Recursor<MockProvider>,
    name: &Name,
) -> Result<Message, RecursorError> {
    recursor
        .resolve(
            Query::new(name.clone(), RecordType::A),
            TokioTime::Instant::now().into(),
            false,
        )
        .await
}

fn validate_response(response: Message, name: &Name, ip: IpAddr) -> bool {
    response.response_code == ResponseCode::NoError
        && response.answers == [Record::from_rdata(name.clone(), 0, ip.into())]
}

fn test_fixture() -> Result<(MockProvider, RecursorOptions), NetError> {
    test_fixture_with_glue(true)
}

fn test_fixture_with_glue(
    include_leaf_glue: bool,
) -> Result<(MockProvider, RecursorOptions), NetError> {
    let query_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let dup_query_name = Name::from_ascii("host.hickory-dns-dup.testing.")?;

    let tld_zone = Name::from_ascii("testing.")?;
    let tld_ns = Name::from_ascii("testing.testing.")?;
    let leaf_zone = Name::from_ascii("hickory-dns.testing.")?;
    let leaf_ns = Name::from_ascii("ns.hickory-dns.testing.")?;
    let dup_leaf_zone = Name::from_ascii("hickory-dns-dup.testing.")?;
    let dup_leaf_ns = Name::from_ascii("ns.hickory-dns-dup.testing.")?;

    let leaf_address = if include_leaf_glue {
        MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
            .with_query_name(&leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional)
    } else {
        // Force append_ips_from_lookup to obtain the address from the parent.
        MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
    };

    let responses = vec![
        MockRecord::ns(ROOT_IP, &tld_zone, &tld_ns),
        MockRecord::a(ROOT_IP, &tld_ns, TLD_IP)
            .with_query_name(&tld_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::ns(TLD_IP, &leaf_zone, &leaf_ns),
        leaf_address,
        MockRecord::ns(TLD_IP, &dup_leaf_zone, &dup_leaf_ns),
        MockRecord::a(TLD_IP, &dup_leaf_ns, LEAF_IP)
            .with_query_name(&dup_leaf_zone)
            .with_query_type(RecordType::NS)
            .with_section(MockResponseSection::Additional),
        MockRecord::a(LEAF_IP, &query_name, LEAF_IP),
        MockRecord::a(LEAF_IP, &dup_query_name, LEAF_IP),
    ];

    let handler = MockNetworkHandler::new(responses).with_mutation(Box::new(
        |_destination: IpAddr, protocol: Protocol, msg: &mut Message| {
            if protocol == Protocol::Udp {
                msg.metadata.truncation = true;
            }
        },
    ));

    let provider = MockProvider::new(handler);
    let options = RecursorOptions {
        deny_server: Vec::new(),
        ..RecursorOptions::default()
    };

    Ok((provider, options))
}

#[cfg(feature = "metrics")]
mod metrics {
    use ::metrics::{Unit, with_local_recorder};
    use metrics_util::debugging::DebuggingRecorder;
    use test_support::{assert_counter_eq, assert_gauge_eq, assert_histogram_sample_count_eq};
    use tokio::runtime::Builder;

    use super::*;
    #[cfg(feature = "__dnssec")]
    use crate::metrics::recursor::{
        BOGUS_ANSWERS_TOTAL, INDETERMINATE_ANSWERS_TOTAL, INSECURE_ANSWERS_TOTAL,
        SECURE_ANSWERS_TOTAL, VALIDATED_RESPONSE_CACHE_SIZE,
    };
    use crate::metrics::recursor::{
        CACHE_HIT_DURATION, CACHE_HIT_TOTAL, CACHE_MISS_DURATION, CACHE_MISS_TOTAL,
        CONNECTION_CACHE_SIZE, IN_FLIGHT_QUERIES, NAME_SERVER_CACHE_SIZE, OUTGOING_QUERIES_TOTAL,
        RESPONSE_CACHE_SIZE,
    };
    #[cfg(feature = "__dnssec")]
    use crate::recursor::DnssecConfig;
    use crate::recursor::DnssecPolicy;

    #[test]
    fn test_recursor_metrics() {
        subscribe();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let query_name = Name::parse("hickory-dns.testing.", None).unwrap();

        with_local_recorder(&recorder, || {
            let runtime = Builder::new_current_thread().enable_all().build().unwrap();

            let tld_zone = Name::from_ascii("testing.").unwrap();
            let tld_ns = Name::from_ascii("testing.testing.").unwrap();
            let leaf_zone = Name::from_ascii("hickory-dns.testing.").unwrap();
            let leaf_ns = Name::from_ascii("leaf.testing.").unwrap();

            let handler = MockNetworkHandler::new(vec![
                MockRecord::ns(ROOT_IP, &tld_zone, &tld_ns),
                MockRecord::a(ROOT_IP, &tld_ns, TLD_IP)
                    .with_query_name(&tld_zone)
                    .with_query_type(RecordType::NS)
                    .with_section(MockResponseSection::Additional),
                MockRecord::ns(TLD_IP, &leaf_zone, &leaf_ns),
                MockRecord::a(TLD_IP, &leaf_ns, LEAF_IP)
                    .with_query_name(&leaf_zone)
                    .with_query_type(RecordType::NS)
                    .with_section(MockResponseSection::Additional),
                MockRecord::a(LEAF_IP, &leaf_zone, A_RR_IP),
            ]);

            let provider = MockProvider::new(handler);

            #[cfg(not(feature = "__dnssec"))]
            let policy = DnssecPolicy::SecurityUnaware;
            #[cfg(feature = "__dnssec")]
            let policy = DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default());

            let recursor = Recursor::new(
                &[ROOT_IP],
                policy,
                None,
                RecursorOptions {
                    deny_server: Vec::new(),
                    ..RecursorOptions::default()
                },
                provider,
            )
            .unwrap();

            runtime.block_on(async {
                for _ in 0..3 {
                    let response = recursor
                        .resolve(
                            Query::new(query_name.clone(), RecordType::A),
                            Instant::now(),
                            false,
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.response_code, ResponseCode::NoError);
                }
            });
        });

        #[allow(clippy::mutable_key_type)]
        // False positive, see the documentation for metrics::Key.
        let map = snapshotter.snapshot().into_hashmap();

        // The expected counts of queries/cache hits/misses/etc differ
        // depending on whether we were validating DNSSEC, which requires
        // additional queries.

        #[cfg(not(feature = "__dnssec"))]
        {
            assert_counter_eq(&map, OUTGOING_QUERIES_TOTAL, vec![], 3);
            assert_counter_eq(&map, CACHE_HIT_TOTAL, vec![], 2);
            assert_counter_eq(&map, CACHE_MISS_TOTAL, vec![], 1);
            assert_histogram_sample_count_eq(&map, CACHE_HIT_DURATION, vec![], 2, Unit::Seconds);
            assert_histogram_sample_count_eq(&map, CACHE_MISS_DURATION, vec![], 1, Unit::Seconds);

            assert_gauge_eq(&map, RESPONSE_CACHE_SIZE, vec![], 3);
            assert_gauge_eq(&map, NAME_SERVER_CACHE_SIZE, vec![], 2);
            assert_gauge_eq(&map, CONNECTION_CACHE_SIZE, vec![], 2);
            assert_gauge_eq(&map, IN_FLIGHT_QUERIES, vec![], 0);
        }

        #[cfg(feature = "__dnssec")]
        {
            assert_counter_eq(&map, OUTGOING_QUERIES_TOTAL, vec![], 4);
            assert_counter_eq(&map, CACHE_HIT_TOTAL, vec![], 5);
            assert_counter_eq(&map, CACHE_MISS_TOTAL, vec![], 2);
            assert_histogram_sample_count_eq(&map, CACHE_HIT_DURATION, vec![], 3, Unit::Seconds);
            assert_histogram_sample_count_eq(&map, CACHE_MISS_DURATION, vec![], 1, Unit::Seconds);

            // When validating DNSSEC, we should also see DNSSEC-specific metrics.
            // The state of the mock data means all answers should have been considered
            // bogus.
            assert_counter_eq(&map, SECURE_ANSWERS_TOTAL, vec![], 0);
            assert_counter_eq(&map, INSECURE_ANSWERS_TOTAL, vec![], 0);
            assert_counter_eq(&map, BOGUS_ANSWERS_TOTAL, vec![], 5);
            assert_counter_eq(&map, INDETERMINATE_ANSWERS_TOTAL, vec![], 0);

            // Both the regular cache and validated cache should have entries.
            assert_gauge_eq(&map, RESPONSE_CACHE_SIZE, vec![], 3);
            assert_gauge_eq(&map, VALIDATED_RESPONSE_CACHE_SIZE, vec![], 1);
            assert_gauge_eq(&map, NAME_SERVER_CACHE_SIZE, vec![], 2);
            assert_gauge_eq(&map, CONNECTION_CACHE_SIZE, vec![], 2);
            assert_gauge_eq(&map, IN_FLIGHT_QUERIES, vec![], 0);
        }
    }

    const A_RR_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
}

#[cfg(all(
    test,
    feature = "serde",
    feature = "toml",
    any(feature = "__tls", feature = "__quic")
))]
mod config {
    use std::{fs, path::Path};

    use hickory_proto::rr::Name;

    use crate::{
        config::{OpportunisticEncryption, OpportunisticEncryptionConfig},
        recursor::{
            DnssecPolicyConfig, ForcedEncryptedAuthoritativeConfig,
            ForcedEncryptedAuthoritativePolicy, ForcedEncryptedAuthoritativePolicyError,
            ForcedEncryptedAuthoritativeProtocol, ForcedEncryptedAuthoritativeServerConfig,
            RecursiveConfig,
        },
    };

    #[test]
    fn can_parse_recursive_config() {
        let input = r#"roots = "/etc/root.hints"
forced_encrypted_authoritatives = "/etc/servers.json"
dnssec_policy.ValidateWithStaticKey.path = "/etc/trusted-key.key""#;

        let config = toml::from_str::<RecursiveConfig>(input).unwrap();

        assert_eq!(
            config.forced_encrypted_authoritatives.as_deref(),
            Some(Path::new("/etc/servers.json"))
        );

        if let DnssecPolicyConfig::ValidateWithStaticKey { path, .. } = config.dnssec_policy {
            assert_eq!(Some(Path::new("/etc/trusted-key.key")), path.as_deref());
        } else {
            unreachable!()
        }
    }

    #[test]
    fn can_parse_recursor_cache_policy() {
        use std::time::Duration;

        use hickory_proto::rr::RecordType;

        let input = r#"roots = "/etc/root.hints"

[cache_policy.default]
positive_max_ttl = 14400

[cache_policy.A]
positive_max_ttl = 3600"#;

        let config = toml::from_str::<RecursiveConfig>(input).unwrap();

        assert_eq!(
            *config
                .options
                .cache_policy
                .positive_response_ttl_bounds(RecordType::MX)
                .end(),
            Duration::from_secs(14400)
        );

        assert_eq!(
            *config
                .options
                .cache_policy
                .positive_response_ttl_bounds(RecordType::A)
                .end(),
            Duration::from_secs(3600)
        )
    }

    #[test]
    fn can_parse_recursor_opportunistic_enc_policy() {
        let input = r#"roots = "/etc/root.hints"
[opportunistic_encryption]
enabled = {}
"#;

        let config = toml::from_str::<RecursiveConfig>(input).unwrap();
        assert_eq!(
            config.options.opportunistic_encryption,
            OpportunisticEncryption::Enabled {
                config: OpportunisticEncryptionConfig::default()
            }
        );
    }

    #[test]
    fn can_parse_recursor_forced_encrypted_authoritatives_json() {
        let input = r#"{"servers":[{"name":"a.root-servers.net.","address":"198.41.0.4","protocol":"dot"}]}"#;
        let parsed: ForcedEncryptedAuthoritativeConfig = serde_json::from_str(input).unwrap();

        assert_eq!(
            parsed.servers[0].name,
            Name::from_ascii("a.root-servers.net.").unwrap()
        );
        assert_eq!(
            parsed.servers[0].address,
            Some("198.41.0.4".parse().unwrap())
        );
        assert_eq!(
            parsed.servers[0].protocol,
            ForcedEncryptedAuthoritativeProtocol::Dot
        );
    }

    #[test]
    fn can_read_recursor_forced_encrypted_authoritatives_json_file() {
        let path = std::env::temp_dir().join(format!(
            "hickory-forced-encrypted-authoritatives-{}.json",
            std::process::id()
        ));
        let input = r#"{"servers":[{"name":"a.root-servers.net.","address":"198.41.0.4","protocol":"dot"}]}"#;
        fs::write(&path, input).unwrap();

        let parsed = ForcedEncryptedAuthoritativeConfig::read_json(&path).unwrap();

        fs::remove_file(&path).unwrap();
        assert_eq!(
            parsed.servers[0].name,
            Name::from_ascii("a.root-servers.net.").unwrap()
        );
        assert_eq!(
            parsed.servers[0].address,
            Some("198.41.0.4".parse().unwrap())
        );
        assert_eq!(
            parsed.servers[0].protocol,
            ForcedEncryptedAuthoritativeProtocol::Dot
        );
    }

    #[test]
    fn forced_encrypted_authoritative_policy_matches_by_ip() {
        let server = super::policy_validation::server();
        let address = server.address.unwrap();
        let policy =
            ForcedEncryptedAuthoritativePolicy::try_from(ForcedEncryptedAuthoritativeConfig {
                authenticated_referrals: false,
                servers: vec![server.clone()],
                zones: vec![],
            })
            .unwrap();

        assert_eq!(policy.server_for(address).unwrap().name, server.name);
        assert_eq!(policy.server_for("198.41.0.5".parse().unwrap()), None);
        assert_eq!(
            policy.protocol_for("198.41.0.4".parse().unwrap()),
            Some(ForcedEncryptedAuthoritativeProtocol::Dot)
        );
        assert_eq!(policy.protocol_for("198.41.0.5".parse().unwrap()), None);
    }

    #[test]
    fn forced_encrypted_authoritative_config_converts_to_policy() {
        let config = ForcedEncryptedAuthoritativeConfig {
            authenticated_referrals: false,
            zones: vec![],
            servers: vec![ForcedEncryptedAuthoritativeServerConfig {
                name: Name::from_ascii("a.root-servers.net.").unwrap(),
                address: Some("198.41.0.4".parse().unwrap()),
                protocol: ForcedEncryptedAuthoritativeProtocol::Dot,
                trust_anchor: Some(super::TEST_TRUST_ANCHOR.to_owned()),
                comment: None,
            }],
        };

        let policy = ForcedEncryptedAuthoritativePolicy::try_from(config).unwrap();

        let server = policy.server_for("198.41.0.4".parse().unwrap()).unwrap();
        assert_eq!(
            server.name,
            Name::from_ascii("a.root-servers.net.").unwrap()
        );
        assert_eq!(
            server.address,
            "198.41.0.4".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            server.trust_anchor.as_deref(),
            Some(super::TEST_TRUST_ANCHOR)
        );
        assert_eq!(server.tls_name, "a.root-servers.net");
        assert_eq!(server.trust_roots.len(), 1);
        assert_eq!(
            policy.protocol_for("198.41.0.4".parse().unwrap()),
            Some(ForcedEncryptedAuthoritativeProtocol::Dot)
        );
    }

    #[test]
    fn forced_encrypted_authoritative_config_preserves_server_fields() {
        let first_anchor = super::TEST_TRUST_ANCHOR;
        let second_anchor = format!("\r\n{}\r\n", first_anchor.replace('\n', "\r\n"));
        let input = serde_json::json!({"servers":[
            {"name":"NS.first.test.","address":"192.0.2.1","protocol":"dot",
             "trust_anchor": first_anchor},
            {"name":"ns.second.test.","address":"2001:db8::2","protocol":"dot",
             "trust_anchor": second_anchor}
        ]});
        let config: ForcedEncryptedAuthoritativeConfig = serde_json::from_value(input).unwrap();
        let expected = config.servers.clone();
        let policy = ForcedEncryptedAuthoritativePolicy::try_from(config).unwrap();

        for expected in expected {
            let server = policy.server_for(expected.address.unwrap()).unwrap();
            assert_eq!(server.name.to_ascii(), expected.name.to_ascii());
            assert_eq!(server.address, expected.address.unwrap());
            assert_eq!(server.protocol, expected.protocol);
            assert_eq!(server.trust_anchor, expected.trust_anchor);
            assert_eq!(server.trust_roots.len(), 1);
            assert_eq!(policy.protocol_for(server.address), Some(server.protocol));
        }
        assert_eq!(policy.server_for("192.0.2.99".parse().unwrap()), None);
    }

    #[test]
    fn forced_encrypted_authoritative_config_rejects_invalid_policy_entries() {
        let missing_address = ForcedEncryptedAuthoritativeConfig {
            authenticated_referrals: false,
            zones: vec![],
            servers: vec![ForcedEncryptedAuthoritativeServerConfig {
                name: Name::from_ascii("a.root-servers.net.").unwrap(),
                address: None,
                protocol: ForcedEncryptedAuthoritativeProtocol::Dot,
                trust_anchor: None,
                comment: None,
            }],
        };
        assert!(matches!(
            ForcedEncryptedAuthoritativePolicy::try_from(missing_address),
            Err(ForcedEncryptedAuthoritativePolicyError::MissingServerAddress { .. })
        ));
    }
}

// These existing public certificates exercise parsing, not live TLS validity.
#[cfg(feature = "serde")]
const TEST_TRUST_ANCHOR: &str = include_str!("../../../../tests/test-data/ca.pem");

#[cfg(feature = "serde")]
mod policy_validation {
    use super::TEST_TRUST_ANCHOR;
    use crate::{
        proto::rr::Name,
        recursor::{
            ForcedEncryptedAuthoritativeConfig, ForcedEncryptedAuthoritativePolicy,
            ForcedEncryptedAuthoritativePolicyError as PolicyError,
            ForcedEncryptedAuthoritativeProtocol as Protocol,
            ForcedEncryptedAuthoritativeServerConfig as Server,
        },
    };

    pub(super) fn server() -> Server {
        Server {
            name: Name::from_ascii("a.root-servers.net.").unwrap(),
            address: Some("198.41.0.4".parse().unwrap()),
            protocol: Protocol::Dot,
            trust_anchor: Some(TEST_TRUST_ANCHOR.to_owned()),
            comment: None,
        }
    }

    fn convert(servers: Vec<Server>) -> Result<ForcedEncryptedAuthoritativePolicy, PolicyError> {
        ForcedEncryptedAuthoritativeConfig {
            authenticated_referrals: false,
            servers,
            zones: vec![],
        }
        .try_into()
    }

    #[test]
    fn empty_policy_is_valid() {
        assert_eq!(
            convert(vec![]).unwrap(),
            ForcedEncryptedAuthoritativePolicy::default()
        );
    }

    #[test]
    fn missing_address_is_rejected() {
        let mut entry = server();
        entry.address = None;
        assert!(matches!(
            convert(vec![entry]),
            Err(PolicyError::MissingServerAddress { .. })
        ));
    }

    #[cfg(not(feature = "__quic"))]
    #[test]
    fn doq_is_rejected_without_quic_support() {
        let mut entry = server();
        entry.protocol = Protocol::Doq;
        assert!(matches!(
            convert(vec![entry]),
            Err(PolicyError::UnsupportedProtocol {
                protocol: Protocol::Doq,
                ..
            })
        ));
    }

    #[cfg(feature = "__quic")]
    #[test]
    fn doq_is_accepted_when_quic_is_available() {
        let mut entry = server();
        entry.protocol = Protocol::Doq;
        let policy = convert(vec![entry]).unwrap();
        assert_eq!(
            policy.servers.values().next().unwrap().protocol,
            Protocol::Doq
        );
    }

    #[cfg(not(feature = "__tls"))]
    #[test]
    fn dot_is_rejected_without_tls_support() {
        assert!(matches!(
            convert(vec![server()]),
            Err(PolicyError::UnsupportedProtocol {
                protocol: Protocol::Dot,
                ..
            })
        ));
    }

    #[cfg(feature = "__tls")]
    #[test]
    fn missing_or_blank_trust_anchor_is_rejected() {
        for anchor in [None, Some(""), Some(" \r\n\t")] {
            let mut entry = server();
            entry.trust_anchor = anchor.map(str::to_owned);
            assert!(matches!(
                convert(vec![entry]),
                Err(PolicyError::MissingTrustAnchor { .. })
            ));
        }
    }

    #[cfg(feature = "__tls")]
    #[test]
    fn malformed_trust_material_is_rejected_including_partial_bundles() {
        let invalid_der = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----";
        for anchor in [
            "not a certificate".to_owned(),
            "-----BEGIN CERTIFICATE-----\n!invalid base64!\n-----END CERTIFICATE-----".to_owned(),
            "-----BEGIN CERTIFICATE-----\nAQID".to_owned(),
            "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----".to_owned(),
            invalid_der.to_owned(),
            format!("-----BEGIN CERTIFICATE-----\n{TEST_TRUST_ANCHOR}"),
            format!("{TEST_TRUST_ANCHOR}\n{invalid_der}"),
            format!("{invalid_der}\n{TEST_TRUST_ANCHOR}"),
            format!("{TEST_TRUST_ANCHOR}\ntrailing junk"),
            format!("{TEST_TRUST_ANCHOR}\n-----BEGIN CERTIFICATE-----\nAQID"),
            format!(
                "{TEST_TRUST_ANCHOR}\n-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----"
            ),
        ] {
            let mut entry = server();
            entry.trust_anchor = Some(anchor);
            assert!(matches!(
                convert(vec![entry]),
                Err(PolicyError::InvalidTrustAnchor { .. })
            ));
        }
    }

    #[cfg(feature = "__tls")]
    #[test]
    fn invalid_tls_identities_are_rejected() {
        for name in [".", "*.example.test.", "ns_bad.example.test.", "192.0.2.1."] {
            let mut entry = server();
            entry.name = Name::from_ascii(name).unwrap();
            assert!(
                matches!(
                    convert(vec![entry]),
                    Err(PolicyError::InvalidServerName { .. })
                ),
                "{name}"
            );
        }
    }

    #[cfg(feature = "__tls")]
    const SECOND_TRUST_ANCHOR: &str =
        include_str!("../../../../tests/test-data/test_configs/sec/example.cert.pem");

    #[cfg(feature = "__tls")]
    #[test]
    fn conflicting_addresses_and_names_are_rejected_in_either_order() {
        let original = server();
        let mut other_name = original.clone();
        other_name.name = Name::from_ascii("different.example.test.").unwrap();
        let mut other_trust = original.clone();
        other_trust.trust_anchor = Some(SECOND_TRUST_ANCHOR.to_owned());
        let mut other_address_and_trust = other_trust.clone();
        other_address_and_trust.address = Some("2001:db8::1".parse().unwrap());
        other_address_and_trust.name = Name::from_ascii("A.ROOT-SERVERS.NET").unwrap();

        for reverse in [false, true] {
            for conflicting in [&other_name, &other_trust, &other_address_and_trust] {
                let same_address = original.address == conflicting.address;
                let mut entries = vec![original.clone(), conflicting.clone()];
                if reverse {
                    entries.reverse();
                }
                match convert(entries) {
                    Err(PolicyError::ConflictingServerAddress { .. }) if same_address => {}
                    Err(PolicyError::ConflictingServerName { .. }) if !same_address => {}
                    result => panic!("expected policy conflict, got {result:?}"),
                }
            }
        }
    }

    #[cfg(feature = "__tls")]
    #[test]
    fn equivalent_duplicates_and_multiple_addresses_are_valid() {
        let mut original = server();
        original.trust_anchor = Some(format!("{TEST_TRUST_ANCHOR}\n{SECOND_TRUST_ANCHOR}"));
        let mut equivalent = original.clone();
        equivalent.name = Name::from_ascii("A.ROOT-SERVERS.NET").unwrap();
        equivalent.comment = Some("A note does not change the policy".to_owned());
        equivalent.trust_anchor = Some(
            format!("\r\n{SECOND_TRUST_ANCHOR}\n{TEST_TRUST_ANCHOR}\n{TEST_TRUST_ANCHOR}\n")
                .replace('\n', "\r\n"),
        );
        let mut ipv6 = equivalent.clone();
        ipv6.address = Some("2001:db8::1".parse().unwrap());
        let policy = convert(vec![original.clone(), equivalent, ipv6.clone()]).unwrap();
        assert_eq!(policy.servers.len(), 2);
        for entry in [original, ipv6] {
            let retained = policy.server_for(entry.address.unwrap()).unwrap();
            assert_eq!(retained.tls_name, "a.root-servers.net");
            assert_eq!(retained.name.to_ascii(), entry.name.to_ascii());
            assert_eq!(retained.trust_anchor, entry.trust_anchor);
            assert_eq!(retained.trust_roots.len(), 2);
        }
    }
}

#[cfg(feature = "serde")]
mod policy_wiring {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::{
        LEAF_IP, MockProvider, Name, Query, ROOT_IP, RecordType, Recursor, RecursorMode,
        ResponseCode, test_fixture,
    };
    use crate::{
        net::xfer::Protocol,
        recursor::{DnssecPolicy, DnssecPolicyConfig, RecursiveConfig, handle::RecursorDnsHandle},
    };

    fn policy_json() -> String {
        serde_json::json!({"servers":[{
            "name":"ns.hickory-dns.testing.","address":"10.0.3.1","protocol":"dot",
            "trust_anchor": super::TEST_TRUST_ANCHOR
        }]})
        .to_string()
    }

    struct ConfigFiles(PathBuf);

    impl ConfigFiles {
        fn new(policy: Option<&str>) -> Self {
            static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "hickory-policy-wiring-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let files = Self(path);
            fs::write(
                files.0.join("root.hints"),
                format!(". 3600 IN NS root.testing.\nroot.testing. 3600 IN A {ROOT_IP}\n"),
            )
            .unwrap();
            if let Some(policy) = policy {
                fs::write(files.0.join("servers.json"), policy).unwrap();
            }
            files
        }
    }

    impl Drop for ConfigFiles {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.0.join("servers.json"));
            let _ = fs::remove_file(self.0.join("root.hints"));
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn configured_recursor(
        policy: Option<&str>,
        dnssec_policy: DnssecPolicyConfig,
    ) -> (Recursor<MockProvider>, MockProvider) {
        let files = ConfigFiles::new(policy);
        let (provider, options) = test_fixture().unwrap();
        let config = RecursiveConfig {
            roots: "root.hints".into(),
            forced_encrypted_authoritatives: policy.map(|_| "servers.json".into()),
            dnssec_policy,
            options,
        };
        let recursor = Recursor::from_config(config, Some(&files.0), provider.clone()).unwrap();
        // The resolver must own its policy after the configuration files are removed.
        (recursor, provider)
    }

    fn lookup_handle(recursor: &Recursor<MockProvider>) -> &RecursorDnsHandle<MockProvider> {
        match &recursor.mode {
            RecursorMode::NonValidating { handle } => handle,
            #[cfg(feature = "__dnssec")]
            RecursorMode::Validating(validating) => validating.handle.inner(),
        }
    }

    #[cfg(feature = "__tls")]
    fn assert_retained_policy(recursor: &Recursor<MockProvider>) {
        let handle = lookup_handle(recursor);
        let server = handle.authoritative_server_policy(LEAF_IP).unwrap();
        assert_eq!(
            server.name,
            Name::from_ascii("ns.hickory-dns.testing.").unwrap()
        );
        assert_eq!(server.address, LEAF_IP);
        assert_eq!(
            server.protocol,
            crate::recursor::ForcedEncryptedAuthoritativeProtocol::Dot
        );
        assert_eq!(
            server.trust_anchor.as_deref(),
            Some(super::TEST_TRUST_ANCHOR)
        );
        assert_eq!(server.tls_name, "ns.hickory-dns.testing");
        assert_eq!(server.trust_roots.len(), 1);
        assert_eq!(handle.authoritative_server_policy(ROOT_IP), None);

        let cloned = handle.clone();
        assert!(std::ptr::eq(
            server,
            cloned.authoritative_server_policy(LEAF_IP).unwrap()
        ));
    }

    #[cfg(feature = "__tls")]
    #[test]
    fn from_config_retains_authoritative_policy() {
        let (recursor, _) =
            configured_recursor(Some(&policy_json()), DnssecPolicyConfig::SecurityUnaware);
        assert!(!recursor.is_validating());
        assert_retained_policy(&recursor);
    }

    #[cfg(feature = "__quic")]
    #[test]
    fn from_config_retains_required_doq_and_its_verifier() {
        let mut value: serde_json::Value = serde_json::from_str(&policy_json()).unwrap();
        value["servers"][0]["protocol"] = "doq".into();
        let (recursor, provider) = configured_recursor(
            Some(&value.to_string()),
            DnssecPolicyConfig::SecurityUnaware,
        );
        let handle = lookup_handle(&recursor);
        assert_eq!(
            handle
                .authoritative_server_policy(LEAF_IP)
                .unwrap()
                .protocol,
            crate::recursor::ForcedEncryptedAuthoritativeProtocol::Doq
        );
        let context = handle.pool_context();
        let endpoint = &context.server_tls_configs[&LEAF_IP];
        assert_eq!(endpoint.protocol, Protocol::Quic);
        assert_eq!(&*endpoint.server_name, "ns.hickory-dns.testing");
        assert!(provider.new_connection_calls().is_empty());
    }

    #[cfg(all(feature = "__dnssec", feature = "__tls"))]
    #[test]
    fn from_config_retains_authoritative_policy_in_dnssec_modes() {
        for (dnssec_policy, validates) in [
            (DnssecPolicyConfig::ValidationDisabled, false),
            (
                DnssecPolicyConfig::ValidateWithStaticKey {
                    path: None,
                    nsec3_soft_iteration_limit: None,
                    nsec3_hard_iteration_limit: None,
                    validation_cache_size: None,
                },
                true,
            ),
        ] {
            let (recursor, _) = configured_recursor(Some(&policy_json()), dnssec_policy);
            assert_eq!(recursor.is_validating(), validates);
            assert_retained_policy(&recursor);
        }
    }

    #[tokio::test]
    async fn from_config_without_policy_keeps_existing_dns_behavior() {
        let (recursor, provider) = configured_recursor(None, DnssecPolicyConfig::SecurityUnaware);
        assert_eq!(
            lookup_handle(&recursor).authoritative_server_policy(LEAF_IP),
            None
        );
        let query = Query::new(
            Name::from_ascii("host.hickory-dns.testing.").unwrap(),
            RecordType::A,
        );
        let response = recursor
            .resolve(query, std::time::Instant::now(), false)
            .await
            .unwrap();
        assert_eq!(response.response_code, ResponseCode::NoError);
        assert!(
            response
                .answers
                .iter()
                .any(|r| r.data.ip_addr() == Some(LEAF_IP))
        );
        assert!(provider.count_new_connection_calls(LEAF_IP, Protocol::Udp) > 0);
        assert!(provider.count_new_connection_calls(LEAF_IP, Protocol::Tcp) > 0);
    }

    #[test]
    fn from_config_rejects_invalid_policies_before_connecting() {
        let base: serde_json::Value = serde_json::from_str(&policy_json()).unwrap();
        let mut cases = vec![];
        #[cfg(not(feature = "__quic"))]
        {
            let mut doq = base.clone();
            doq["servers"][0]["protocol"] = "doq".into();
            cases.push((doq.to_string(), "unsupported required protocol"));
        }
        let mut missing_address = base.clone();
        missing_address["servers"][0]
            .as_object_mut()
            .unwrap()
            .remove("address");
        cases.push((missing_address.to_string(), "missing address"));
        cases.push((
            "{invalid JSON".to_owned(),
            "failed to parse authoritative encryption policy",
        ));
        #[cfg(not(feature = "__tls"))]
        cases.push((base.to_string(), "unsupported required protocol"));
        #[cfg(feature = "__tls")]
        {
            let mut missing_trust = base.clone();
            missing_trust["servers"][0]
                .as_object_mut()
                .unwrap()
                .remove("trust_anchor");
            cases.push((missing_trust.to_string(), "missing trust anchor"));
            let mut bad_trust = base.clone();
            bad_trust["servers"][0]["trust_anchor"] = "bad PEM".into();
            cases.push((bad_trust.to_string(), "invalid trust anchor"));
            let mut bad_name = base.clone();
            bad_name["servers"][0]["name"] = "*.example.test.".into();
            cases.push((bad_name.to_string(), "invalid TLS DNS name"));
            let mut duplicate = base["servers"][0].clone();
            duplicate["name"] = "another.example.test.".into();
            let conflict = serde_json::json!({"servers":[base["servers"][0], duplicate]});
            cases.push((
                conflict.to_string(),
                "conflicting authoritative encryption policies",
            ));
        }
        for (json, expected_error) in cases {
            let files = ConfigFiles::new(Some(&json));
            let (provider, options) = test_fixture().unwrap();
            let config = RecursiveConfig {
                roots: "root.hints".into(),
                forced_encrypted_authoritatives: Some("servers.json".into()),
                dnssec_policy: DnssecPolicyConfig::SecurityUnaware,
                options,
            };
            let error = match Recursor::from_config(config, Some(&files.0), provider.clone()) {
                Ok(_) => panic!("invalid policy unexpectedly started the resolver"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains(expected_error), "{error}");
            assert!(provider.new_connection_calls().is_empty());
        }
    }

    #[test]
    fn public_constructors_start_without_authoritative_policy() {
        let (provider, options) = test_fixture().unwrap();
        for recursor in [
            Recursor::with_options(&[ROOT_IP], options.clone(), provider.clone()).unwrap(),
            Recursor::new(&[ROOT_IP], DnssecPolicy::default(), None, options, provider).unwrap(),
        ] {
            assert_eq!(
                lookup_handle(&recursor).authoritative_server_policy(LEAF_IP),
                None
            );
        }
    }

    #[cfg(feature = "__tls")]
    mod selection {
        use std::{
            net::IpAddr,
            sync::{Arc, Mutex},
            time::Instant,
        };

        use super::super::{TEST_TRUST_ANCHOR, TLD_IP, test_fixture_with_glue};
        use super::*;
        use crate::{
            ConnectionProvider, PoolContext,
            config::{
                ConnectionConfig, OpportunisticEncryption, OpportunisticEncryptionConfig,
                ProtocolConfig,
            },
            net::NetError,
        };

        #[derive(Clone)]
        struct SelectionProvider {
            inner: MockProvider,
            calls: Arc<Mutex<Vec<SelectedConnection>>>,
            fail_tls_for: Option<IpAddr>,
        }

        struct SelectedConnection {
            ip: IpAddr,
            config: ConnectionConfig,
            uses_endpoint_tls: bool,
        }

        // Records resolver decisions. The mock TCP stream models a successful
        // TLS connection without performing a handshake; these are selection
        // tests, not evidence of live certificate authentication.
        impl ConnectionProvider for SelectionProvider {
            type Conn = <MockProvider as ConnectionProvider>::Conn;
            type FutureConn = <MockProvider as ConnectionProvider>::FutureConn;
            type RuntimeProvider = MockProvider;

            fn new_connection(
                &self,
                ip: IpAddr,
                config: &ConnectionConfig,
                cx: &PoolContext,
            ) -> Result<Self::FutureConn, NetError> {
                self.calls.lock().unwrap().push(SelectedConnection {
                    ip,
                    config: config.clone(),
                    uses_endpoint_tls: !std::ptr::eq(cx.tls_config_for_server(ip), &cx.tls),
                });
                let mut modeled = config.clone();
                if matches!(config.protocol, ProtocolConfig::Tls { .. }) {
                    if self.fail_tls_for == Some(ip) {
                        return Err(NetError::from("simulated TLS connection failure"));
                    }
                    modeled.protocol = ProtocolConfig::Tcp;
                }
                // The wire model is plaintext TCP, so it must use a separate
                // non-policy context. Production correctly rejects TCP with the
                // real required-DoT context; these tests only record selection.
                let modeled_cx =
                    PoolContext::new(cx.options.clone(), crate::TlsConfig::new().unwrap());
                self.inner.new_connection(ip, &modeled, &modeled_cx)
            }

            fn runtime_provider(&self) -> &Self::RuntimeProvider {
                &self.inner
            }
        }

        fn server_name(ip: IpAddr) -> &'static str {
            match ip {
                ROOT_IP => "root.testing",
                TLD_IP => "testing.testing",
                LEAF_IP => "ns.hickory-dns.testing",
                _ => panic!("unexpected fixture address"),
            }
        }

        fn configured(
            protected: &[IpAddr],
            opportunistic: bool,
            include_glue: bool,
            fail_tls_for: Option<IpAddr>,
        ) -> (Recursor<SelectionProvider>, SelectionProvider) {
            let servers = protected
                .iter()
                .map(|ip| {
                    serde_json::json!({
                        "name": format!("{}.", server_name(*ip).to_ascii_uppercase()),
                        "address": ip.to_string(),
                        "protocol": "dot",
                        "trust_anchor": TEST_TRUST_ANCHOR,
                    })
                })
                .collect::<Vec<_>>();
            let json = serde_json::json!({"servers": servers}).to_string();
            let files = ConfigFiles::new(Some(&json));
            let (inner, mut options) = test_fixture_with_glue(include_glue).unwrap();
            if opportunistic {
                options.opportunistic_encryption = OpportunisticEncryption::Enabled {
                    // Keep background probes out of this decision test; listed
                    // endpoints must still use DoT without needing a probe.
                    config: OpportunisticEncryptionConfig {
                        max_concurrent_probes: 0,
                        ..OpportunisticEncryptionConfig::default()
                    },
                };
            }
            let provider = SelectionProvider {
                inner,
                calls: Arc::new(Mutex::new(vec![])),
                fail_tls_for,
            };
            let config = RecursiveConfig {
                roots: "root.hints".into(),
                forced_encrypted_authoritatives: Some("servers.json".into()),
                dnssec_policy: DnssecPolicyConfig::SecurityUnaware,
                options,
            };
            let recursor = Recursor::from_config(config, Some(&files.0), provider.clone()).unwrap();
            (recursor, provider)
        }

        async fn resolve(
            recursor: &Recursor<SelectionProvider>,
        ) -> Result<crate::proto::op::Message, crate::recursor::RecursorError> {
            recursor
                .resolve(
                    Query::new(
                        Name::from_ascii("host.hickory-dns.testing.").unwrap(),
                        RecordType::A,
                    ),
                    Instant::now(),
                    false,
                )
                .await
        }

        fn assert_selected(provider: &SelectionProvider, protected: &[IpAddr]) {
            let calls = provider.calls.lock().unwrap();
            for ip in [ROOT_IP, TLD_IP, LEAF_IP] {
                let selected = calls
                    .iter()
                    .filter(|call| call.ip == ip)
                    .collect::<Vec<_>>();
                assert!(!selected.is_empty(), "no connection selected for {ip}");
                if protected.contains(&ip) {
                    for call in selected {
                        assert_eq!(call.config.port, 853);
                        assert_eq!(
                            call.config.protocol,
                            ProtocolConfig::Tls {
                                server_name: Arc::from(server_name(ip)),
                            }
                        );
                        assert!(call.uses_endpoint_tls);
                    }
                } else {
                    // With no successful opportunistic probe, ordinary servers
                    // retain UDP followed by TCP for the truncated mock reply.
                    assert!(
                        selected
                            .iter()
                            .any(|call| call.config.protocol == ProtocolConfig::Udp)
                    );
                    assert!(
                        selected
                            .iter()
                            .any(|call| call.config.protocol == ProtocolConfig::Tcp)
                    );
                    for call in selected {
                        assert_eq!(call.config.port, 53);
                        assert!(!call.uses_endpoint_tls);
                    }
                }
            }
        }

        #[tokio::test]
        async fn listed_root_and_referral_addresses_select_dot_only() {
            for opportunistic in [false, true] {
                for protected in [
                    vec![ROOT_IP],
                    vec![TLD_IP],
                    vec![LEAF_IP],
                    vec![ROOT_IP, TLD_IP, LEAF_IP],
                ] {
                    let (recursor, provider) = configured(&protected, opportunistic, true, None);
                    let response = resolve(&recursor).await.unwrap();
                    assert_eq!(response.response_code, ResponseCode::NoError);
                    assert!(
                        response
                            .answers
                            .iter()
                            .any(|r| r.data.ip_addr() == Some(LEAF_IP))
                    );
                    assert_selected(&provider, &protected);
                }
            }
        }

        #[tokio::test]
        async fn resolved_nameserver_addresses_select_dot_only() {
            for opportunistic in [false, true] {
                let (recursor, provider) = configured(&[LEAF_IP], opportunistic, false, None);
                let response = resolve(&recursor).await.unwrap();
                assert_eq!(response.response_code, ResponseCode::NoError);
                assert!(
                    response
                        .answers
                        .iter()
                        .any(|r| r.data.ip_addr() == Some(LEAF_IP))
                );
                assert!(provider.inner.queries(&TLD_IP).contains(&Query::new(
                    Name::from_ascii("ns.hickory-dns.testing.").unwrap(),
                    RecordType::A,
                )));
                assert_selected(&provider, &[LEAF_IP]);
            }
        }

        #[tokio::test]
        async fn failed_dot_does_not_select_plaintext_for_the_listed_address() {
            for opportunistic in [false, true] {
                let (recursor, provider) =
                    configured(&[LEAF_IP], opportunistic, true, Some(LEAF_IP));
                assert!(resolve(&recursor).await.is_err());
                assert_selected(&provider, &[LEAF_IP]);
                assert!(provider.inner.queries(&LEAF_IP).is_empty());
            }
        }
    }
}

const ROOT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
const TLD_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
const LEAF_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 1));
const DELEGATED_LEAF_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 1));
const ENT_DELEGATED_LEAF_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 5, 1));
