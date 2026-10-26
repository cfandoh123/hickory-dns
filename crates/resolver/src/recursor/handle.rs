use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use async_recursion::async_recursion;
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use lru_cache::LruCache;
use parking_lot::Mutex;
use tracing::{debug, trace, warn};

#[cfg(all(test, feature = "serde", feature = "__tls"))]
#[path = "security_tests.rs"]
mod security_tests;

#[cfg(all(feature = "serde", feature = "__tls"))]
use super::ForcedEncryptedAuthoritativeProtocol;
use super::{
    DnssecPolicy, QNameMinimization, RecursorError, RecursorOptions, error::AuthorityData,
    is_subzone,
};
#[cfg(feature = "serde")]
use super::{ForcedEncryptedAuthoritativePolicy, ForcedEncryptedAuthoritativeServerPolicy};
#[cfg(feature = "metrics")]
use crate::metrics::recursor::RecursorMetrics;
#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::rdata::DNSSECRData;
use crate::{
    cache::{ResponseCache, TtlConfig},
    config::{NameServerConfig, OpportunisticEncryption, ResolverOpts},
    connection_provider::{ConnectionProvider, TlsConfig},
    name_server::NameServer,
    name_server_pool::{NameServerPool, NameServerTransportState, PoolContext},
    net::DnsHandle,
    proto::{
        access_control::{AccessControlSet, AccessControlSetBuilder},
        op::{DnsRequestOptions, Message, Query},
        rr::{
            Name, RData,
            RData::CNAME,
            Record, RecordType,
            rdata::{A, AAAA, NS},
        },
    },
};

/// Cache identity for an endpoint and the immutable trust settings used to reach it.
/// An address alone would allow an ordinary or differently authenticated session
/// to be reused for a protected lookup.
#[derive(Clone, Eq, PartialEq, Hash)]
struct ConnectionCacheKey {
    config: NameServerConfig,
    #[cfg(feature = "__tls")]
    tls_identity: Option<crate::connection_provider::TlsConfigIdentity>,
}

#[derive(Clone)]
pub(crate) struct RecursorDnsHandle<P: ConnectionProvider> {
    roots: NameServerPool<P>,
    name_server_cache: Arc<Mutex<LruCache<Name, NameServerPool<P>>>>,
    response_cache: ResponseCache,
    #[cfg(feature = "serde")]
    authenticated_response_cache: ResponseCache,
    #[cfg(feature = "metrics")]
    pub(super) metrics: RecursorMetrics,
    recursion_limit: u8,
    ns_recursion_limit: u8,
    name_server_filter: AccessControlSet,
    pool_context: Arc<PoolContext>,
    conn_provider: P,
    connection_cache: Arc<Mutex<LruCache<ConnectionCacheKey, Arc<NameServer<P>>>>>,
    request_options: DnsRequestOptions,
    ttl_config: TtlConfig,
    qname_minimization: QNameMinimization,
    #[cfg(feature = "serde")]
    forced_encrypted_authoritative_policy: Option<Arc<ForcedEncryptedAuthoritativePolicy>>,
}

impl<P: ConnectionProvider> RecursorDnsHandle<P> {
    pub(super) fn new(
        roots: &[IpAddr],
        dnssec_policy: DnssecPolicy,
        encrypted_transport_state: Option<NameServerTransportState>,
        options: RecursorOptions,
        tls: TlsConfig,
        conn_provider: P,
        #[cfg(feature = "serde")] forced_encrypted_authoritative_policy: Option<
            Arc<ForcedEncryptedAuthoritativePolicy>,
        >,
    ) -> Result<Self, RecursorError> {
        assert!(!roots.is_empty(), "roots must not be empty");
        if options.connect_timeout_ms == Some(0) {
            return Err("connect_timeout_ms must be greater than zero".into());
        }
        #[cfg(feature = "serde")]
        if let Some(policy) = &forced_encrypted_authoritative_policy {
            if policy.authenticated_referrals
                && roots.iter().any(|ip| policy.server_for(*ip).is_none())
            {
                return Err(RecursorError::SecurityPolicy {
                    name: Name::root(),
                    reason: "authenticated referrals require a configured identity for every root address",
                });
            }
        }
        let servers = roots
            .iter()
            .copied()
            .map(|ip| {
                name_server_config(
                    ip,
                    &options.opportunistic_encryption,
                    #[cfg(all(feature = "serde", feature = "__tls"))]
                    forced_encrypted_authoritative_policy
                        .as_ref()
                        .and_then(|policy| policy.server_for(ip)),
                )
            })
            .collect::<Vec<_>>();

        let RecursorOptions {
            connect_timeout_ms,
            ns_cache_size,
            response_cache_size,
            recursion_limit,
            ns_recursion_limit,
            allow_answers,
            deny_answers,
            allow_server,
            deny_server,
            avoid_local_udp_ports,
            cache_policy,
            case_randomization,
            opportunistic_encryption,
            edns_payload_len,
            qname_minimization,
        } = options;

        let avoid_local_udp_ports = Arc::new(avoid_local_udp_ports);

        debug!(
            "Using cache sizes {}/{}",
            ns_cache_size, response_cache_size
        );

        let mut pool_context = PoolContext::new(
            recursor_opts(
                avoid_local_udp_ports.clone(),
                case_randomization,
                edns_payload_len,
                connect_timeout_ms,
            ),
            tls,
        )
        .with_probe_budget(
            opportunistic_encryption
                .max_concurrent_probes()
                .unwrap_or_default(),
        )
        .with_answer_filter(
            AccessControlSetBuilder::new("answers")
                .allow(allow_answers.iter()) // no recommended exceptions
                .deny(deny_answers.iter()) // no recommend default filters
                .build()?,
        );
        pool_context.opportunistic_encryption = opportunistic_encryption;
        if let Some(state) = encrypted_transport_state {
            pool_context = pool_context.with_transport_state(state);
        }

        #[cfg(all(feature = "serde", feature = "__tls"))]
        if let Some(policy) = &forced_encrypted_authoritative_policy {
            for server in policy.servers.values() {
                let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                    crate::net::tls::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(crate::net::NetError::from)?
                .with_root_certificates(rustls::RootCertStore {
                    roots: server.trust_roots.clone(),
                })
                .with_no_client_auth();
                let protocol = name_server_config(
                    server.address,
                    &pool_context.opportunistic_encryption,
                    Some(server),
                )
                .connections[0]
                    .protocol
                    .to_protocol();
                pool_context = pool_context.with_server_tls_config(
                    server.address,
                    Arc::from(server.tls_name.as_str()),
                    protocol,
                    tls,
                );
            }
        }

        let pool_context = Arc::new(pool_context);
        let roots =
            NameServerPool::from_config(servers, pool_context.clone(), conn_provider.clone());
        #[cfg(feature = "serde")]
        // Start the trust requirement at the root; adding it only to child
        // pools would leave the first referral open to substitution.
        let roots = if forced_encrypted_authoritative_policy
            .as_ref()
            .is_some_and(|policy| policy.authenticated_referrals)
        {
            roots.with_required_authentication()
        } else {
            roots
        };

        let name_server_cache = Arc::new(Mutex::new(LruCache::new(ns_cache_size)));
        let response_cache = ResponseCache::new(response_cache_size, cache_policy.clone());

        // DnsRequestOptions to use with outbound requests made by the recursor.
        let mut request_options = DnsRequestOptions::default();
        request_options.edns_set_dnssec_ok = dnssec_policy.is_security_aware();
        // Set RD=0 in queries made by the recursive resolver. See the last figure in
        // section 2.2 of RFC 1035, for example. Failure to do so may allow for loops
        // between recursive resolvers following referrals to each other.
        request_options.recursion_desired = false;
        request_options.edns_payload_len = edns_payload_len;

        Ok(Self {
            roots,
            name_server_cache,
            response_cache,
            #[cfg(feature = "serde")]
            authenticated_response_cache: ResponseCache::new(
                response_cache_size,
                cache_policy.clone(),
            ),
            #[cfg(feature = "metrics")]
            metrics: RecursorMetrics::new(),
            recursion_limit,
            ns_recursion_limit,
            name_server_filter: AccessControlSetBuilder::new("name_servers")
                .allow(allow_server.iter())
                .deny(deny_server.iter())
                .build()?,
            pool_context,
            conn_provider,
            connection_cache: Arc::new(Mutex::new(LruCache::new(ns_cache_size))),
            request_options,
            ttl_config: cache_policy.clone(),
            qname_minimization,
            #[cfg(feature = "serde")]
            forced_encrypted_authoritative_policy,
        })
    }

    /// Look up the validated policy for an authoritative connection.
    #[cfg(feature = "serde")]
    pub(super) fn authoritative_server_policy(
        &self,
        ip: IpAddr,
    ) -> Option<&ForcedEncryptedAuthoritativeServerPolicy> {
        self.forced_encrypted_authoritative_policy
            .as_ref()
            .and_then(|policy| policy.server_for(ip))
    }

    /// Choose the required authenticated transport before considering opportunistic defaults.
    fn name_server_config(&self, ip: IpAddr) -> NameServerConfig {
        name_server_config(
            ip,
            &self.pool_context.opportunistic_encryption,
            #[cfg(all(feature = "serde", feature = "__tls"))]
            self.authoritative_server_policy(ip),
        )
    }

    /// Reuse endpoint state only when connection parameters and TLS trust identity match.
    fn cached_name_server(&self, config: &NameServerConfig) -> Arc<NameServer<P>> {
        let key = ConnectionCacheKey {
            config: config.clone(),
            #[cfg(feature = "__tls")]
            tls_identity: self
                .pool_context
                .server_tls_configs
                .get(&config.ip)
                .map(|server| server.identity.clone()),
        };
        let mut cache = self.connection_cache.lock();
        if let Some(server) = cache.get_mut(&key) {
            return server.clone();
        }
        let server = Arc::new(NameServer::new(
            [],
            config.clone(),
            &self.pool_context.options,
            self.conn_provider.clone(),
        ));
        cache.insert(key, server.clone());
        server
    }

    #[cfg(feature = "serde")]
    /// Find the longest trusted local binding covering a name, if binding mode is in use.
    fn configured_zone(&self, name: &Name) -> Option<(&Name, &[IpAddr])> {
        self.forced_encrypted_authoritative_policy
            .as_ref()
            .and_then(|policy| policy.zone_for(name))
    }

    /// Whether all referral and supported dependency hops require authenticated transport.
    fn authenticated_referrals(&self) -> bool {
        #[cfg(feature = "serde")]
        return self
            .forced_encrypted_authoritative_policy
            .as_ref()
            .is_some_and(|policy| policy.authenticated_referrals);
        #[cfg(not(feature = "serde"))]
        false
    }

    /// Authorize a referred NS name/address pair before creating its connection settings.
    /// A trusted parent supplies the NS identity; the curated endpoint policy supplies
    /// its permitted address and trust anchor. An IP match alone is not sufficient.
    fn referral_server_config(
        &self,
        name: &Name,
        ip: IpAddr,
    ) -> Result<NameServerConfig, RecursorError> {
        #[cfg(feature = "serde")]
        if self.authenticated_referrals() {
            let expected = name.to_ascii().trim_end_matches('.').to_ascii_lowercase();
            if !self
                .authoritative_server_policy(ip)
                .is_some_and(|server| server.tls_name == expected)
            {
                return Err(RecursorError::SecurityPolicy {
                    name: name.clone(),
                    reason: "referral nameserver name and address do not match a configured authenticated endpoint",
                });
            }
        }
        let _ = name;
        Ok(self.name_server_config(ip))
    }

    /// Keep protected answers and referrals separate from ordinary cached responses.
    /// DS records belong to the parent zone, so binding-mode selection uses that parent.
    fn response_cache_for_query(&self, query: &Query) -> &ResponseCache {
        #[cfg(feature = "serde")]
        {
            let zone = if query.query_type == RecordType::DS {
                query.name.base_name()
            } else {
                query.name.clone()
            };
            if self.authenticated_referrals() || self.configured_zone(&zone).is_some() {
                return &self.authenticated_response_cache;
            }
        }
        let _ = query;
        &self.response_cache
    }

    #[cfg(feature = "serde")]
    /// Build a required-authentication pool from a trusted local zone binding.
    /// These addresses bypass referral discovery; authenticated-referral mode forbids bindings.
    fn configured_pool(&self, query: &Name) -> Result<Option<NameServerPool<P>>, RecursorError> {
        let Some((zone, addresses)) = self.configured_zone(query) else {
            return Ok(None);
        };
        // Local bindings are an authenticated bootstrap: an untrusted referral
        // cannot add, remove, or replace these eligible endpoints.
        let servers = addresses
            .iter()
            .copied()
            .filter(|ip| !self.name_server_filter.denied(*ip))
            .map(|ip| self.cached_name_server(&self.name_server_config(ip)))
            .collect::<Vec<_>>();
        if servers.is_empty() {
            return Err(RecursorError::SecurityPolicy {
                name: zone.clone(),
                reason: "no approved endpoint passes the server address filter",
            });
        }
        Ok(Some(
            NameServerPool::from_nameservers(servers, self.pool_context.clone())
                .with_zone(zone.clone())
                .with_required_authentication(),
        ))
    }

    pub(crate) async fn resolve(
        &self,
        query: Query,
        request_time: Instant,
        query_has_dnssec_ok: bool,
        depth: u8,
        cname_limit: Arc<AtomicU8>,
    ) -> Result<Message, RecursorError> {
        #[cfg(feature = "metrics")]
        let _guard = self.metrics.new_inflight_query();

        #[cfg(feature = "serde")]
        if query.query_type == RecordType::DS
            && self.configured_zone(&query.name).is_some()
            && self.configured_zone(&query.name.base_name()).is_none()
        {
            return Err(RecursorError::SecurityPolicy {
                name: query.name.clone(),
                reason: "DS queries require an authenticated binding for the parent zone",
            });
        }
        if let Some(result) = self
            .response_cache_for_query(&query)
            .get(&query, request_time)
        {
            let response = result?;
            if response.authoritative {
                #[cfg(feature = "metrics")]
                {
                    self.metrics.cache_hit_counter.increment(1);
                    self.metrics
                        .cache_size
                        .set(self.response_cache.entry_count() as f64);
                }

                let response = self
                    .resolve_cnames(
                        response,
                        query.clone(),
                        request_time,
                        query_has_dnssec_ok,
                        depth,
                        cname_limit,
                    )
                    .await?;

                let result = response.maybe_strip_dnssec_records(query_has_dnssec_ok);
                #[cfg(feature = "metrics")]
                {
                    self.metrics
                        .cache_hit_duration
                        .record(request_time.elapsed());
                    self.metrics
                        .cache_size
                        .set(self.response_cache.entry_count() as f64);
                }
                return Ok(result);
            }
        }

        #[cfg(feature = "metrics")]
        self.metrics.cache_miss_counter.increment(1);

        // Recursively search for authoritative name servers for the queried record to build an NS
        // pool to use for queries for a given zone. By searching for the query name, (e.g.
        // 'www.example.com') we should end up with the following set of queries:
        //
        // query NS . for com. -> NS list + glue for com.
        // query NS com. for example.com. -> NS list + glue for example.com.
        // query NS example.com. for www.example.com. -> no data.
        //
        // ns_pool_for_name would then return an NS pool based the results of the last NS RRset,
        // plus any additional glue records that needed to be resolved, and the authoritative name
        // servers for example.com can be queried directly for 'www.example.com'.
        //
        // When querying zone.name() using this algorithm, you make an NS query for www.example.com
        // directed to the nameservers for example.com, which will generally result in those servers
        // returning a no data response, and an additional query being made for whatever record is
        // being queried.
        //
        // If the user is directly querying the second-level domain (e.g., an A query for example.com),
        // the following behavior will occur:
        //
        // query NS . for com. -> NS list + glue for com.
        // query NS com. for example.com. -> NS list + glue for example.com.
        //
        // ns_pool_for_name would return that as the NS pool to use for the query 'example.com'.
        // The subsequent lookup request for then ask the example.com. servers to resolve
        // A example.com.

        let zone = match query.query_type {
            RecordType::DS => query.name.base_name(),
            _ => query.name.clone(),
        };

        let (depth, ns) = match self
            .ns_pool_for_name(zone.clone(), request_time, depth)
            .await
        {
            Ok((depth, ns)) => (depth, ns),
            Err(e) if e.is_security_failure() => return Err(e),
            // Handle the short circuit case for when we receive NXDOMAIN on a parent name, per RFC
            // 8020.
            Err(e) if e.is_nx_domain() => return Err(e),
            Err(e) => {
                return Err(RecursorError::from(format!(
                    "no nameserver found for {zone}: {e}"
                )));
            }
        };

        // Set the zone based on the longest delegation found by ns_pool_for_name.  This will
        // affect bailiwick filtering.
        let Some(zone) = ns.zone() else {
            return Err("no zone information in name server pool".into());
        };

        debug!(%zone, %query, "found zone for query");

        let cached_response = self.filtered_cache_lookup(&query, request_time);
        let response = match cached_response {
            Some(result) => result?,
            None => {
                self.lookup(query.clone(), zone.clone(), ns, request_time)
                    .await?
            }
        };

        let response = self
            .resolve_cnames(
                response,
                query.clone(),
                request_time,
                query_has_dnssec_ok,
                depth,
                cname_limit,
            )
            .await?;

        // RFC 4035 section 3.2.1 if DO bit not set, strip DNSSEC records unless
        // explicitly requested
        let response = response.maybe_strip_dnssec_records(query_has_dnssec_ok);
        #[cfg(feature = "metrics")]
        {
            self.metrics
                .cache_miss_duration
                .record(request_time.elapsed());
            self.metrics
                .cache_size
                .set(self.response_cache.entry_count() as f64);
        }
        Ok(response)
    }

    pub(crate) fn pool_context(&self) -> &Arc<PoolContext> {
        &self.pool_context
    }

    /// Handle CNAME expansion for the current query
    #[async_recursion]
    async fn resolve_cnames(
        &self,
        mut response: Message,
        query: Query,
        now: Instant,
        query_has_dnssec_ok: bool,
        mut depth: u8,
        cname_limit: Arc<AtomicU8>,
    ) -> Result<Message, RecursorError> {
        let query_type = query.query_type;

        // Don't resolve CNAME lookups for a CNAME (or ANY) query
        if query_type == RecordType::CNAME || query_type == RecordType::ANY {
            return Ok(response);
        }

        // Return early if there aren't any CNAME in the response.
        let has_cname = response
            .all_sections()
            .any(|rec| matches!(rec.data, CNAME(_)));
        if !has_cname {
            return Ok(response);
        }

        depth += 1;
        RecursorError::recursion_exceeded(self.recursion_limit, depth, &query.name)?;

        let mut cname_chain = vec![];
        let mut revalidated_names = HashSet::new();
        #[cfg(feature = "serde")]
        let requires_authentication =
            self.authenticated_referrals() || self.configured_zone(&query.name).is_some();

        for rec in response.all_sections() {
            let CNAME(name) = &rec.data else {
                continue;
            };

            #[cfg(feature = "serde")]
            let protected_target =
                self.authenticated_referrals() || self.configured_zone(&name.0).is_some();
            #[cfg(not(feature = "serde"))]
            let protected_target = false;
            #[cfg(feature = "serde")]
            if requires_authentication && !protected_target {
                return Err(RecursorError::SecurityPolicy {
                    name: name.0.clone(),
                    reason: "protected CNAME target has no authenticated zone binding",
                });
            }
            // Inline data from a different zone must not bypass its own local
            // binding. Re-resolve protected targets, including cached CNAMEs.
            if !protected_target && response.answers.iter().any(|record| record.name == name.0) {
                continue;
            }
            if protected_target {
                revalidated_names.insert(name.0.clone());
            }

            let cname_query = Query::new(name.0.clone(), query_type);

            let count = cname_limit.fetch_add(1, Ordering::Relaxed) + 1;
            if count > MAX_CNAME_LOOKUPS {
                warn!("cname limit exceeded for query {query}");
                return Err(RecursorError::MaxRecordLimitExceeded {
                    count: count as usize,
                    record_type: RecordType::CNAME,
                });
            }

            // Note that we aren't worried about whether the intermediates are local or remote
            // to the original queried name, or included or not included in the original
            // response.  Resolve will either pull the intermediates out of the cache or query
            // the appropriate nameservers if necessary.
            let response = match self
                .resolve(
                    cname_query,
                    now,
                    query_has_dnssec_ok,
                    depth,
                    cname_limit.clone(),
                )
                .await
            {
                Ok(cname_r) => cname_r,
                Err(e) => {
                    return Err(e);
                }
            };

            // Here, we're looking for either the terminal record type (matching the
            // original query, or another CNAME.
            cname_chain.extend(response.answers.iter().filter_map(|r| {
                if r.record_type() == query_type || r.record_type() == RecordType::CNAME {
                    return Some(r.to_owned());
                }

                #[cfg(feature = "__dnssec")]
                if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &r.data {
                    let type_covered = rrsig.input().type_covered;
                    if type_covered == query_type || type_covered == RecordType::CNAME {
                        return Some(r.to_owned());
                    }
                }

                None
            }));
        }

        // Also remove inline data when revalidation returns NODATA: an empty
        // authenticated answer must not leave the original inline address alive.
        response
            .answers
            .retain(|record| !revalidated_names.contains(&record.name));
        response.answers.extend(cname_chain);

        Ok(response)
    }

    /// Retrieve a response from the cache, filtering out non-authoritative responses.
    fn filtered_cache_lookup(
        &self,
        query: &Query,
        now: Instant,
    ) -> Option<Result<Message, RecursorError>> {
        let response = match self.response_cache_for_query(query).get(query, now) {
            Some(Ok(response)) => response,
            Some(Err(e)) => return Some(Err(e.into())),
            None => return None,
        };

        if !response.authoritative {
            return None;
        }

        debug!(?response, "cached data");
        Some(Ok(response))
    }

    /// Query one zone pool, filter its response and cache it under the appropriate trust level.
    /// A required pool may return referrals only for NS discovery in referral mode.
    async fn lookup(
        &self,
        query: Query,
        zone: Name,
        ns: NameServerPool<P>,
        now: Instant,
    ) -> Result<Message, RecursorError> {
        let required = ns.requires_authentication();
        #[cfg(feature = "serde")]
        let cache = if required {
            &self.authenticated_response_cache
        } else {
            &self.response_cache
        };
        #[cfg(not(feature = "serde"))]
        let cache = &self.response_cache;
        let mut response = ns.lookup(query.clone(), self.request_options);

        #[cfg(feature = "metrics")]
        self.metrics.outgoing_query_counter.increment(1);

        // TODO: we are only expecting one response
        // TODO: should we change DnsHandle to always be a single response? And build a totally custom handler for other situations?
        let mut response = match response.next().await {
            Some(Ok(r)) => r,
            Some(Err(error)) => {
                warn!(?query, %error, "lookup error");
                if required
                    && !error.is_security_failure()
                    && !matches!(
                        &error,
                        crate::net::NetError::Dns(crate::net::DnsError::NoRecordsFound(
                            crate::net::NoRecords {
                                response_code: crate::proto::op::ResponseCode::NoError
                                    | crate::proto::op::ResponseCode::NXDomain,
                                ns: None,
                                ..
                            }
                        ))
                    )
                {
                    return Err(crate::net::NetError::SecurityPolicy(
                        format!("authenticated zone {zone}: {error}").into(),
                    )
                    .into());
                }
                cache.insert(query, Err(error.clone()), now);
                return Err(RecursorError::from(error));
            }
            None => {
                warn!("no response to lookup for {query}");
                return Err("no response to lookup".into());
            }
        };

        if required
            && !response.authoritative
            && !(self.authenticated_referrals() && query.query_type == RecordType::NS)
        {
            return Err(RecursorError::SecurityPolicy {
                name: zone,
                reason: "bound server returned a non-authoritative referral; configure an explicit child-zone binding",
            });
        }

        let answer_filter = |record: &Record| {
            #[cfg(feature = "serde")]
            if let Some((record_zone, _)) = self.configured_zone(&record.name) {
                // Inline records cannot claim authority belonging to another
                // binding, even for ANY/CNAME queries that do not chase aliases.
                if !required || record_zone != &zone {
                    return false;
                }
            }
            if !is_subzone(&zone, &record.name) {
                debug!(
                    %record, %zone,
                    "dropping out of bailiwick record",
                );
                return false;
            }

            true
        };

        let answers_len = response.answers.len();
        let authorities_len = response.authorities.len();

        response.additionals.retain(answer_filter);
        response.answers.retain(answer_filter);
        response.authorities.retain(answer_filter);

        // If we stripped all of the answers out, or if we stripped all of the authorities
        // out and there are no answers, return an NXDomain response.
        if response.answers.is_empty() && answers_len != 0
            || (response.answers.is_empty()
                && response.authorities.is_empty()
                && authorities_len != 0)
        {
            return Err(RecursorError::Negative(AuthorityData {
                query: Box::new(query),
                soa: None,
                no_records_found: false,
                nx_domain: true,
                authorities: None,
            }));
        }

        let message = response.into_message();
        cache.insert(query, Ok(message.clone()), now);
        Ok(message)
    }

    /// Identify the correct NameServerPool to use to answer queries for a given name.
    /// Local bindings select a pool directly. Otherwise, walk referrals from the
    /// roots; referral mode authenticates each pool and checks NS identities before
    /// adding it to the nameserver cache.
    #[async_recursion]
    pub(crate) async fn ns_pool_for_name(
        &self,
        query_name: Name,
        request_time: Instant,
        mut depth: u8,
    ) -> Result<(u8, NameServerPool<P>), RecursorError> {
        #[cfg(feature = "serde")]
        if let Some(pool) = self.configured_pool(&query_name)? {
            return Ok((depth, pool));
        }
        // Iterate through zones from TLD down to the query name (not including root)
        let num_labels = query_name.num_labels();
        trace!(num_labels, %query_name, "looking for zones");

        let mut nameserver_pool = self.roots.clone().with_zone(Name::root());

        for i in 1..=num_labels {
            let zone = query_name.trim_to(i as usize);
            if let Some(ns) = self.name_server_cache.lock().get_mut(&zone) {
                match ns.ttl_expired() {
                    true => debug!(?zone, "cached name server pool expired"),
                    false => {
                        debug!(?zone, "already have cached name server pool for zone");
                        nameserver_pool = ns.clone();
                        continue;
                    }
                }
            };

            trace!(depth, ?zone, "ns_pool_for_name: depth {depth} for {zone}");
            depth += 1;
            RecursorError::recursion_exceeded(self.ns_recursion_limit, depth, &zone)?;

            let parent_zone = zone.base_name();

            let query = Query::new(zone.clone(), RecordType::NS);

            // Query for nameserver records via the pool for the parent zone.
            let lookup_res = match self
                .response_cache_for_query(&query)
                .get(&query, request_time)
            {
                Some(Ok(response)) => {
                    debug!(?response, "cached data");
                    Ok(response)
                }
                Some(Err(e)) => Err(e.into()),
                None => {
                    self.lookup(query, parent_zone, nameserver_pool.clone(), request_time)
                        .await
                }
            };

            let response = match lookup_res {
                Ok(response) => response,
                Err(e) if e.is_security_failure() => return Err(e),
                // Short-circuit on NXDOMAIN, per RFC 8020.
                // RFC 9156 also describes a relaxed mode where RFC 8020 is not enforced.
                Err(e)
                    if e.is_nx_domain() && self.qname_minimization == QNameMinimization::Strict =>
                {
                    return Err(e);
                }
                // Short-circuit on timeouts. Requesting a longer name from the same pool would likely
                // encounter them again.
                Err(e) if e.is_timeout() => return Err(e),
                // The name `zone` is not a zone cut. Return the same pool of name servers again, but do
                // not cache it. If this was recursively called by `ns_pool_for_name()`, the outer call
                // will try again with one more label added to the iterative query name.
                Err(_) => {
                    trace!(?zone, "no zone cut at zone");
                    continue;
                }
            };

            let any_ns = response
                .all_sections()
                .any(|record| record.record_type() == RecordType::NS && record.name == zone);
            if !any_ns {
                // Not a zone cut, but there is a CNAME or other record at this name. Return the
                // same pool of name servers as above in the error case, to try again with a
                // longer name.
                trace!(?zone, "no zone cut at zone");
                continue;
            }

            // get all the NS records and glue
            let mut config_group = Vec::new();
            let mut need_ips_for_names = Vec::new();
            let mut glue_ips = HashMap::new();
            let (positive_min_ttl, positive_max_ttl) = self
                .ttl_config
                .positive_response_ttl_bounds(RecordType::NS)
                .into_inner();
            let mut ns_pool_ttl = u32::MAX;

            let ttl = self.add_glue_to_map(&mut glue_ips, response.all_sections());

            if ttl < ns_pool_ttl {
                ns_pool_ttl = ttl;
            }

            for zns in response.all_sections() {
                let RData::NS(ns_data) = &zns.data else {
                    continue;
                };

                if self.authenticated_referrals() && zns.name != zone {
                    continue;
                }
                if !is_subzone(&zone.base_name(), &zns.name) {
                    debug!(
                        name = ?zns.name,
                        parent = ?zone.base_name(),
                        "dropping out of bailiwick record",
                    );
                    continue;
                }

                if zns.ttl < ns_pool_ttl {
                    ns_pool_ttl = zns.ttl;
                }

                for record_type in [RecordType::A, RecordType::AAAA] {
                    let address_query = Query::new(ns_data.0.clone(), record_type);
                    if let Some(Ok(response)) = self
                        .response_cache_for_query(&address_query)
                        .get(&address_query, request_time)
                    {
                        let ttl = self.add_glue_to_map(&mut glue_ips, response.all_sections());
                        if ttl < ns_pool_ttl {
                            ns_pool_ttl = ttl;
                        }
                    }
                }

                match glue_ips.get(&ns_data.0) {
                    Some(glue) if !glue.is_empty() => {
                        for ip in glue.iter().copied() {
                            config_group.push(self.referral_server_config(&ns_data.0, ip)?);
                        }
                    }
                    _ => {
                        debug!(name_server = ?ns_data, "glue not found for name server");
                        need_ips_for_names.push(ns_data.to_owned());
                    }
                }
            }

            // If we have no glue, collect missing nameserver IP addresses.
            // For non-child name servers, get a new pool by calling ns_pool_for_name recursively.
            // For child child name servers, we can use the existing pool, but we *must* use lookup
            // to avoid infinite recursion.
            if config_group.is_empty() && !need_ips_for_names.is_empty() {
                debug!(?zone, "need glue for zone");

                let ttl;
                (ttl, depth) = self
                    .append_ips_from_lookup(
                        &zone,
                        depth,
                        request_time,
                        nameserver_pool.clone(),
                        need_ips_for_names.iter(),
                        &mut config_group,
                    )
                    .await?;

                if ttl < ns_pool_ttl {
                    ns_pool_ttl = ttl;
                }
            }

            let servers = config_group
                .iter()
                .map(|server| self.cached_name_server(server))
                .collect();

            let ns_pool_ttl =
                Duration::from_secs(ns_pool_ttl as u64).clamp(positive_min_ttl, positive_max_ttl);

            nameserver_pool = NameServerPool::from_nameservers(servers, self.pool_context.clone())
                .with_ttl(ns_pool_ttl)
                .with_zone(zone.clone());

            if self.authenticated_referrals() {
                if config_group.is_empty() {
                    return Err(RecursorError::SecurityPolicy {
                        name: zone.clone(),
                        reason: "referral has no usable authenticated nameserver addresses",
                    });
                }
                nameserver_pool = nameserver_pool.with_required_authentication();
            }

            // store in cache for future usage
            debug!(?zone, "found nameservers for {zone}");
            self.name_server_cache
                .lock()
                .insert(zone.clone(), nameserver_pool.clone());
        }

        #[cfg(feature = "metrics")]
        {
            self.metrics
                .name_server_cache_size
                .set(self.name_server_cache.lock().len() as f64);
            self.metrics
                .connection_cache_size
                .set(self.connection_cache.lock().len() as f64);
        }

        Ok((depth, nameserver_pool))
    }

    /// Helper function to add IP addresses from any A or AAAA records to a map indexed by record
    /// name.
    fn add_glue_to_map<'a>(
        &self,
        glue_map: &mut HashMap<Name, Vec<IpAddr>>,
        records: impl Iterator<Item = &'a Record>,
    ) -> u32 {
        let mut ttl = u32::MAX;

        for record in records {
            let ip = match &record.data {
                RData::A(A(ipv4)) => (*ipv4).into(),
                RData::AAAA(AAAA(ipv6)) => (*ipv6).into(),
                _ => continue,
            };
            if self.name_server_filter.denied(ip) {
                debug!(name = %record.name, %ip, "ignoring address due to do_not_query");
                continue;
            }
            if record.ttl < ttl {
                ttl = record.ttl;
            }
            let ns_glue_ips = match glue_map.get_mut(&record.name) {
                Some(ips) => ips,
                None => {
                    glue_map.insert(record.name.clone(), Vec::new());
                    glue_map.get_mut(&record.name).unwrap()
                }
            };
            if !ns_glue_ips.contains(&ip) {
                ns_glue_ips.push(ip);
            }
        }

        ttl
    }

    /// Resolve missing nameserver addresses while preserving the original transport requirement.
    /// Return the minimum address TTL and updated recursion depth for the resulting pool.
    async fn append_ips_from_lookup<'a, I: Iterator<Item = &'a NS>>(
        &self,
        zone: &Name,
        depth: u8,
        request_time: Instant,
        nameserver_pool: NameServerPool<P>,
        nameservers: I,
        config: &mut Vec<NameServerConfig>,
    ) -> Result<(u32, u8), RecursorError> {
        // Dependency lookups in this mode must use the same authenticated
        // recursion and CNAME handling as the original query, never an ordinary
        // cache or pool. In-bailiwick glueless cycles fail closed if the parent
        // cannot supply an address; recursion limits bound external cycles.
        if self.authenticated_referrals() {
            let mut ttl = u32::MAX;
            for ns in nameservers {
                for kind in [RecordType::A, RecordType::AAAA] {
                    let query = Query::new(ns.0.clone(), kind);
                    let result = if is_subzone(zone, &ns.0) {
                        self.lookup(
                            query,
                            zone.base_name(),
                            nameserver_pool.clone(),
                            request_time,
                        )
                        .await
                    } else {
                        self.resolve(
                            query,
                            request_time,
                            true,
                            depth + 1,
                            Arc::new(AtomicU8::new(0)),
                        )
                        .await
                    };
                    let message = match result {
                        Ok(message) => message,
                        Err(error) if error.is_no_records_found() || error.is_nx_domain() => {
                            continue;
                        }
                        // TODO: Try other authenticated NS candidates before
                        // aborting discovery. The availability benchmark found
                        // that this early return prevents glueless failover when
                        // one dependency fails but an approved backup is reachable.
                        Err(error) => return Err(error),
                    };
                    // resolve() follows and authenticates aliases. Only the
                    // terminal address RRset, not arbitrary extra answers, counts.
                    let mut terminal = ns.0.clone();
                    for _ in 0..MAX_CNAME_LOOKUPS {
                        match message.answers.iter().find_map(|record| {
                            if record.name != terminal {
                                return None;
                            }
                            if let CNAME(target) = &record.data {
                                Some(target.0.clone())
                            } else {
                                None
                            }
                        }) {
                            Some(target) => terminal = target,
                            None => break,
                        }
                    }
                    for answer in message
                        .answers
                        .iter()
                        .filter(|answer| answer.name == terminal && answer.record_type() == kind)
                    {
                        let Some(ip) = answer.data.ip_addr() else {
                            continue;
                        };
                        if self.name_server_filter.denied(ip) {
                            continue;
                        }
                        config.push(self.referral_server_config(&ns.0, ip)?);
                        ttl = ttl.min(answer.ttl);
                    }
                }
            }
            return Ok((ttl, depth));
        }
        let mut pool_queries = vec![];

        for ns in nameservers {
            let record_name = ns.0.clone();

            // For child nameservers of zone, we can reuse the pool that was passed in as
            // nameserver_pool, but for a non-child nameservers we need to get an appropriate pool.
            // To avoid incrementing the depth counter for each nameserver, we'll use the passed in
            // depth as a fixed base for the nameserver lookups
            let nameserver_pool = if !is_subzone(zone, &record_name) {
                match self
                    .ns_pool_for_name(record_name.clone(), request_time, depth)
                    .await
                {
                    Ok((_, pool)) => pool.with_zone(zone.clone()),
                    // The NS hostname could not be resolved. This doesn't mean the
                    // original queried domain doesn't exist, only that this nameserver
                    // is unreachable. Skip it and try others. If they all fail, the
                    // empty pool will result in SERVFAIL.
                    Err(error) if error.is_security_failure() => return Err(error),
                    Err(error) => {
                        debug!(?record_name, ?error, "nameserver hostname lookup failure");
                        continue;
                    }
                }
            } else {
                nameserver_pool.clone()
            };

            pool_queries.push((nameserver_pool, record_name));
        }

        let mut futures = FuturesUnordered::new();

        for (pool, query) in pool_queries.iter() {
            for rec_type in [RecordType::A, RecordType::AAAA] {
                let required = pool.requires_authentication();
                futures.push(Box::pin(
                    pool.lookup(Query::new(query.clone(), rec_type), self.request_options)
                        .into_future()
                        .map(move |(first, _rest)| (required, first)),
                ));
            }
        }

        let mut ttl = u32::MAX;

        while let Some((required, next)) = futures.next().await {
            match next {
                Some(Ok(response)) => {
                    debug!("append_ips_from_lookup: A or AAAA response: {response:?}");
                    config.extend(response.into_message()
                        .answers
                        .into_iter()
                        .filter_map(|answer| {
                            let ip = answer.data.ip_addr()?;

                            if self.name_server_filter.denied(ip) {
                                debug!(%ip, "append_ips_from_lookup: ignoring address due to do_not_query");
                                None
                            } else {
                                if answer.ttl < ttl {
                                    ttl = answer.ttl;
                                }
                                Some(ip)
                            }
                        }).map(|ip| self.name_server_config(ip)));
                }
                Some(Err(e)) => {
                    if e.is_security_failure() {
                        return Err(e.into());
                    }
                    if required && !e.is_no_records_found() {
                        return Err(crate::net::NetError::SecurityPolicy(
                            format!("authenticated nameserver address lookup: {e}").into(),
                        )
                        .into());
                    }
                    warn!("append_ips_from_lookup: resolution failed failed: {e}");
                }
                None => {
                    warn!("no response to lookup");
                }
            }
        }

        Ok((ttl, depth))
    }
}

#[cfg(feature = "__dnssec")]
mod for_dnssec {
    use futures_util::{
        future,
        stream::{self, BoxStream},
    };

    use super::*;
    use crate::{
        net::{DnsHandle, NetError},
        proto::op::{DnsRequest, DnsResponse, OpCode},
    };

    impl<P: ConnectionProvider> DnsHandle for RecursorDnsHandle<P> {
        type Response = BoxStream<'static, Result<DnsResponse, NetError>>;
        type Runtime = P::RuntimeProvider;

        fn send(&self, request: DnsRequest) -> Self::Response {
            let query = if let OpCode::Query = request.op_code {
                if let Some(query) = request.queries.first().cloned() {
                    query
                } else {
                    return Box::pin(stream::once(future::err(NetError::from(
                        "no query in request",
                    ))));
                }
            } else {
                return Box::pin(stream::once(future::err(NetError::from(
                    "request is not a query",
                ))));
            };

            let this = self.clone();
            stream::once(async move {
                // request the DNSSEC records; we'll strip them if not needed on the caller side
                let do_bit = true;

                let future =
                    this.resolve(query, Instant::now(), do_bit, 0, Arc::new(AtomicU8::new(0)));
                let response = match future.await {
                    Ok(response) => response,
                    Err(e) => return Err(NetError::from(e)),
                };

                // `DnssecDnsHandle` will only look at the answer section of the message so
                // we can put "stubs" in the other fields
                let mut msg = Message::query();

                msg.add_answers(response.answers.iter().cloned());
                msg.add_authorities(response.authorities.iter().cloned());
                msg.add_additionals(response.additionals.iter().cloned());

                DnsResponse::from_message(msg.into_response()).map_err(NetError::from)
            })
            .boxed()
        }
    }
}

fn recursor_opts(
    avoid_local_udp_ports: Arc<HashSet<u16>>,
    case_randomization: bool,
    edns_payload_len: u16,
    connect_timeout_ms: Option<u64>,
) -> ResolverOpts {
    let mut options = ResolverOpts {
        ndots: 0,
        edns0: true,
        #[cfg(feature = "__dnssec")]
        validate: false, // we'll need to do any dnssec validation differently in a recursor (top-down rather than bottom-up)
        preserve_intermediates: true,
        recursion_desired: false,
        num_concurrent_reqs: 1,
        avoid_local_udp_ports,
        case_randomization,
        edns_payload_len,
        ..ResolverOpts::default()
    };
    if let Some(milliseconds) = connect_timeout_ms {
        options.connect_timeout = Duration::from_millis(milliseconds);
    }
    options
}

/// Construct endpoint protocols without allowing a required policy to become a preference.
fn name_server_config(
    ip: IpAddr,
    opportunistic_encryption: &OpportunisticEncryption,
    #[cfg(all(feature = "serde", feature = "__tls"))] required: Option<
        &ForcedEncryptedAuthoritativeServerPolicy,
    >,
) -> NameServerConfig {
    #[cfg(all(feature = "serde", feature = "__tls"))]
    if let Some(required) = required {
        return match required.protocol {
            ForcedEncryptedAuthoritativeProtocol::Dot => {
                NameServerConfig::tls(ip, Arc::from(required.tls_name.as_str()))
            }
            #[cfg(feature = "__quic")]
            ForcedEncryptedAuthoritativeProtocol::Doq => {
                NameServerConfig::quic(ip, Arc::from(required.tls_name.as_str()))
            }
            #[cfg(not(feature = "__quic"))]
            ForcedEncryptedAuthoritativeProtocol::Doq => {
                unreachable!("required DoQ needs QUIC support, checked during startup validation")
            }
        };
    }
    match opportunistic_encryption {
        #[cfg(any(
            feature = "tls-aws-lc-rs",
            feature = "tls-ring",
            feature = "quic-aws-lc-rs",
            feature = "quic-ring"
        ))]
        OpportunisticEncryption::Enabled { .. } => NameServerConfig::opportunistic_encryption(ip),
        _ => NameServerConfig::udp_and_tcp(ip),
    }
}

/// Maximum number of cname records to look up in a CNAME chain, regardless of the recursion
/// depth limit
const MAX_CNAME_LOOKUPS: u8 = 64;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ipnet::IpNet;

    use crate::{
        net::runtime::TokioRuntimeProvider,
        recursor::{DnssecPolicy, Recursor, RecursorMode, RecursorOptions},
    };

    #[test]
    fn zero_connection_timeout_is_rejected_at_startup() {
        let options = RecursorOptions {
            connect_timeout_ms: Some(0),
            ..RecursorOptions::default()
        };
        match Recursor::new(
            &[IpAddr::from([192, 0, 2, 1])],
            DnssecPolicy::default(),
            None,
            options,
            TokioRuntimeProvider::default(),
        ) {
            Err(error) => assert!(error.to_string().contains("connect_timeout_ms")),
            Ok(_) => panic!("zero connection timeout was accepted"),
        }
    }

    #[test]
    fn test_nameserver_filter() {
        let options = RecursorOptions {
            allow_server: [IpNet::new(IpAddr::from([192, 168, 0, 1]), 32).unwrap()].to_vec(),
            deny_server: [
                IpNet::new(IpAddr::from(Ipv4Addr::LOCALHOST), 8).unwrap(),
                IpNet::new(IpAddr::from([192, 168, 0, 0]), 23).unwrap(),
                IpNet::new(IpAddr::from([172, 17, 0, 0]), 20).unwrap(),
            ]
            .to_vec(),
            ..RecursorOptions::default()
        };

        #[cfg_attr(not(feature = "__dnssec"), allow(irrefutable_let_patterns))]
        let Recursor {
            mode: RecursorMode::NonValidating { handle },
        } = Recursor::new(
            &[IpAddr::from([192, 0, 2, 1])],
            DnssecPolicy::default(),
            None,
            options,
            TokioRuntimeProvider::default(),
        )
        .unwrap()
        else {
            panic!("unexpected DNSSEC validation mode");
        };

        for addr in [
            [127, 0, 0, 0],
            [127, 0, 0, 1],
            [192, 168, 1, 0],
            [192, 168, 1, 254],
            [172, 17, 0, 1],
        ] {
            assert!(handle.name_server_filter.denied(IpAddr::from(addr)));
        }

        for addr in [[128, 0, 0, 0], [192, 168, 2, 0], [192, 168, 0, 1]] {
            assert!(!handle.name_server_filter.denied(IpAddr::from(addr)));
        }
    }
}
