use async_trait::async_trait;
use futures_util::Stream;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use log::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;

use crate::route_distinguisher::RouteDistinguisher;

pub type PathId = u32;
pub type RouterId = Ipv4Addr;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub enum RouteOrigin {
    Igp,
    Egp,
    Incomplete,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RouteAttrs {
    pub origin: Option<RouteOrigin>,
    pub as_path: Option<Vec<u32>>,
    pub communities: Option<Vec<(u16, u16)>>,
    pub large_communities: Option<Vec<(u32, u32, u32)>>,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub nexthop: Option<IpAddr>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionId {
    pub from_client: SocketAddr,
    pub peer_address: IpAddr,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum RouteState {
    /// The route has been received from a neighbor, but was rejected in a filter
    Seen,
    /// The route has been received from a neighbor and was accepted in the filters
    Accepted,
    /// e.g. equal cost multipath routes
    Active,
    /// This means this is the preferred route, and this route is propagated to BGP neighbors
    Selected,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TableType {
    PrePolicyAdjIn,
    PostPolicyAdjIn,
    LocRib {
        #[serde(skip_serializing)]
        route_state: RouteState,
    },
}

impl Serialize for TableType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let table_type = match self {
            TableType::PrePolicyAdjIn => "PrePolicyAdjIn",
            TableType::PostPolicyAdjIn => "PostPolicyAdjIn",
            TableType::LocRib { .. } => "LocRib",
        };

        serializer.serialize_str(table_type)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableSelector {
    // None equal default Routing Instance
    #[serde(skip_serializing_if = "RouteDistinguisher::is_default")]
    pub route_distinguisher: RouteDistinguisher,
    pub session_id: SessionId,
    #[serde(rename = "type")]
    pub table_type: TableType,
}

impl TableSelector {
    pub fn client_addr(&self) -> &SocketAddr {
        &self.session_id.from_client
    }
    pub fn session_id(&self) -> Option<&SessionId> {
        match self.table_type {
            TableType::LocRib { .. } => None,
            _ => Some(&self.session_id),
        }
    }
    pub fn route_state(&self) -> RouteState {
        match self.table_type {
            TableType::LocRib { route_state, .. } => route_state,
            TableType::PostPolicyAdjIn => RouteState::Accepted,
            TableType::PrePolicyAdjIn => RouteState::Seen,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TableQuery {
    Table(TableSelector),
    Session(SessionId),
    Client(SocketAddr),
    Router(RouterId),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NetQuery<T = IpNet> {
    Contains(T),
    MostSpecific(T),
    Exact(T),
    OrLonger(T),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query<T = IpNet> {
    #[serde(flatten)]
    pub table_query: Option<TableQuery>,
    #[serde(flatten)]
    pub net_query: NetQuery<T>,
    pub limits: Option<QueryLimits>,
    #[serde(default)]
    pub as_path_regex: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryResult {
    pub state: RouteState,
    pub net: IpNet,
    #[serde(flatten)]
    pub table: TableSelector,
    #[serde(flatten)]
    pub client: Client,
    #[serde(flatten)]
    pub session: Option<Session>,
    #[serde(flatten)]
    pub attrs: RouteAttrs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLimits {
    pub max_results_per_table: usize,
    pub max_results: usize,
}

/// information saved about a connected router
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_name: String,
    pub router_id: RouterId, // Router ID used for LocRib
}

/// information saved about a connected peer
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Session {}

impl Default for QueryLimits {
    fn default() -> Self {
        Self {
            max_results_per_table: 200,
            max_results: 500,
        }
    }
}

#[async_trait]
pub trait Store: Clone + Send + Sync + 'static {
    async fn update_route(
        &self,
        path_id: PathId,
        net: IpNet,
        table: TableSelector,
        attrs: RouteAttrs,
    );

    async fn withdraw_route(&self, path_id: PathId, net: IpNet, table: TableSelector);

    fn get_routes(&self, query: Query) -> Pin<Box<dyn Stream<Item = QueryResult> + Send>>;

    fn get_routers(&self) -> HashMap<SocketAddr, Client>;

    async fn client_up(
        &self,
        client_addr: SocketAddr,
        route_state: RouteState,
        client_data: Client,
    );

    async fn client_down(&self, client_addr: SocketAddr);

    async fn session_up(&self, session: SessionId, session_data: Session);

    async fn session_down(&self, session: SessionId, new_state: Option<Session>);

    async fn insert_bgp_update(
        &self,
        session: TableSelector,
        update: zettabgp::prelude::BgpUpdateMessage,
    ) {
        use zettabgp::prelude::*;
        let mut attrs: RouteAttrs = Default::default();
        let mut nexthop = None;
        let mut update_nets = vec![];
        let mut withdraw_nets = vec![];
        for attr in update.attrs {
            match attr {
                BgpAttrItem::MPUpdates(updates) => {
                    let nexthop = match updates.nexthop {
                        BgpAddr::V4(v4) => Some(IpAddr::from(v4)),
                        BgpAddr::V6(v6) => Some(IpAddr::from(v6)),
                        _ => None,
                    };
                    for net in bgp_addrs_to_nets(&updates.addrs) {
                        update_nets.push((net, nexthop));
                    }
                }
                BgpAttrItem::MPWithdraws(withdraws) => {
                    for net in bgp_addrs_to_nets(&withdraws.addrs) {
                        withdraw_nets.push(net);
                    }
                }
                BgpAttrItem::NextHop(BgpNextHop { value }) => {
                    nexthop = Some(value);
                }
                BgpAttrItem::CommunityList(BgpCommunityList { value }) => {
                    let mut communities = vec![];
                    for community in value.into_iter() {
                        communities.push((
                            (community.value >> 16) as u16,
                            (community.value & 0xffff) as u16,
                        ));
                    }
                    attrs.communities = Some(communities);
                }
                BgpAttrItem::MED(BgpMED { value }) => {
                    attrs.med = Some(value);
                }
                BgpAttrItem::LocalPref(BgpLocalpref { value }) => {
                    attrs.local_pref = Some(value);
                }
                BgpAttrItem::Origin(BgpOrigin { value }) => {
                    attrs.origin = Some(match value {
                        BgpAttrOrigin::Igp => RouteOrigin::Igp,
                        BgpAttrOrigin::Egp => RouteOrigin::Egp,
                        BgpAttrOrigin::Incomplete => RouteOrigin::Incomplete,
                    })
                }
                BgpAttrItem::ASPath(BgpASpath { value }) => {
                    let mut as_path = vec![];
                    for asn in value {
                        as_path.push(asn.value);
                    }
                    attrs.as_path = Some(as_path);
                }
                BgpAttrItem::LargeCommunityList(BgpLargeCommunityList { value }) => {
                    let mut communities = vec![];
                    for community in value.into_iter() {
                        communities.push((community.ga, community.ldp1, community.ldp2));
                    }
                    attrs.large_communities = Some(communities);
                }
                _ => {}
            }
        }
        for net in bgp_addrs_to_nets(&update.updates).into_iter() {
            update_nets.push((net, nexthop));
        }
        for net in bgp_addrs_to_nets(&update.withdraws).into_iter() {
            withdraw_nets.push(net);
        }

        for ((mut rd, path, prefix), nexthop) in update_nets {
            if rd.is_default() {
                rd = session.route_distinguisher
            }
            let mut attrs = attrs.clone();
            attrs.nexthop = nexthop;
            self.update_route(
                path,
                prefix,
                TableSelector {
                    route_distinguisher: rd,
                    ..session.clone()
                },
                attrs,
            )
            .await;
        }
        for (mut rd, path, prefix) in withdraw_nets {
            if rd.is_default() {
                rd = session.route_distinguisher
            }
            self.withdraw_route(
                path,
                prefix,
                TableSelector {
                    route_distinguisher: rd,
                    ..session.clone()
                },
            )
            .await;
        }
    }
}

fn bgp_addrs_to_nets(
    addrs: &zettabgp::prelude::BgpAddrs,
) -> Vec<(RouteDistinguisher, PathId, IpNet)> {
    use zettabgp::prelude::*;
    match addrs {
        BgpAddrs::IPV4UP(ref addrs) => addrs
            .iter()
            .filter_map(|addr| {
                let WithPathId { pathid, nlri } = addr;
                match Ipv4Net::new(nlri.addr, nlri.prefixlen) {
                    Ok(net) => Some((RouteDistinguisher::Default, *pathid, IpNet::V4(net))),
                    Err(_) => {
                        warn!("invalid BgpAddrs prefixlen");
                        None
                    }
                }
            })
            .collect(),
        BgpAddrs::IPV6UP(ref addrs) => addrs
            .iter()
            .filter_map(|addr| {
                let WithPathId { pathid, nlri } = addr;
                match Ipv6Net::new(nlri.addr, nlri.prefixlen) {
                    Ok(net) => Some((RouteDistinguisher::Default, *pathid, IpNet::V6(net))),
                    Err(_) => {
                        warn!("invalid BgpAddrs prefixlen");
                        None
                    }
                }
            })
            .collect(),
        BgpAddrs::IPV4U(ref addrs) => addrs
            .iter()
            .filter_map(|addr| match Ipv4Net::new(addr.addr, addr.prefixlen) {
                Ok(net) => Some((RouteDistinguisher::Default, 0, IpNet::V4(net))),
                Err(_) => {
                    warn!("invalid BgpAddrs prefixlen");
                    None
                }
            })
            .collect(),
        BgpAddrs::IPV6U(ref addrs) => addrs
            .iter()
            .filter_map(|addr| match Ipv6Net::new(addr.addr, addr.prefixlen) {
                Ok(net) => Some((RouteDistinguisher::Default, 0, IpNet::V6(net))),
                Err(_) => {
                    warn!("invalid BgpAddrs prefixlen");
                    None
                }
            })
            .collect(),
        _ => vec![],
    }
}
