use futures_util::StreamExt;
use bitvec::view::BitView;
use bitvec::prelude::Msb0;
use std::net::SocketAddr;
use tokio_util::codec::length_delimited::LengthDelimitedCodec;
use tokio::net::TcpListener;
use zettabgp::bmp::BmpMessage;
use zettabgp::bmp::prelude::BmpMessageRouteMonitoring;
use zettabgp::bmp::prelude::BmpMessagePeerHeader;
use crate::table::{Table, TableSelector, SessionId};
use log::*;

fn table_selector_for_peer(client_addr: SocketAddr, peer: &BmpMessagePeerHeader) -> Option<TableSelector> {
    match (peer.peertype, peer.flags.view_bits::<Msb0>()[7]) {
        (0, false) => Some(TableSelector::PrePolicyAdjIn(SessionId {
            from_client: client_addr,
            peer_address: peer.peeraddress,
        })),
        (0, true) => Some(TableSelector::PostPolicyAdjIn(SessionId {
            from_client: client_addr,
            peer_address: peer.peeraddress,
        })),
        (3, _) => Some(TableSelector::LocRib { from_client: client_addr }),
        _ => None,
    }
}

async fn process_route_monitoring(table: &impl Table, client_addr: SocketAddr, rm: BmpMessageRouteMonitoring) {
    let session = match table_selector_for_peer(client_addr, &rm.peer) {
        Some(session) => session,
        None => {
            trace!("unknown peer type {} flags {:x}", rm.peer.peertype, rm.peer.flags);
            return;
        }
    };

    table.insert_bgp_update(session, rm.update).await;
}

pub async fn run(table: impl Table) -> anyhow::Result<()> {
    let listener = TcpListener::bind("[::]:11019").await?;
    loop {
        let (io, client_addr) = listener.accept().await?;
        info!("connected {:?}", client_addr);

        let table = table.clone();
        tokio::spawn(async move {
            let mut read = LengthDelimitedCodec::builder()
                .length_field_offset(1)
                .length_field_type::<u32>()
                .num_skip(0)
                .new_read(io);
            let mut termination_msg = None;
            while let Some(msg) = read.next().await {
                let orig_msg = match msg {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("BMP Codec Error: {:?}", e);
                        continue;
                    }
                };
                let msg = match BmpMessage::decode_from(&orig_msg[5..]) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("BMP Parse Error: {:?}", e);
                        warn!("{:x?}", &orig_msg);
                        continue;
                    }
                };

                match msg {
                    BmpMessage::RouteMonitoring(rm) => {
                        process_route_monitoring(&table, client_addr, rm).await;
                    }
                    BmpMessage::PeerUpNotification(n) => {
                        trace!("{} {:?}", client_addr, n);
                    }
                    BmpMessage::PeerDownNotification(n) => {
                        trace!("{} {:?}", client_addr, n);
                        let session = match table_selector_for_peer(client_addr, &n.peer) {
                            Some(TableSelector::PrePolicyAdjIn(session)) => session,
                            _ => {
                                warn!("could not process peer down for peer type {} flags {:x}", n.peer.peertype, n.peer.flags);
                                continue;
                            }
                        };
                        table.clear_peer_table(session).await;
                    }
                    BmpMessage::Termination(n) => {
                        info!("disconnected {} {:?}", client_addr, n);
                        termination_msg = Some(n);
                        break;
                    }
                    msg => trace!("unknown message from {} {:#?}", client_addr, msg),
                }
            }
            info!("disconnected {} {:?}", client_addr, termination_msg);
            table.clear_router_table(client_addr).await;
        });

    }
}
