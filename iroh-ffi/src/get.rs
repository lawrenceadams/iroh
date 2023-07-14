use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use iroh_io::{AsyncSliceWriter, File};
use range_collections::RangeSet2;
use safer_ffi::prelude::*;

use iroh::{
    bytes::{
        get::fsm,
        protocol::{GetRequest, RangeSpecSeq, Request, RequestToken},
        Hash,
    },
    dial::Ticket,
    net::tls::PeerId,
};

use crate::{error::IrohError, node::IrohNode};

#[ffi_export]
/// @memberof iroh_node_t
// TODO(b5): optional token arg
fn iroh_get(
    node: &mut IrohNode,
    hash: char_p::Ref<'_>,
    peer: char_p::Ref<'_>,
    peer_addr: char_p::Ref<'_>,
    out_path: char_p::Ref<'_>,
    callback: extern "C" fn(Option<repr_c::Box<IrohError>>),
) {
    let node1 = node.inner().clone();
    let rt = node.async_runtime();
    let hash = hash.to_string();
    let peer = peer.to_string();
    let peer_addr = peer_addr.to_string();
    let out_path = PathBuf::from(out_path.to_string());

    node.async_runtime().clone().spawn(async move {
        let result = async move {
            let hash = hash.parse::<Hash>()?;
            let peer = peer.parse::<PeerId>()?;
            let peer_addr = peer_addr.parse()?;
            let conn = node1
                .dial(&iroh::bytes::protocol::ALPN, peer, &vec![peer_addr])
                .await?;
            get_blob_to_file(conn, hash, None, out_path).await
        }
        .await;

        match result {
            Ok(()) => rt.spawn_blocking(move || callback(None)),
            Err(error) => rt.spawn_blocking(move || callback(Some(IrohError::new(error).into()))),
        };
    });
}

#[ffi_export]
/// @memberof iroh_node_t
/// Get a collection from a peer.
pub fn iroh_get_ticket(
    node: &mut IrohNode,
    ticket: char_p::Ref<'_>,
    out_path: char_p::Ref<'_>,
    callback: extern "C" fn(Option<repr_c::Box<IrohError>>),
) {
    let ticket = ticket.to_string();
    let out_path = PathBuf::from(out_path.to_string());

    let rt = node.async_runtime();
    node.async_runtime().spawn(async move {
        let result = async {
            let ticket = Ticket::from_str(ticket.as_str())?;
            // TODO(b5): use the node endpoint(s) to dial
            let conn = node
                .inner()
                .clone()
                .dial(
                    &iroh::bytes::protocol::ALPN,
                    ticket.peer(),
                    &ticket.addrs().to_vec(),
                )
                .await?;
            get_blob_to_file(conn, ticket.hash(), ticket.token().cloned(), out_path).await
        }
        .await;

        match result {
            Ok(()) => rt.spawn_blocking(move || callback(None)),
            Err(error) => rt.spawn_blocking(move || callback(Some(IrohError::new(error).into()))),
        };
    });
}

async fn get_blob_to_file(
    conn: quinn::Connection,
    hash: Hash,
    token: Option<RequestToken>,
    out_path: PathBuf,
) -> Result<()> {
    get_blob_ranges_to_file(
        conn,
        hash,
        token,
        RangeSpecSeq::new([RangeSet2::all()]),
        out_path,
    )
    .await
}

// TODO(b5): This currently assumes "all" ranges, needs to be adjusted to honor
// RangeSpecSeq args other than "all"
async fn get_blob_ranges_to_file(
    conn: quinn::Connection,
    hash: Hash,
    token: Option<RequestToken>,
    ranges: RangeSpecSeq,
    out_path: PathBuf,
) -> Result<()> {
    let request = Request::Get(GetRequest::new(hash, ranges)).with_token(token);
    let response = fsm::start(conn, request);
    let connected = response.next().await?;

    let fsm::ConnectedNext::StartRoot(curr) = connected.next().await? else {
                return Ok(())
            };
    let header = curr.next();

    let path = out_path.clone();
    let mut file = File::create(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&path)
    })
    .await?;

    let (curr, _size) = header.next().await?;
    let _curr = curr.write_all(&mut file).await?;
    file.sync().await?;
    Ok(())
}
