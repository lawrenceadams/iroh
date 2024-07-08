use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU64,
    ops::ControlFlow,
};

use bytes::Bytes;
use futures_lite::StreamExt;
use iroh_blobs::store::Store as PayloadStore;
use tracing::{debug, trace};

use crate::{
    proto::{
        grouping::{Area, ThreeDRange},
        keys::NamespaceId,
        sync::{
            AreaOfInterestHandle, Fingerprint, LengthyEntry, ReconciliationAnnounceEntries,
            ReconciliationMessage, ReconciliationSendEntry, ReconciliationSendFingerprint,
            ReconciliationSendPayload, ReconciliationTerminatePayload,
        },
        willow::PayloadDigest,
    },
    session::{
        aoi_finder::{AoiIntersection, AoiIntersectionQueue},
        channels::{ChannelSenders, MessageReceiver},
        events::{Event, EventEmitter},
        payload::{send_payload_chunked, CurrentPayload},
        static_tokens::StaticTokens,
        Error, Role, SessionId,
    },
    store::{
        traits::{EntryReader, EntryStorage, SplitAction, SplitOpts, Storage},
        Origin, Store,
    },
    util::stream::Cancelable,
};

#[derive(derive_more::Debug)]
pub struct Reconciler<S: Storage> {
    shared: Shared<S>,
    recv: Cancelable<MessageReceiver<ReconciliationMessage>>,
    events: EventEmitter,
    targets: TargetMap<S>,
    current_entry: CurrentEntry,
}

type TargetId = (AreaOfInterestHandle, AreaOfInterestHandle);

impl<S: Storage> Reconciler<S> {
    pub fn new(
        store: Store<S>,
        recv: Cancelable<MessageReceiver<ReconciliationMessage>>,
        aoi_intersection_queue: AoiIntersectionQueue,
        static_tokens: StaticTokens,
        session_id: SessionId,
        send: ChannelSenders,
        our_role: Role,
        events: EventEmitter,
    ) -> Result<Self, Error> {
        let shared = Shared {
            store,
            our_role,
            send,
            static_tokens,
            session_id,
        };
        Ok(Self {
            shared,
            recv,
            targets: TargetMap::new(aoi_intersection_queue),
            current_entry: Default::default(),

            events,
        })
    }

    pub async fn run(mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                message = self.recv.try_next() => {
                    match message? {
                        None => break,
                        Some(message) => match self.received_message(message).await? {
                            ControlFlow::Continue(_) => {}
                            ControlFlow::Break(_) => {
                                debug!("reconciliation complete");
                                break;
                            }
                        }
                    }
                }
                Ok(intersection) = self.targets.aoi_intersection_queue.recv_async() => {
                    let intersection = intersection;
                    let area = intersection.intersection.clone();
                    self.targets.init_target(&self.shared, intersection).await?;
                    self.events.send(Event::AreaIntersection(area)).await?;
                }
            }
        }
        Ok(())
    }

    async fn received_message(
        &mut self,
        message: ReconciliationMessage,
    ) -> Result<ControlFlow<(), ()>, Error> {
        match message {
            ReconciliationMessage::SendFingerprint(message) => {
                self.targets
                    .get_eventually(&self.shared, &message.handles())
                    .await?
                    .received_send_fingerprint(&self.shared, message)
                    .await?;
            }
            ReconciliationMessage::AnnounceEntries(message) => {
                let target_id = message.handles();
                self.current_entry
                    .received_announce_entries(target_id, message.count)?;
                let target = self
                    .targets
                    .get_eventually(&self.shared, &target_id)
                    .await?;
                target
                    .received_announce_entries(&self.shared, message)
                    .await?;
                if target.is_complete() && self.current_entry.is_none() {
                    return self.complete_target(target_id).await;
                }
            }
            ReconciliationMessage::SendEntry(message) => {
                let authorised_entry = self
                    .shared
                    .static_tokens
                    .authorise_entry_eventually(
                        message.entry.entry,
                        message.static_token_handle,
                        message.dynamic_token,
                    )
                    .await?;
                self.current_entry.received_entry(
                    authorised_entry.entry().payload_digest,
                    message.entry.available,
                )?;
                self.shared
                    .store
                    .entries()
                    .ingest(&authorised_entry, Origin::Remote(self.shared.session_id))?;
            }
            ReconciliationMessage::SendPayload(message) => {
                self.current_entry
                    .received_send_payload(self.shared.store.payloads(), message.bytes)
                    .await?;
            }
            ReconciliationMessage::TerminatePayload(_message) => {
                if let Some(completed_target) =
                    self.current_entry.received_terminate_payload().await?
                {
                    let target = self
                        .targets
                        .map
                        .get(&completed_target)
                        .expect("target to exist");
                    if target.is_complete() {
                        return self.complete_target(target.id()).await;
                    }
                }
            }
        };
        Ok(ControlFlow::Continue(()))
    }

    pub async fn complete_target(&mut self, id: TargetId) -> Result<ControlFlow<(), ()>, Error> {
        let target = self
            .targets
            .map
            .remove(&id)
            .ok_or(Error::InvalidMessageInCurrentState)?;
        let event = Event::Reconciled(target.area);
        self.events.send(event).await?;
        if self.targets.map.is_empty() {
            Ok(ControlFlow::Break(()))
        } else {
            Ok(ControlFlow::Continue(()))
        }
    }
}

#[derive(Debug)]
struct TargetMap<S: Storage> {
    map: HashMap<TargetId, Target<S>>,
    aoi_intersection_queue: AoiIntersectionQueue,
}

impl<S: Storage> TargetMap<S> {
    pub fn new(aoi_intersection_queue: AoiIntersectionQueue) -> Self {
        Self {
            map: Default::default(),
            aoi_intersection_queue,
        }
    }
    pub async fn get_eventually(
        &mut self,
        shared: &Shared<S>,
        requested_id: &TargetId,
    ) -> Result<&mut Target<S>, Error> {
        tracing::info!("aoi wait: {requested_id:?}");
        if !self.map.contains_key(requested_id) {
            self.wait_for_target(shared, requested_id).await?;
        }
        return Ok(self.map.get_mut(requested_id).unwrap());
    }

    async fn wait_for_target(
        &mut self,
        shared: &Shared<S>,
        requested_id: &TargetId,
    ) -> Result<(), Error> {
        loop {
            let intersection = self
                .aoi_intersection_queue
                .recv_async()
                .await
                .map_err(|_| Error::InvalidState("aoi finder closed"))?;
            let id = self.init_target(shared, intersection).await?;
            if id == *requested_id {
                break Ok(());
            }
        }
    }

    async fn init_target(
        &mut self,
        shared: &Shared<S>,
        intersection: AoiIntersection,
    ) -> Result<TargetId, Error> {
        let snapshot = shared.store.entries().snapshot()?;
        let target = Target::init(snapshot, shared, intersection).await?;
        let id = target.id();
        tracing::info!("init {id:?}");
        self.map.insert(id, target);
        Ok(id)
    }
}

#[derive(Debug, Default)]
struct CurrentEntry(Option<EntryState>);

impl CurrentEntry {
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub fn received_announce_entries(
        &mut self,
        target: TargetId,
        count: u64,
    ) -> Result<Option<TargetId>, Error> {
        if self.0.is_some() {
            return Err(Error::InvalidMessageInCurrentState);
        }
        if let Some(count) = NonZeroU64::new(count) {
            self.0 = Some(EntryState {
                target,
                remaining: Some(count),
                payload: CurrentPayload::default(),
            });
            Ok(None)
        } else {
            Ok(Some(target))
        }
    }

    pub fn received_entry(
        &mut self,
        payload_digest: PayloadDigest,
        expected_length: u64,
    ) -> Result<(), Error> {
        let state = self.get_mut()?;
        state.payload.ensure_none()?;
        state.remaining = match state.remaining.take() {
            None => return Err(Error::InvalidMessageInCurrentState),
            Some(c) => NonZeroU64::new(c.get().saturating_sub(1)),
        };
        state.payload.set(payload_digest, expected_length)?;
        Ok(())
    }

    pub async fn received_send_payload<P: PayloadStore>(
        &mut self,
        store: &P,
        bytes: Bytes,
    ) -> Result<(), Error> {
        self.get_mut()?.payload.recv_chunk(store, bytes).await?;
        Ok(())
    }

    pub async fn received_terminate_payload(&mut self) -> Result<Option<TargetId>, Error> {
        let s = self.get_mut()?;
        s.payload.finalize().await?;
        if s.remaining.is_none() {
            let target_id = s.target;
            self.0 = None;
            Ok(Some(target_id))
        } else {
            Ok(None)
        }
    }

    pub fn get_mut(&mut self) -> Result<&mut EntryState, Error> {
        match self.0.as_mut() {
            Some(s) => Ok(s),
            None => Err(Error::InvalidMessageInCurrentState),
        }
    }
}

#[derive(Debug)]
struct EntryState {
    target: TargetId,
    remaining: Option<NonZeroU64>,
    payload: CurrentPayload,
}

#[derive(Debug)]
struct Shared<S: Storage> {
    store: Store<S>,
    our_role: Role,
    send: ChannelSenders,
    static_tokens: StaticTokens,
    session_id: SessionId,
}

#[derive(Debug)]
struct Target<S: Storage> {
    snapshot: <S::Entries as EntryStorage>::Snapshot,

    our_handle: AreaOfInterestHandle,
    their_handle: AreaOfInterestHandle,
    namespace: NamespaceId,
    area: Area,

    our_uncovered_ranges: HashSet<u64>,
    started: bool,

    our_range_counter: u64,
    their_range_counter: u64,
}

impl<S: Storage> Target<S> {
    fn id(&self) -> TargetId {
        (self.our_handle, self.their_handle)
    }
    async fn init(
        snapshot: <S::Entries as EntryStorage>::Snapshot,
        shared: &Shared<S>,
        intersection: AoiIntersection,
    ) -> Result<Self, Error> {
        let mut this = Target {
            snapshot,
            our_handle: intersection.our_handle,
            their_handle: intersection.their_handle,
            namespace: intersection.namespace,
            area: intersection.intersection,
            our_uncovered_ranges: Default::default(),
            started: false,
            our_range_counter: 0,
            their_range_counter: 0,
        };
        if shared.our_role == Role::Alfie {
            this.initiate(shared).await?;
        }
        Ok(this)
    }

    async fn initiate(&mut self, shared: &Shared<S>) -> Result<(), Error> {
        let range = self.area.into_range();
        let fingerprint = self.snapshot.fingerprint(self.namespace, &range)?;
        self.send_fingerprint(shared, range, fingerprint, None)
            .await?;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.started && self.our_uncovered_ranges.is_empty()
    }

    async fn received_send_fingerprint(
        &mut self,
        shared: &Shared<S>,
        message: ReconciliationSendFingerprint,
    ) -> Result<(), Error> {
        if let Some(range_count) = message.covers {
            self.mark_our_range_covered(range_count)?;
        }
        let range_count = self.next_range_count_theirs();

        let our_fingerprint = self.snapshot.fingerprint(self.namespace, &message.range)?;

        // case 1: fingerprint match.
        if our_fingerprint == message.fingerprint {
            let reply = ReconciliationAnnounceEntries {
                range: message.range.clone(),
                count: 0,
                want_response: false,
                will_sort: false,
                sender_handle: message.receiver_handle,
                receiver_handle: message.sender_handle,
                covers: Some(range_count),
            };
            shared.send.send(reply).await?;
        }
        // case 2: fingerprint is empty
        else if message.fingerprint.is_empty() {
            self.announce_and_send_entries(shared, &message.range, true, Some(range_count), None)
                .await?;
        }
        // case 3: fingerprint doesn't match and is non-empty
        else {
            // reply by splitting the range into parts unless it is very short
            // TODO: Expose
            let split_opts = SplitOpts::default();
            let snapshot = self.snapshot.clone();
            let mut iter = snapshot
                .split_range(self.namespace, &message.range, &split_opts)?
                .peekable();
            while let Some(res) = iter.next() {
                let (subrange, action) = res?;
                let is_last = iter.peek().is_none();
                let covers = is_last.then_some(range_count);
                match action {
                    SplitAction::SendEntries(count) => {
                        self.announce_and_send_entries(
                            shared,
                            &subrange,
                            true,
                            covers,
                            Some(count),
                        )
                        .await?;
                    }
                    SplitAction::SendFingerprint(fingerprint) => {
                        self.send_fingerprint(shared, subrange, fingerprint, covers)
                            .await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn received_announce_entries(
        &mut self,
        shared: &Shared<S>,
        message: ReconciliationAnnounceEntries,
    ) -> Result<(), Error> {
        if let Some(range_count) = message.covers {
            self.mark_our_range_covered(range_count)?;
        }

        if message.want_response {
            let range_count = self.next_range_count_theirs();
            self.announce_and_send_entries(shared, &message.range, false, Some(range_count), None)
                .await?;
        }
        trace!("received_announce_entries done");
        Ok(())
    }

    async fn send_fingerprint(
        &mut self,
        shared: &Shared<S>,
        range: ThreeDRange,
        fingerprint: Fingerprint,
        covers: Option<u64>,
    ) -> anyhow::Result<()> {
        self.mark_our_next_range_pending();
        let msg = ReconciliationSendFingerprint {
            range,
            fingerprint,
            sender_handle: self.our_handle,
            receiver_handle: self.their_handle,
            covers,
        };
        shared.send.send(msg).await?;
        Ok(())
    }

    async fn announce_and_send_entries(
        &mut self,
        shared: &Shared<S>,
        range: &ThreeDRange,
        want_response: bool,
        covers: Option<u64>,
        our_entry_count: Option<u64>,
    ) -> Result<(), Error> {
        let our_entry_count = match our_entry_count {
            Some(count) => count,
            None => self.snapshot.count(self.namespace, range)?,
        };
        let msg = ReconciliationAnnounceEntries {
            range: range.clone(),
            count: our_entry_count,
            want_response,
            will_sort: false, // todo: sorted?
            sender_handle: self.our_handle,
            receiver_handle: self.their_handle,
            covers,
        };
        if want_response {
            self.mark_our_next_range_pending();
        }
        shared.send.send(msg).await?;

        for authorised_entry in self
            .snapshot
            .get_entries_with_authorisation(self.namespace, range)
        {
            let authorised_entry = authorised_entry?;
            let (entry, token) = authorised_entry.into_parts();
            let (static_token, dynamic_token) = token.into_parts();
            // TODO: partial payloads
            let available = entry.payload_length;
            let static_token_handle = shared
                .static_tokens
                .bind_and_send_ours(static_token, &shared.send)
                .await?;
            let digest = entry.payload_digest;
            let msg = ReconciliationSendEntry {
                entry: LengthyEntry::new(entry, available),
                static_token_handle,
                dynamic_token,
            };
            shared.send.send(msg).await?;

            // TODO: only send payload if configured to do so and/or under size limit.
            let send_payloads = true;
            let chunk_size = 1024 * 64;
            if send_payloads
                && send_payload_chunked(
                    digest,
                    shared.store.payloads(),
                    &shared.send,
                    chunk_size,
                    |bytes| ReconciliationSendPayload { bytes }.into(),
                )
                .await?
            {
                let msg = ReconciliationTerminatePayload;
                shared.send.send(msg).await?;
            }
        }
        Ok(())
    }

    fn mark_our_next_range_pending(&mut self) {
        let range_count = self.next_range_count_ours();
        self.started = true;
        self.our_uncovered_ranges.insert(range_count);
    }

    fn mark_our_range_covered(&mut self, range_count: u64) -> Result<(), Error> {
        if !self.our_uncovered_ranges.remove(&range_count) {
            Err(Error::InvalidState(
                "attempted to mark an unknown range as covered",
            ))
        } else {
            Ok(())
        }
    }

    fn next_range_count_ours(&mut self) -> u64 {
        let range_count = self.our_range_counter;
        self.our_range_counter += 1;
        range_count
    }

    fn next_range_count_theirs(&mut self) -> u64 {
        let range_count = self.their_range_counter;
        self.their_range_counter += 1;
        range_count
    }
}
