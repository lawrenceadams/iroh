use std::{
    collections::{hash_map, BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::CapSelector,
    proto::{grouping::AreaOfInterest, sync::ReadAuthorisation},
    session::{
        error::ChannelReceiverDropped,
        intents::{EventKind, Intent},
    },
};

mod aoi_finder;
mod capabilities;
pub mod channels;
mod data;
pub mod error;
pub mod intents;
mod pai_finder;
mod payload;
mod reconciler;
mod resource;
mod run;
mod static_tokens;

pub use self::channels::Channels;
pub use self::error::Error;
pub use self::run::run_session;

pub type SessionId = u64;

/// To break symmetry, we refer to the peer that initiated the synchronisation session as Alfie,
/// and the other peer as Betty.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Role {
    /// The peer that initiated the synchronisation session.
    Alfie,
    /// The peer that accepted the synchronisation session.
    Betty,
}

impl Role {
    /// Returns `true` if we initiated the session.
    pub fn is_alfie(&self) -> bool {
        matches!(self, Role::Alfie)
    }
    /// Returns `true` if we accepted the session.
    pub fn is_betty(&self) -> bool {
        matches!(self, Role::Betty)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionMode {
    /// Run a single, full reconciliation, and then quit.
    ReconcileOnce,
    /// Run reconciliations and data mode, until intentionally closed.
    Live,
}

impl SessionMode {
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }
}

#[derive(Debug, Default, Clone)]
pub enum Interests {
    #[default]
    All,
    Select(HashMap<CapSelector, AreaOfInterestSelector>),
    Exact(HashMap<ReadAuthorisation, HashSet<AreaOfInterest>>),
}

impl Interests {
    pub fn select() -> SelectBuilder {
        SelectBuilder::default()
    }
}

#[derive(Default, Debug)]
pub struct SelectBuilder(HashMap<CapSelector, AreaOfInterestSelector>);

impl SelectBuilder {
    pub fn add_full(mut self, cap: impl Into<CapSelector>) -> Self {
        let cap = cap.into();
        self.0.insert(cap, AreaOfInterestSelector::Widest);
        self
    }

    pub fn area(
        mut self,
        cap: impl Into<CapSelector>,
        aois: impl IntoIterator<Item = impl Into<AreaOfInterest>>,
    ) -> Self {
        let cap = cap.into();
        let aois = aois.into_iter();
        let aois = aois.map(|aoi| aoi.into());
        match self.0.entry(cap) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(AreaOfInterestSelector::Exact(aois.collect()));
            }
            hash_map::Entry::Occupied(mut entry) => match entry.get_mut() {
                AreaOfInterestSelector::Widest => {}
                AreaOfInterestSelector::Exact(existing) => existing.extend(aois),
            },
        }
        self
    }

    pub fn build(self) -> Interests {
        Interests::Select(self.0)
    }
}

impl From<SelectBuilder> for Interests {
    fn from(builder: SelectBuilder) -> Self {
        builder.build()
    }
}

#[derive(Debug)]
pub enum SessionUpdate {
    SubmitIntent(Intent),
}

#[derive(Debug, Default, Clone)]
pub enum AreaOfInterestSelector {
    #[default]
    Widest,
    Exact(BTreeSet<AreaOfInterest>),
}

/// Options to initialize a session with.
#[derive(Debug)]
pub struct SessionInit {
    /// List of interests we wish to synchronize, together with our capabilities to read them.
    pub interests: Interests,
    pub mode: SessionMode,
}

impl SessionInit {
    pub fn new(interests: impl Into<Interests>, mode: SessionMode) -> Self {
        let interests = interests.into();
        Self { interests, mode }
    }
}

/// The bind scope for resources.
///
/// Resources are bound by either peer
#[derive(Copy, Clone, Debug)]
pub enum Scope {
    /// Resources bound by ourselves.
    Ours,
    /// Resources bound by the other peer.
    Theirs,
}

#[derive(Debug, Clone)]
pub struct EventSender(pub mpsc::Sender<SessionEvent>);

impl EventSender {
    pub async fn send(&self, event: SessionEvent) -> Result<(), ChannelReceiverDropped> {
        self.0.send(event).await.map_err(|_| ChannelReceiverDropped)
    }
}

#[derive(Debug)]
pub enum SessionEvent {
    Established,
    Complete { result: Result<(), Arc<Error>> },
}

#[derive(Debug)]
pub struct SessionHandle {
    pub cancel_token: CancellationToken,
    pub update_tx: mpsc::Sender<SessionUpdate>,
    pub event_rx: mpsc::Receiver<SessionEvent>,
}

impl SessionHandle {
    /// Wait for the session to finish.
    ///
    /// Returns an error if the session failed to complete.
    pub async fn complete(&mut self) -> Result<(), Arc<Error>> {
        while let Some(event) = self.event_rx.recv().await {
            if let SessionEvent::Complete { result } = event {
                return result;
            }
        }
        Ok(())
    }

    pub async fn send_update(&self, update: SessionUpdate) -> anyhow::Result<()> {
        self.update_tx.send(update).await?;
        Ok(())
    }

    /// Finish the session gracefully.
    ///
    /// After calling this, no further protocol messages will be sent from this node.
    /// Previously queued messages will still be sent out. The session will only be closed
    /// once the other peer closes their senders as well.
    pub fn close(&self) {
        tracing::debug!("close session (session handle close called)");
        self.cancel_token.cancel();
    }
}
