use super::WindowSizeRef;
use crate::{
    ChannelMsg,
    channels::receive::{PendingDelivery, ReceiveState},
};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::Sender;

/// A handle to the [`super::Channel`]'s to be able to transmit messages
/// to it and update it's `window_size`.
pub struct ChannelRef {
    pub(super) sender: Sender<ChannelMsg>,
    pub(super) window_size: WindowSizeRef,
    pub(crate) receive_state: Arc<ReceiveState>,
    pub(crate) delivery: Mutex<Option<PendingDelivery>>,
}

impl ChannelRef {
    pub fn new(sender: Sender<ChannelMsg>) -> Self {
        Self {
            sender,
            window_size: WindowSizeRef::new(0),
            receive_state: Arc::new(ReceiveState::default()),
            delivery: Mutex::new(None),
        }
    }

    pub(crate) fn window_size(&self) -> &WindowSizeRef {
        &self.window_size
    }
    pub(crate) fn enable_receive_flow(
        &self,
        packet_size: usize,
        control_limit: usize,
        wake: Arc<dyn Fn() + Send + Sync>,
    ) {
        *self.delivery.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingDelivery::new(packet_size, control_limit));
        self.receive_state.configure(wake);
    }
    pub(crate) fn deliver(&self, message: ChannelMsg) -> Result<(), crate::Error> {
        self.delivery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
            .ok_or(crate::Error::Inconsistent)?
            .send(&self.sender, &self.receive_state, message)
    }
}

impl std::ops::Deref for ChannelRef {
    type Target = Sender<ChannelMsg>;

    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}

impl std::fmt::Debug for ChannelRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelRef")
            .field("window_size", &self.window_size)
            .finish_non_exhaustive()
    }
}
