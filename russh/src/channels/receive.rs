use crate::{ChannelMsg, Error};
use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use tokio::sync::mpsc::{Sender, error::TrySendError};
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct ReceiveState {
    consumed: AtomicU32,
    scheduled: AtomicBool,
    wake: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}
impl ReceiveState {
    pub fn configure(&self, wake: Arc<dyn Fn() + Send + Sync>) {
        *self.wake.lock().unwrap_or_else(|e| e.into_inner()) = Some(wake);
    }
    pub fn read(&self, message: Option<&ChannelMsg>) {
        let bytes = match message {
            Some(ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. }) => {
                data.len() as u32
            }
            _ => 0,
        };
        self.consume(bytes);
    }
    fn consume(&self, bytes: u32) {
        let wake = self.wake.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(wake) = wake else {
            return;
        };
        self.consumed.fetch_add(bytes, Ordering::AcqRel);
        if !self.scheduled.swap(true, Ordering::AcqRel) {
            wake();
        }
    }
    pub fn take_consumed(&self) -> u32 {
        self.scheduled.store(false, Ordering::Release);
        self.consumed.swap(0, Ordering::AcqRel)
    }
}

enum PendingMessage {
    Data {
        bytes: Zeroizing<Vec<u8>>,
        ext: Option<u32>,
    },
    Control(ChannelMsg),
}
impl PendingMessage {
    fn into_message(self) -> ChannelMsg {
        match self {
            Self::Data {
                mut bytes,
                ext: None,
            } => ChannelMsg::Data {
                data: std::mem::take(&mut *bytes).into(),
            },
            Self::Data {
                mut bytes,
                ext: Some(ext),
            } => ChannelMsg::ExtendedData {
                data: std::mem::take(&mut *bytes).into(),
                ext,
            },
            Self::Control(message) => message,
        }
    }
}

pub(crate) struct PendingDelivery {
    messages: VecDeque<PendingMessage>,
    control_count: usize,
    control_limit: usize,
    packet_size: usize,
    pub reclaimed: u32,
    pub closing: bool,
}
impl PendingDelivery {
    pub fn new(packet_size: usize, control_limit: usize) -> Self {
        Self {
            messages: VecDeque::new(),
            control_count: 0,
            control_limit,
            packet_size,
            reclaimed: 0,
            closing: false,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
    pub fn send(
        &mut self,
        sender: &Sender<ChannelMsg>,
        state: &ReceiveState,
        message: ChannelMsg,
    ) -> Result<(), Error> {
        if sender.is_closed() {
            self.discard(state);
            // A handler-only consumer receives data through Handler::data instead.
            state.read(Some(&message));
            return Ok(());
        }
        let message = if self.messages.is_empty() {
            match sender.try_send(message) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(message)) => message,
                Err(TrySendError::Closed(message)) => {
                    state.read(Some(&message));
                    return Ok(());
                }
            }
        } else {
            message
        };
        match message {
            ChannelMsg::Data { data } => self.push_data(&data, None),
            ChannelMsg::ExtendedData { data, ext } => self.push_data(&data, Some(ext)),
            message => {
                if self.control_count >= self.control_limit {
                    return Err(Error::Inconsistent);
                }
                self.control_count += 1;
                self.messages.push_back(PendingMessage::Control(message));
            }
        }
        Ok(())
    }
    fn push_data(&mut self, data: &[u8], ext: Option<u32>) {
        if data.is_empty() {
            return;
        }
        if let Some(PendingMessage::Data {
            bytes,
            ext: previous,
        }) = self.messages.back_mut()
            && *previous == ext
            && bytes.len() + data.len() <= self.packet_size
        {
            bytes.extend_from_slice(data);
            return;
        }
        self.messages.push_back(PendingMessage::Data {
            bytes: Zeroizing::new(data.to_vec()),
            ext,
        });
    }
    fn discard(&mut self, state: &ReceiveState) {
        // Dropping the read half leaves Handler::data as the consumer. Return
        // credit for its already delivered payloads as well as future packets.
        for message in self.messages.drain(..) {
            let bytes = match &message {
                PendingMessage::Data { bytes, .. } => bytes.len() as u32,
                PendingMessage::Control(_) => 0,
            };
            state.consume(bytes);
        }
        self.control_count = 0;
    }
    pub fn flush(&mut self, sender: &Sender<ChannelMsg>, state: &ReceiveState) {
        if sender.is_closed() {
            self.discard(state);
            return;
        }
        while !self.messages.is_empty() {
            match sender.try_reserve() {
                Ok(slot) => {
                    let Some(message) = self.messages.pop_front() else {
                        break;
                    };
                    if matches!(message, PendingMessage::Control(_)) {
                        self.control_count -= 1;
                    }
                    slot.send(message.into_message());
                }
                Err(TrySendError::Full(_)) => break,
                Err(TrySendError::Closed(_)) => {
                    self.discard(state);
                    break;
                }
            }
        }
    }
}
