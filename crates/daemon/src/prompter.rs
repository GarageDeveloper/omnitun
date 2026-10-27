//! The client of a `Connect`: it receives the session's progress until the
//! tunnel is up. Questions do not go through here: the session's engine
//! asks them on its own prompt socket.

use std::sync::Mutex;

use tokio::sync::mpsc;
use vpn_core::ipc::Event;

/// A connected client: events go out.
#[derive(Clone)]
pub struct ClientLink {
    events: mpsc::Sender<Event>,
}

impl ClientLink {
    pub fn new(events: mpsc::Sender<Event>) -> Self {
        Self { events }
    }

    /// Queues an event; false when the client is gone or not reading, in
    /// which case it is treated as detached.
    pub fn send(&self, event: Event) -> bool {
        self.events.try_send(event).is_ok()
    }

    /// Resolves when the client has gone away.
    pub async fn closed(&self) {
        self.events.closed().await
    }
}

/// The client that started a session, until it goes away or the session
/// is up.
pub struct SessionClient {
    client: Mutex<Option<ClientLink>>,
}

impl SessionClient {
    pub fn new(client: ClientLink) -> Self {
        Self { client: Mutex::new(Some(client)) }
    }

    /// Sends an event to the attached client, detaching it if it is gone.
    pub fn notify(&self, event: Event) {
        let mut client = self.client.lock().unwrap();
        if let Some(link) = client.as_ref()
            && !link.send(event)
        {
            *client = None;
        }
    }

    pub fn detach(&self) {
        *self.client.lock().unwrap() = None;
    }

    pub fn is_attached(&self) -> bool {
        self.client.lock().unwrap().as_ref().is_some_and(|c| !c.events.is_closed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn detached_client() {
        let (tx, mut rx) = mpsc::channel(8);
        let client = SessionClient::new(ClientLink::new(tx));
        client.notify(Event::Done);
        assert!(matches!(rx.try_recv(), Ok(Event::Done)));
        client.detach();
        client.notify(Event::Done);
        assert!(rx.try_recv().is_err(), "no events after detach");
    }

    #[tokio::test]
    async fn client_not_reading_is_detached() {
        let (tx, mut rx) = mpsc::channel(1);
        let client = SessionClient::new(ClientLink::new(tx));
        client.notify(Event::Done); // fills the queue
        client.notify(Event::Done); // dropped: client considered gone
        assert!(!client.is_attached());
        assert!(matches!(rx.try_recv(), Ok(Event::Done)));
    }
}
