//! The session's questions, asked directly to its owner's client on the
//! prompt socket: the daemon never sees an answer. Answers other than
//! one-time codes and signatures are remembered for the session, so it can reconnect on
//! its own; they never leave this process and are wiped when it ends.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::bail;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use vpn_core::ipc::{Event, Request};
use vpn_core::{FailureKind, Prompt, Prompter, failure};
use zeroize::{Zeroize, Zeroizing};

const ANSWER_TIMEOUT: Duration = Duration::from_secs(300);
/// Longest line a client may send (answers are short).
const MAX_ANSWER_LINE: u64 = 64 * 1024;
const CLIENT_QUEUE: usize = 16;

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Option<String>>>>>;

/// The client attached to the prompt socket, if any.
#[derive(Clone)]
struct Client {
    events: mpsc::Sender<Event>,
    pending: Pending,
    gone: CancellationToken,
}

pub struct PromptHub {
    client: Mutex<Option<Client>>,
    attached: Notify,
    cache: Mutex<HashMap<String, Zeroizing<String>>>,
    /// How long a question waits for a client to attach (interactive
    /// attempts); zero for reconnections.
    attach_wait: Mutex<Duration>,
    next: AtomicU64,
}

impl Default for PromptHub {
    fn default() -> Self {
        Self {
            client: Mutex::new(None),
            attached: Notify::new(),
            cache: Default::default(),
            attach_wait: Mutex::new(Duration::ZERO),
            next: AtomicU64::new(1),
        }
    }
}

impl PromptHub {
    pub fn set_attach_wait(&self, wait: Duration) {
        *self.attach_wait.lock().unwrap() = wait;
    }

    /// Accepts the owner's clients (and root's), the newest replacing the
    /// previous one.
    pub async fn listen(self: Arc<Self>, listener: UnixListener, owner: u32) {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            match stream.peer_cred() {
                Ok(cred) if cred.uid() == owner || cred.uid() == 0 => self.attach(stream),
                Ok(cred) => tracing::warn!("refusing a prompt client of uid {}", cred.uid()),
                Err(e) => tracing::warn!("prompt client: {e}"),
            }
        }
    }

    /// Serves one client: events out, answers in.
    pub fn attach(&self, stream: UnixStream) {
        let (read, mut write) = stream.into_split();
        let (events, mut events_rx) = mpsc::channel::<Event>(CLIENT_QUEUE);
        let client = Client { events, pending: Default::default(), gone: CancellationToken::new() };
        let gone = client.gone.clone();
        tokio::spawn(async move {
            while let Some(event) = events_rx.recv().await {
                let mut line = serde_json::to_vec(&event).expect("events serialize");
                line.push(b'\n');
                if write.write_all(&line).await.is_err() {
                    break;
                }
            }
        });
        let pending = client.pending.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(read);
            loop {
                let mut line = String::new();
                match (&mut lines).take(MAX_ANSWER_LINE).read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) if !line.ends_with('\n') => {
                        line.zeroize();
                        break;
                    }
                    Ok(_) => {
                        if let Ok(Request::Answer { id, value }) = serde_json::from_str::<Request>(&line)
                            && let Some(waiting) = pending.lock().unwrap().remove(&id)
                        {
                            let _ = waiting.send(value);
                        }
                        line.zeroize();
                    }
                }
            }
            gone.cancel();
        });
        *self.client.lock().unwrap() = Some(client);
        self.attached.notify_waiters();
    }

    /// The attached client, waiting for one if this attempt expects it.
    async fn client(&self, what: &str) -> anyhow::Result<Client> {
        let wait = *self.attach_wait.lock().unwrap();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let attached = self.attached.notified();
            if let Some(client) = self.client.lock().unwrap().clone()
                && !client.gone.is_cancelled()
            {
                return Ok(client);
            }
            if tokio::time::timeout_at(deadline, attached).await.is_err() {
                return Err(failure(FailureKind::NeedsUser, format!("{what} required but no client is attached")));
            }
        }
    }

    fn detach(&self, client: &Client) {
        let mut current = self.client.lock().unwrap();
        if current.as_ref().is_some_and(|c| c.gone == client.gone) {
            *current = None;
        }
    }
}

#[async_trait]
impl Prompter for PromptHub {
    async fn ask(&self, prompt: Prompt) -> anyhow::Result<Zeroizing<String>> {
        if prompt.kind.remembered()
            && let Some(value) = self.cache.lock().unwrap().get(&prompt.key)
        {
            return Ok(value.clone());
        }
        let client = self.client(&prompt.key).await?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        client.pending.lock().unwrap().insert(id, tx);
        let (key, kind) = (prompt.key.clone(), prompt.kind);
        if client.events.try_send(Event::Prompt { id, prompt }).is_err() {
            client.pending.lock().unwrap().remove(&id);
            self.detach(&client);
            return Err(failure(FailureKind::NeedsUser, format!("the client went away while asking for {key}")));
        }
        let answer = tokio::select! {
            biased;
            answer = tokio::time::timeout(ANSWER_TIMEOUT, rx) => Some(answer),
            _ = client.gone.cancelled() => None,
        };
        client.pending.lock().unwrap().remove(&id);
        let value = match answer {
            Some(Ok(Ok(Some(value)))) => Zeroizing::new(value),
            Some(Ok(Ok(None))) => return Err(failure(FailureKind::Cancelled, format!("{key} prompt cancelled"))),
            // Nobody left to answer: like no client at all.
            Some(Ok(Err(_))) | None => {
                self.detach(&client);
                return Err(failure(FailureKind::NeedsUser, format!("the client went away while asking for {key}")));
            }
            Some(Err(_)) => bail!("no answer for {key} within {}s", ANSWER_TIMEOUT.as_secs()),
        };
        if kind.remembered() {
            self.cache.lock().unwrap().insert(key, value.clone());
        }
        Ok(value)
    }

    async fn open_url(&self, url: &str) -> anyhow::Result<()> {
        let client = self.client("browser login").await?;
        if client.events.try_send(Event::OpenUrl { url: url.to_owned() }).is_err() {
            self.detach(&client);
            return Err(failure(FailureKind::NeedsUser, "the client went away before the browser login"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncBufReadExt;
    use tokio::time::timeout;
    use vpn_core::PromptKind;

    use super::*;

    fn prompt(key: &str, kind: PromptKind) -> Prompt {
        Prompt::new(key, kind, format!("{key}?"))
    }

    /// The client's side of an attached prompt socket.
    struct TestClient {
        lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
        write: tokio::net::unix::OwnedWriteHalf,
    }

    impl TestClient {
        fn attach(hub: &PromptHub) -> Self {
            let (ours, theirs) = UnixStream::pair().unwrap();
            hub.attach(theirs);
            let (read, write) = ours.into_split();
            Self { lines: BufReader::new(read).lines(), write }
        }

        async fn next(&mut self) -> Event {
            let line = timeout(Duration::from_secs(5), self.lines.next_line()).await.unwrap().unwrap().unwrap();
            serde_json::from_str(&line).unwrap()
        }

        async fn answer(&mut self, id: u64, value: Option<&str>) {
            let request = Request::Answer { id, value: value.map(Into::into) };
            let mut line = serde_json::to_vec(&request).unwrap();
            line.push(b'\n');
            self.write.write_all(&line).await.unwrap();
        }
    }

    async fn ask_bg(
        hub: &Arc<PromptHub>,
        client: &mut TestClient,
        key: &str,
        kind: PromptKind,
    ) -> (u64, tokio::task::JoinHandle<anyhow::Result<Zeroizing<String>>>) {
        let (hub2, pr) = (hub.clone(), prompt(key, kind));
        let task = tokio::spawn(async move { hub2.ask(pr).await });
        match client.next().await {
            Event::Prompt { id, prompt } => {
                assert_eq!((prompt.key.as_str(), prompt.kind), (key, kind));
                (id, task)
            }
            other => panic!("expected a prompt, got {other:?}"),
        }
    }

    async fn result(task: tokio::task::JoinHandle<anyhow::Result<Zeroizing<String>>>) -> anyhow::Result<String> {
        timeout(Duration::from_secs(5), task).await.expect("ask did not finish").unwrap().map(|v| v.to_string())
    }

    #[tokio::test]
    async fn secrets_are_remembered_for_the_session() {
        let hub = Arc::new(PromptHub::default());
        let mut client = TestClient::attach(&hub);
        let (id, task) = ask_bg(&hub, &mut client, "password", PromptKind::Secret).await;
        client.answer(id, Some("hunter2")).await;
        assert_eq!(result(task).await.unwrap(), "hunter2");
        // A reconnection: no client needed for what is remembered.
        drop(client);
        assert_eq!(hub.ask(prompt("password", PromptKind::Secret)).await.unwrap().as_str(), "hunter2");
        let err = hub.ask(prompt("username", PromptKind::Text)).await.unwrap_err();
        assert_eq!(vpn_core::failure::kind_of(&err), FailureKind::NeedsUser, "{err}");
    }

    #[tokio::test]
    async fn codes_are_never_remembered() {
        let hub = Arc::new(PromptHub::default());
        let mut client = TestClient::attach(&hub);
        for code in ["111111", "222222"] {
            let (id, task) = ask_bg(&hub, &mut client, "otp", PromptKind::Otp).await;
            client.answer(id, Some(code)).await;
            assert_eq!(result(task).await.unwrap(), code);
        }
        drop(client);
        let err = hub.ask(prompt("otp", PromptKind::Otp)).await.unwrap_err();
        assert_eq!(vpn_core::failure::kind_of(&err), FailureKind::NeedsUser, "{err}");
    }

    #[tokio::test]
    async fn signatures_are_never_remembered() {
        let hub = Arc::new(PromptHub::default());
        let mut client = TestClient::attach(&hub);
        let (id, task) = ask_bg(&hub, &mut client, vpn_core::prompt::SIGN, PromptKind::Sign).await;
        client.answer(id, Some("30440220")).await;
        result(task).await.unwrap();
        drop(client);
        let err = hub.ask(prompt(vpn_core::prompt::SIGN, PromptKind::Sign)).await.unwrap_err();
        assert_eq!(vpn_core::failure::kind_of(&err), FailureKind::NeedsUser, "{err}");
    }

    #[tokio::test]
    async fn a_cancelled_answer_fails_and_is_not_remembered() {
        let hub = Arc::new(PromptHub::default());
        let mut client = TestClient::attach(&hub);
        let (id, task) = ask_bg(&hub, &mut client, "password", PromptKind::Secret).await;
        client.answer(id, None).await;
        assert_eq!(vpn_core::failure::kind_of(&result(task).await.unwrap_err()), FailureKind::Cancelled);
        let (id, task) = ask_bg(&hub, &mut client, "password", PromptKind::Secret).await;
        client.answer(id, Some("ok")).await;
        assert_eq!(result(task).await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn answers_are_routed_by_id() {
        let hub = Arc::new(PromptHub::default());
        let mut client = TestClient::attach(&hub);
        let (id1, t1) = ask_bg(&hub, &mut client, "username", PromptKind::Text).await;
        let (id2, t2) = ask_bg(&hub, &mut client, "otp", PromptKind::Otp).await;
        assert_ne!(id1, id2);
        client.answer(id1.max(id2) + 1000, Some("stray")).await;
        client.answer(id2, Some("123456")).await;
        client.answer(id1, Some("alice")).await;
        client.answer(id1, Some("again")).await;
        assert_eq!(result(t1).await.unwrap(), "alice");
        assert_eq!(result(t2).await.unwrap(), "123456");
    }

    /// The client exits while a question is shown: the attempt fails at
    /// once instead of waiting for the answer timeout.
    #[tokio::test]
    async fn a_client_leaving_fails_the_question() {
        let hub = Arc::new(PromptHub::default());
        let mut client = TestClient::attach(&hub);
        let (_id, task) = ask_bg(&hub, &mut client, "password", PromptKind::Secret).await;
        drop(client);
        let err = result(task).await.unwrap_err();
        assert!(err.to_string().contains("the client went away while asking for password"), "{err}");
        assert_eq!(vpn_core::failure::kind_of(&err), FailureKind::NeedsUser);
    }

    /// An interactive attempt waits for its client to attach.
    #[tokio::test]
    async fn questions_wait_for_a_client_that_is_coming() {
        let hub = Arc::new(PromptHub::default());
        hub.set_attach_wait(Duration::from_secs(5));
        let (hub2, pr) = (hub.clone(), prompt("password", PromptKind::Secret));
        let task = tokio::spawn(async move { hub2.ask(pr).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut client = TestClient::attach(&hub);
        let Event::Prompt { id, .. } = client.next().await else { panic!("expected a prompt") };
        client.answer(id, Some("late")).await;
        assert_eq!(result(task).await.unwrap(), "late");
    }

    #[tokio::test(start_paused = true)]
    async fn nobody_attaching_means_the_user_is_needed() {
        let hub = Arc::new(PromptHub::default());
        hub.set_attach_wait(Duration::from_secs(10));
        let err = hub.ask(prompt("password", PromptKind::Secret)).await.unwrap_err();
        assert_eq!(vpn_core::failure::kind_of(&err), FailureKind::NeedsUser);
        assert!(hub.open_url("https://gw/saml").await.is_err());
    }

    #[tokio::test]
    async fn browser_logins_reach_the_client() {
        let hub = Arc::new(PromptHub::default());
        let mut client = TestClient::attach(&hub);
        hub.open_url("https://gw/remote/saml/start?redirect=1").await.unwrap();
        assert!(
            matches!(client.next().await, Event::OpenUrl { url } if url == "https://gw/remote/saml/start?redirect=1")
        );
    }

    #[tokio::test]
    async fn only_the_owner_may_attach() {
        let dir = std::env::temp_dir().join(format!("omnitun-engine-prompts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.sock");
        let me = nix::unistd::getuid().as_raw();
        if me == 0 {
            return; // root may always attach
        }
        let hub = Arc::new(PromptHub::default());
        tokio::spawn(hub.clone().listen(UnixListener::bind(&path).unwrap(), me.wrapping_add(1)));
        let _stranger = UnixStream::connect(&path).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let err = hub.ask(prompt("password", PromptKind::Secret)).await.unwrap_err();
        assert_eq!(vpn_core::failure::kind_of(&err), FailureKind::NeedsUser, "another user's client was attached");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
