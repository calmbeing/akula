#![allow(unreachable_code)]
use crate::{
    kv::{
        mdbx::MdbxTransaction,
        tables::{self, AccountChange},
        MdbxWithDirHandle,
    },
    models::{BlockNumber, U256},
    p2p::{
        node::Node,
        types::{
            GetPooledTransactions, InboundMessage, Message, NewPooledTransactionHashes, PeerFilter,
            PooledTransactions, Transactions,
        },
    },
    stagedsync::stage::{ExecOutput, Stage, StageError, StageInput, UnwindInput, UnwindOutput},
    txpool::types::*,
    TaskGuard,
};
use async_trait::async_trait;
use hashbrown::HashMap;
use mdbx::{EnvironmentKind, WriteMap, RO};
use parking_lot::Mutex;
use rand::Rng;
use std::{collections::BinaryHeap, sync::Arc, time::Duration};
use task_group::TaskGroup;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tracing::*;

pub const PER_SENDER: usize = 32;

#[derive(Debug, Default)]
pub struct Queues {
    best_queue: BinaryHeap<ScoredTransaction>,
    worst_queue: BinaryHeap<ScoredTransaction>,
}

#[derive(Default)]
pub struct PoolBuilder {
    node: Option<Arc<Node>>,
    db: Option<Arc<MdbxWithDirHandle<WriteMap>>>,
}

impl PoolBuilder {
    pub fn set_node(mut self, node: Arc<Node>) -> Self {
        self.node = Some(node);
        self
    }

    pub fn set_db(mut self, db: Arc<MdbxWithDirHandle<WriteMap>>) -> Self {
        self.db = Some(db);
        self
    }

    pub fn build(self) -> anyhow::Result<Pool> {
        let node = self.node.ok_or_else(|| anyhow::anyhow!("node not set"))?;
        let db = self.db.ok_or_else(|| anyhow::anyhow!("db not set"))?;
        Ok(Pool {
            inner: Arc::new(TransactionPoolInner {
                node,
                db,
                queues: Default::default(),
                lookup: Default::default(),
            }),
        })
    }
}

#[derive(Debug)]
struct TransactionPoolInner {
    node: Arc<Node>,
    db: Arc<MdbxWithDirHandle<WriteMap>>,
    queues: Mutex<Queues>,
    lookup: TransactionLookup,
}

#[derive(Debug)]
pub struct Pool {
    inner: Arc<TransactionPoolInner>,
}

impl Clone for Pool {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[async_trait]
impl<'db, E: EnvironmentKind> Stage<'db, E> for Pool {
    fn id(&self) -> crate::StageId {
        crate::stagedsync::stages::TX_POOL
    }

    async fn execute<'tx>(
        &mut self,
        txn: &'tx mut MdbxTransaction<'db, mdbx::RW, E>,
        input: StageInput,
    ) -> Result<ExecOutput, StageError>
    where
        'db: 'tx,
    {
        let start_key = input.stage_progress.unwrap_or_default();
        if start_key == BlockNumber(0) {
            // FIXME: remove the little hack.
            return Ok(ExecOutput::Progress {
                stage_progress: input
                    .previous_stage
                    .map(|(_, number)| number)
                    .unwrap_or_default(),
                done: true,
                reached_tip: true,
            });
        }
        let to_announce = {
            let mut queues = self.inner.queues.lock();
            let state_changes = txn
                .cursor(tables::AccountChangeSet)?
                .walk(Some(start_key))
                .map(|entry| {
                    entry.map(|(_, AccountChange { address, account })| {
                        (address, account.unwrap_or_default())
                    })
                })
                .collect::<Result<HashMap<_, _>, _>>()?;

            let mut buf = Vec::new();
            queues.worst_queue.retain(|scored| {
                if let Some(account) = state_changes.get(&scored.sender) {
                    if account.nonce > scored.nonce {
                        false
                    } else {
                        if account.balance > scored.total_price {
                            buf.push(scored.clone());
                            false
                        } else {
                            true
                        }
                    }
                } else {
                    true
                }
            });

            queues.best_queue.retain(
                |ScoredTransaction {
                     sender,
                     nonce,
                     total_price,
                     ..
                 }| {
                    if let Some(account) = state_changes.get(&sender) {
                        !(account.nonce > *nonce || account.balance < *total_price)
                    } else {
                        true
                    }
                },
            );
            queues.best_queue.extend(buf);

            queues
                .best_queue
                .iter()
                .filter_map(|scored_tx| {
                    self.inner
                        .lookup
                        .get(scored_tx.hash)
                        .map(|tx| (tx.hash, tx.msg.clone()))
                })
                .collect::<Vec<_>>()
        };
        self.inner.node.announce_transactions(to_announce).await;

        Ok(ExecOutput::Progress {
            stage_progress: input
                .previous_stage
                .map(|(_, number)| number)
                .unwrap_or_default(),
            done: true,
            reached_tip: true,
        })
    }

    async fn unwind<'tx>(
        &mut self,
        _txn: &'tx mut MdbxTransaction<'db, mdbx::RW, E>,
        input: UnwindInput,
    ) -> anyhow::Result<UnwindOutput>
    where
        'db: 'tx,
    {
        // FIXME: implement.
        let mut queues = self.inner.queues.lock();
        queues.best_queue.clear();
        queues.worst_queue.clear();

        Ok(UnwindOutput {
            stage_progress: input.unwind_to,
        })
    }
}

impl Pool {
    fn add_transaction<'env, 'txn>(
        inner: &TransactionPoolInner,
        queues: &mut Queues,
        txn: &'txn MdbxTransaction<'env, RO, WriteMap>,
        tx: Transaction,
        current_base_fee: U256,
    ) -> anyhow::Result<InsertionStatus>
    where
        'env: 'txn,
    {
        if inner.lookup.contains_hash(&tx.hash) {
            return Ok(InsertionStatus::Discarded(DiscardReason::AlreadyKnown));
        };

        let account = txn.get(tables::Account, tx.sender)?.unwrap_or_default();
        if account.nonce > tx.nonce() {
            return Ok(InsertionStatus::Discarded(DiscardReason::NonceTooLow));
        };
        if account.balance < tx.total_price() {
            return Ok(InsertionStatus::Discarded(
                DiscardReason::InsufficientBalance,
            ));
        }

        let scored_transaction = ScoredTransaction::new(&tx);
        let queue_type = if tx
            .max_fee_per_gas()
            .saturating_sub(tx.max_priority_fee_per_gas())
            >= current_base_fee
        {
            QueueType::Best
        } else {
            QueueType::Worst
        };
        inner.lookup.insert(tx);

        match queue_type {
            QueueType::Best => {
                queues.best_queue.push(scored_transaction);
            }
            QueueType::Worst => {
                queues.worst_queue.push(scored_transaction);
            }
        }
        Ok(InsertionStatus::Inserted(queue_type))
    }
}

impl Pool {
    pub async fn run(&self) {
        let tasks = TaskGroup::new();

        let (request_tx, mut request_rx) = mpsc::channel::<(Vec<_>, _)>(128);
        tasks.spawn_with_name("transaction_requester", {
            let mut local_tasks = Vec::with_capacity(128);

            let this = self.inner.clone();

            async move {
                while let Some((hashes, pred)) = request_rx.recv().await {
                    local_tasks.push(TaskGuard(tokio::spawn({
                        let this = this.clone();

                        async move {
                            let request_id = rand::thread_rng().gen::<u64>();

                            trace!(
                                "Sending transactions request: id={} len={} peer_predicate={:?}",
                                request_id,
                                hashes.len(),
                                pred
                            );

                            this.node
                                .get_pooled_transactions(request_id, &hashes, pred)
                                .await;
                        }
                    })));
                }
            }
        });

        let (penalty_tx, mut penalty_rx) = mpsc::channel(128);
        tasks.spawn_with_name("peer_penalizer", {
            let this = self.inner.node.clone();

            async move {
                while let Some(peer_id) = penalty_rx.recv().await {
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), this.penalize_peer(peer_id))
                            .await;
                }
            }
        });

        let (inbound_tx, mut inbound_rx) = mpsc::channel(128);
        tasks.spawn({
            let this = self.inner.clone();

            async move {
                while let Some((GetPooledTransactions { request_id, hashes }, peer_id, sentry_id)) =
                    inbound_rx.recv().await
                {
                    let transactions = hashes
                        .iter()
                        .filter_map(|hash| this.lookup.get(hash).map(|tx| tx.msg))
                        .collect::<Vec<_>>();
                    this.node
                        .send_pooled_transactions(
                            request_id,
                            transactions,
                            PeerFilter::Peer(peer_id, sentry_id),
                        )
                        .await;
                }
            }
        });

        tasks.spawn({
            let this = self.inner.clone();
            let mut ticker = tokio::time::interval(Duration::from_secs(5));

            async move {
                loop {
                    ticker.tick().await;

                    let to_announce = {
                        let queues = this.queues.lock();
                        queues
                            .best_queue
                            .iter()
                            .filter_map(|scored_tx| {
                                this.lookup.get(scored_tx.hash).map(|tx| (tx.hash, tx.msg))
                            })
                            .collect::<Vec<_>>()
                    };

                    if !to_announce.is_empty() {
                        this.node.announce_transactions(to_announce).await;
                    }
                }
            }
        });

        let (processor_tx, mut processor_rx) = mpsc::channel(1 << 10);
        tasks.spawn({
            let this = self.inner.clone();
            let base_fee = U256::ZERO;

            let mut ticker = tokio::time::interval(Duration::from_secs(3));

            async move {
                tokio::select! {
                    _ = ticker.tick() => {
                        let mut transactions = Vec::new();
                        while let Ok(txs) = processor_rx.try_recv() {
                            transactions.extend(txs);
                        }

                        let txn = this.db.begin()?;
                        let mut queues = this.queues.lock();

                        for transaction in transactions {
                            Self::add_transaction(&this, &mut queues, &txn, transaction, base_fee)?;
                        }
                    },
                }

                Ok::<_, anyhow::Error>(())
            }
        });

        tasks.spawn_with_name("incoming router", {
            let this = self.inner.clone();

            async move {
                let mut stream = this.node.stream_transactions().await;

                while let Some(InboundMessage {
                    msg,
                    peer_id,
                    sentry_id,
                }) = stream.next().await
                {
                    match msg {
                        Message::NewPooledTransactionHashes(NewPooledTransactionHashes(hashes)) => {
                            request_tx
                                .send((hashes, PeerFilter::Peer(peer_id, sentry_id)))
                                .await?;
                        }
                        Message::Transactions(Transactions(transactions))
                            if !transactions.is_empty() =>
                        {
                            match transactions
                                .into_iter()
                                .map(Transaction::try_from)
                                .collect::<Result<Vec<_>, _>>()
                            {
                                Ok(transactions) => {
                                    processor_tx.send(transactions).await?;
                                }
                                Err(_) => {
                                    penalty_tx.send(peer_id).await?;
                                }
                            }
                        }
                        Message::GetPooledTransactions(request) => {
                            inbound_tx.send((request, peer_id, sentry_id)).await?;
                        }
                        Message::PooledTransactions(PooledTransactions {
                            transactions, ..
                        }) => {
                            match transactions
                                .into_iter()
                                .map(Transaction::try_from)
                                .collect::<Result<Vec<_>, _>>()
                            {
                                Ok(transactions) => {
                                    processor_tx.send(transactions).await?;
                                }
                                Err(_) => {
                                    penalty_tx.send(peer_id).await?;
                                }
                            }
                        }
                        _ => {}
                    }
                }

                Ok::<_, anyhow::Error>(())
            }
        });

        std::future::pending::<()>().await;
    }
}
