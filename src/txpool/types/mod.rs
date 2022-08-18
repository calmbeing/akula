mod lookup;
mod nonce;
mod transaction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueType {
    Best,
    Worst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertionStatus {
    Inserted(QueueType),
    Discarded(DiscardReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscardReason {
    AlreadyKnown,
    Underpriced,
    NonceTooLow,
    InsufficientBalance,
}

pub use self::{lookup::*, nonce::*, transaction::*};
