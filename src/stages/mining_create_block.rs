use std::{cell::RefCell, cmp::Ordering};

use crate::{
    consensus::*,
    kv::{mdbx::MdbxTransaction, tables},
    mining::{
        proposal::{create_block_header, create_proposal},
        state::MiningConfig,
    },
    models::*,
    stagedsync::stage::*,
    StageId,
};
use anyhow::bail;
use async_trait::async_trait;
use cipher::typenum::int;
use hex::FromHex;
use mdbx::{EnvironmentKind, RW};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use parbytes::ToPretty;
use std::{
    rc::Rc,
    sync::{Arc, Mutex},
};
use tokio::io::copy;
use tracing::debug;

pub const CREATE_BLOCK: StageId = StageId("CreateBlock");
// DAOForkExtraRange is the number of consecutive blocks from the DAO fork point
// to override the extra-data in to prevent no-fork attacks.
pub const DAOFORKEXTRARANG: i32 = 10;

#[derive(Debug)]
pub struct CreateBlock {
    pub config: Arc<Mutex<MiningConfig>>,
    pub mining_block: Arc<Mutex<MiningBlock>>,
    pub chain_spec: ChainSpec,
}

#[derive(Debug)]
pub struct MiningBlock {
    pub header: BlockHeader,
    pub uncles: Vec<BlockHeader>,
    // TODO: pub txs:      types.Transactions,
    //TODO pub receipts types.Receipts,
    //TODO pub local_Txs  types.TransactionsStream
    //TODO pub remote_Txs types.TransactionsStream
}

#[async_trait]
impl<'db, E> Stage<'db, E> for CreateBlock
where
    E: EnvironmentKind,
{
    fn id(&self) -> StageId {
        CREATE_BLOCK
    }

    async fn execute<'tx>(
        &mut self,
        tx: &'tx mut MdbxTransaction<'db, RW, E>,
        input: StageInput,
    ) -> Result<ExecOutput, StageError>
    where
        'db: 'tx,
    {
        let parent_number = input.stage_progress.unwrap();

        let parent_header = get_header(tx, parent_number)?;

        let mut proposal = create_block_header(&parent_header, Arc::clone(&self.config))?;
        if is_clique(self.config.lock().unwrap().consensus.name()) {
            if let Some(cl) = self.config.lock().unwrap().consensus.clique() {
                cl.prepare(tx, &mut proposal);
            }

            // If we are care about TheDAO hard-fork check whether to override the extra-data or not
            if let Some(dao_block) = &self.config.lock().unwrap().dao_fork_block {
                // Check whether the block is among the fork extra-override range
                let limit = BigInt::checked_add(&dao_block, &BigInt::from(DAOFORKEXTRARANG));
                if proposal.number.0.cmp(&DAOFORKEXTRARANG.to_u64().unwrap()) >= Ordering::Equal
                    && proposal.number.0.cmp(&limit.unwrap().to_u64().unwrap()) == Ordering::Less
                {
                    let dao_fork_block_extra =
                        hex::decode("0x64616f2d686172642d666f726b").unwrap().into();
                    // Depending whether we support or oppose the fork, override differently
                    if self.config.lock().unwrap().dao_fork_support {
                        proposal.extra_data = dao_fork_block_extra;
                    } else if bytes::Bytes::eq(&proposal.extra_data, &dao_fork_block_extra) {
                        // If miner opposes, don't let it use the reserved extra-data
                        proposal.extra_data = bytes::Bytes::default();
                    }
                };
            }
        }

        // TODO: make uncles for proposal block

        debug!("Proposal created: {:?}", proposal); // TODO save block proposal

        Ok(ExecOutput::Progress {
            stage_progress: parent_number + 1,
            done: true,
            reached_tip: true,
        })
    }

    async fn unwind<'tx>(
        &mut self,
        _tx: &'tx mut MdbxTransaction<'db, RW, E>,
        _input: UnwindInput,
    ) -> anyhow::Result<UnwindOutput>
    where
        'db: 'tx,
    {
        todo!()
    }
}

fn get_header<E>(
    tx: &mut MdbxTransaction<'_, RW, E>,
    number: BlockNumber,
) -> anyhow::Result<BlockHeader>
where
    E: EnvironmentKind,
{
    let mut cursor = tx.cursor(tables::Header)?;
    Ok(match cursor.seek(number)? {
        Some(((found_number, _), header)) if found_number == number => header,
        _ => bail!("Expected header at block height {} not found.", number.0),
    })
}
