use crate::devp2p::Swarm;
use akula::{
    akula_tracing::{self, Component},
    binutil::AkulaDataDir,
    consensus::{engine_factory, Consensus, ForkChoiceMode, InitialParams, ParliaInitialParams},
    kv::tables::CHAINDATA_TABLES,
    mining::state::*,
    models::*,
    p2p::node::NodeBuilder,
    rpc::{
        debug::DebugApiServerImpl, erigon::ErigonApiServerImpl, eth::EthApiServerImpl,
        net::NetApiServerImpl, otterscan::OtterscanApiServerImpl, parity::ParityApiServerImpl,
        trace::TraceApiServerImpl, web3::Web3ApiServerImpl,
    },
    sentry::*,
    stagedsync,
    stages::*,
    version_string,
};
use anyhow::Context;
use bytes::Bytes;
use clap::Parser;
use ethereum_jsonrpc::{
    ErigonApiServer, EthApiServer, NetApiServer, OtterscanApiServer, ParityApiServer,
    TraceApiServer, Web3ApiServer,
};
use expanded_pathbuf::ExpandedPathBuf;
use futures::executor::block_on;
use http::Uri;
use jsonrpsee::{
    core::server::rpc_module::Methods, http_server::HttpServerBuilder, ws_server::WsServerBuilder,
};
use num_bigint::BigInt;
use secp256k1::SecretKey;
use std::{
    collections::HashSet,
    fs::OpenOptions,
    future::pending,
    io::Write,
    net::SocketAddr,
    panic,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::sleep;
use tracing::*;
use tracing_subscriber::prelude::*;

#[derive(Parser)]
#[clap(name = "Akula", about = "Next-generation Ethereum implementation.")]
pub struct Opt {
    /// Path to database directory.
    #[clap(long, help = "Database directory path", default_value_t)]
    pub datadir: AkulaDataDir,

    /// Name of the network to join
    #[clap(long)]
    pub chain: Option<String>,

    /// Chain specification file to use
    #[clap(long)]
    pub chain_spec_file: Option<ExpandedPathBuf>,

    /// Sentry GRPC service URL
    #[clap(long, help = "Sentry GRPC service URLs as 'http://host:port'")]
    pub sentry_api_addr: Option<String>,

    #[clap(flatten)]
    pub sentry_opts: akula::sentry::Opts,

    /// Last block where to sync to.
    #[clap(long)]
    pub max_block: Option<BlockNumber>,

    /// Start with unwinding to this block.
    #[clap(long)]
    pub start_with_unwind: Option<BlockNumber>,

    /// Turn on pruning.
    #[clap(long)]
    pub prune: bool,

    /// Use incremental staged sync.
    #[clap(long)]
    pub increment: Option<BlockNumber>,

    /// Sender recovery batch size (blocks)
    #[clap(long, default_value = "500000")]
    pub sender_recovery_batch_size: u64,

    /// Execution batch size (Ggas).
    #[clap(long, default_value = "5000")]
    pub execution_batch_size: u64,

    /// Execution history batch size (Ggas).
    #[clap(long, default_value = "250")]
    pub execution_history_batch_size: u64,

    /// Exit execution stage after batch.
    #[clap(long)]
    pub execution_exit_after_batch: bool,

    /// Skip commitment (state root) verification.
    #[clap(long)]
    pub skip_commitment: bool,

    /// Exit Akula after sync is complete and there's no progress.
    #[clap(long)]
    pub exit_after_sync: bool,

    /// Delay applied at the terminating stage.
    #[clap(long, default_value = "0")]
    pub delay_after_sync: u64,

    /// Disable JSONRPC.
    #[clap(long)]
    pub no_rpc: bool,

    /// Enable API options
    #[clap(long)]
    pub enable_api: Option<String>,

    /// Enable JSONRPC at this IP address and port.
    #[clap(long, default_value = "127.0.0.1:8545")]
    pub rpc_listen_address: String,

    /// Enable Websocket at this IP address and port.
    #[clap(long, default_value = "127.0.0.1:8546")]
    pub websocket_listen_address: String,

    /// Enable gRPC at this IP address and port.
    #[clap(long, default_value = "127.0.0.1:7545")]
    pub grpc_listen_address: SocketAddr,

    /// Enable CL engine RPC at this IP address and port.
    #[clap(long, default_value = "127.0.0.1:8551")]
    pub engine_listen_address: SocketAddr,

    /// Enable mining
    #[clap(long)]
    pub mine: bool,

    /// Adress for block mining rewards
    #[clap(long)]
    pub mine_etherbase: Option<H160>,

    /// Extra data for mined blocks
    #[clap(long)]
    pub mine_extradata: Option<String>,

    /// Private key to sign mined blocks with
    #[clap(long)]
    pub mine_secretkey: Option<SecretKey>,

    /// BLS Private key to sign vote, hex format
    #[clap(long)]
    pub bls_secret_key: Option<String>,

    /// BLS Public key, hex format
    #[clap(long)]
    pub bls_public_key: Option<String>,

    /// Path to JWT secret file.
    #[clap(long)]
    pub jwt_secret_path: Option<ExpandedPathBuf>,
}

async fn create_swarm_helper(opt: Opt, chain_config: ChainConfig) {
    akula::sentry::run(
        opt.sentry_opts,
        opt.datadir,
        chain_config.chain_spec.p2p.clone(),
    )
    .await;
}

#[allow(unreachable_code)]
fn main() -> anyhow::Result<()> {
    let opt: Opt = Opt::parse();
    let opt_arc = Arc::new(Mutex::new(opt));
    fdlimit::raise_fd_limit();
    akula_tracing::build_subscriber(Component::Core).init();

    let mut can_mine = false;
    let opt_conf = opt_arc.lock().unwrap();
    if opt_conf.mine {
        can_mine = true;
        if opt_conf.exit_after_sync {
            warn!("Conflicting options: --exit-after-sync is set, will not enable mining");
            can_mine = false;
        }

        if opt_conf.mine_etherbase.is_none() {
            warn!("Etherbase not set, will not enable mining");
            can_mine = false;
        }

        if opt_conf.mine_secretkey.is_none() {
            warn!("No private key to sign blocks given, will not enable mining");
            can_mine = false;
        }

        if opt_conf.bls_secret_key.is_none() {
            warn!("No BLS private key to sign vote, will not enable mining");
            can_mine = false;
        }

        if opt_conf.bls_public_key.is_none() {
            warn!("No BLS public key, will not enable mining");
            can_mine = false;
        }
    };

    let can_mine_arc = Arc::new(Mutex::new(can_mine));
    let can_mine_arc_stage = can_mine_arc.clone();

    let mut bundled_chain_spec = false;

    let chain_config = if let Some(chain) = &opt_conf.chain {
        bundled_chain_spec = true;
        Some(ChainSpec::load_builtin(chain)?)
    } else if let Some(path) = &opt_conf.chain_spec_file {
        Some(ChainSpec::load_from_file(path)?)
    } else {
        None
    };

    std::fs::create_dir_all(&opt_conf.datadir.0)?;
    let akula_chain_data_dir = opt_conf.datadir.chain_data_dir();
    let akula_chain_data_dir_arc = Arc::new(Mutex::new(akula_chain_data_dir));

    let etl_temp_path = opt_conf.datadir.etl_temp_dir();
    let etl_arc = Arc::new(Mutex::new(etl_temp_path));

    let etl_arc_lock = etl_arc.lock().unwrap();
    let _ = std::fs::remove_dir_all(&*etl_arc_lock);

    std::fs::create_dir_all(&*etl_arc_lock)?;

    let etl_temp_dir =
        Arc::new(tempfile::tempdir_in(&*etl_arc_lock).context("failed to create ETL temp dir")?);
    let etl_dir_arc = Arc::new(Mutex::new(etl_temp_dir));
    let etl_dir_full_arc = etl_dir_arc.clone();

    let db = Arc::new(akula::kv::new_database(
        &CHAINDATA_TABLES,
        &akula_chain_data_dir_arc.lock().unwrap(),
    )?);

    let db_back = db.clone();
    akula::database_version::migrate_database(&db_back)?;
    let db_arc = Arc::new(Mutex::new(db));

    let chainspec = {
        let span = span!(Level::INFO, "", " Genesis initialization ");
        let _g = span.enter();
        let txn = db_back.begin_mutable()?;
        let (chainspec, initialized) = akula::genesis::initialize_genesis(
            &txn,
            &etl_dir_arc.lock().unwrap(),
            bundled_chain_spec,
            chain_config,
        )?;
        if initialized {
            txn.commit()?;
        }

        chainspec
    };

    // chainspec_arc to avoid move error.
    let chainspec_arc = Arc::new(Mutex::new(chainspec));
    let chainspec_arc_stage = chainspec_arc.clone();

    // akula::database_version::migrate_database(&db_back)?;
    let chain_config = ChainConfig::from(chainspec_arc.lock().unwrap().clone());

    let sentries = if let Some(raw_str) = &opt_conf.sentry_api_addr {
        raw_str
            .split(',')
            .filter_map(|s| s.parse::<Uri>().ok())
            .collect::<Vec<_>>()
    } else {
        let max_peers = opt_conf.sentry_opts.max_peers;
        let sentry_api_addr = opt_conf.sentry_opts.sentry_addr;

        let opt_back: Opt = Opt::parse();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_stack_size(128 * 1024 * 1024)
            .build()?;

        let swarm = create_swarm_helper(opt_back, chain_config.clone());

        let opt_sync: Opt = Opt::parse();
        rt.block_on(async {
            let swarm = akula::sentry::run(
                opt_sync.sentry_opts,
                opt_sync.datadir,
                chain_config.clone().chain_spec.p2p.clone(),
            )
            .await;
        });

        vec![format!("http://{sentry_api_addr}").parse()?]
    };

    let mut builder = NodeBuilder::new(chain_config.clone()).set_stash(db_back.clone());
    for sentry_api_addr in sentries {
        builder = builder.add_sentry(sentry_api_addr);
    }

    let node = Arc::new(builder.build()?);
    let node_arc = Arc::new(Mutex::new(node));
    let node_stage = node_arc.clone();

    // spawn mining stage thread.
    // std::thread::Builder::new()
    //     .stack_size(128 * 1024 * 1024)
    //     .spawn(|| {
    //         let opt: Opt = Opt::parse();
    //         let rt = tokio::runtime::Builder::new_multi_thread()
    //             .enable_all()
    //             .thread_stack_size(128 * 1024 * 1024)
    //             .build()
    //             .unwrap();
    //         rt.block_on(async move {
    //             // init consensus init params
    //             let chainspec_arc_lock = chainspec_arc.lock().unwrap();
    //             let can_mine_lock = can_mine_arc.lock().unwrap();
    //             let node_arc_lock = node_arc.lock().unwrap();
    //             let params = match &chainspec_arc_lock.consensus.seal_verification {
    //                 SealVerificationParams::Parlia { .. } => {
    //                     if !can_mine_lock.clone() {
    //                         InitialParams::Useless
    //                     } else {
    //                         InitialParams::Parlia(ParliaInitialParams {
    //                             bls_prv_key: opt.bls_secret_key,
    //                             bls_pub_key: opt.bls_public_key,
    //                             node: Some(Arc::clone(&node_arc_lock)),
    //                             sync_stage: None,
    //                         })
    //                     }
    //                 }
    //                 _ => InitialParams::Useless,
    //             };

    //             // init consensus init params
    //             let params = match chainspec_arc_lock.consensus.seal_verification {
    //                 SealVerificationParams::Parlia { .. } => {
    //                     if !can_mine_lock.clone() {
    //                         InitialParams::Useless
    //                     } else {
    //                         let opt: Opt = Opt::parse();
    //                         InitialParams::Parlia(ParliaInitialParams {
    //                             bls_prv_key: opt.bls_secret_key,
    //                             bls_pub_key: opt.bls_public_key,
    //                             node: Some(Arc::clone(&node_arc_lock)),
    //                             sync_stage: None,
    //                         })
    //                     }
    //                 }
    //                 _ => InitialParams::Useless,
    //             };

    //             let db_back = Arc::new(
    //                 akula::kv::new_database(
    //                     &CHAINDATA_TABLES,
    //                     &akula_chain_data_dir_arc.lock().unwrap(),
    //                 )
    //                 .unwrap(),
    //             );

    //             if can_mine_lock.clone() {
    //                 let mut mining_stage = stagedsync::StagedSync::new();
    //                 let consensus_config = engine_factory(
    //                     Some(db_back.clone()),
    //                     chainspec_arc_lock.clone(),
    //                     Some(opt.engine_listen_address),
    //                     params.clone(),
    //                 )
    //                 .unwrap();
    //                 let config = MiningConfig {
    //                     enabled: true,
    //                     ether_base: opt.mine_etherbase.unwrap().clone(),
    //                     secret_key: opt.mine_secretkey.unwrap().clone(),
    //                     extra_data: opt.mine_extradata.map(Bytes::from).clone(),
    //                     consensus: consensus_config,
    //                     dao_fork_block: Some(BigInt::new(num_bigint::Sign::Plus, vec![])),
    //                     dao_fork_support: false,
    //                     gas_limit: 30000000,
    //                 };
    //                 let mining_config_mutex = Arc::new(Mutex::new(config));
    //                 info!("Mining enabled");
    //                 let mining_block = MiningBlock {
    //                     header: BlockHeader {
    //                         parent_hash: H256::zero(),
    //                         ommers_hash: H256::zero(),
    //                         beneficiary: Address::zero(),
    //                         state_root: H256::zero(),
    //                         transactions_root: H256::zero(),
    //                         receipts_root: H256::zero(),
    //                         logs_bloom: Bloom::zero(),
    //                         difficulty: U256::ZERO,
    //                         number: BlockNumber(0),
    //                         gas_limit: 0,
    //                         gas_used: 0,
    //                         timestamp: 0,
    //                         extra_data: Bytes::new(),
    //                         mix_hash: H256::zero(),
    //                         nonce: H64::zero(),
    //                         base_fee_per_gas: None,
    //                     },
    //                     ommers: Default::default(),
    //                     transactions: vec![],
    //                 };
    //                 let mining_block_mutex = Arc::new(Mutex::new(mining_block));
    //                 let mining_status = MiningStatus::new();
    //                 let mining_status_mutex = Arc::new(Mutex::new(mining_status));

    //                 mining_stage.push(
    //                     CreateBlock {
    //                         mining_status: Arc::clone(&mining_status_mutex),
    //                         mining_block: Arc::clone(&mining_block_mutex),
    //                         mining_config: Arc::clone(&mining_config_mutex),
    //                         chain_spec: chainspec_arc_lock.clone(),
    //                     },
    //                     false,
    //                 );

    //                 mining_stage.push(
    //                     MiningExecBlock {
    //                         mining_status: Arc::clone(&mining_status_mutex),
    //                         mining_block: Arc::clone(&mining_block_mutex),
    //                         mining_config: Arc::clone(&mining_config_mutex),
    //                         chain_spec: chainspec_arc_lock.clone(),
    //                     },
    //                     false,
    //                 );

    //                 let etl_dir_arc_lock = etl_dir_arc.lock().unwrap();
    //                 mining_stage.push(HashState::new(etl_dir_arc_lock.clone(), None), !opt.prune);

    //                 mining_stage.push_with_unwind_priority(
    //                     Interhashes::new(etl_dir_arc_lock.clone(), None),
    //                     !opt.prune,
    //                     1,
    //                 );
    //                 info!("createBlock stage enabled");

    //                 mining_stage.push(
    //                     MiningFinishBlock {
    //                         mining_status: Arc::clone(&mining_status_mutex),
    //                         mining_block: Arc::clone(&mining_block_mutex),
    //                         mining_config: Arc::clone(&mining_config_mutex),
    //                         chain_spec: chainspec_arc_lock.clone(),
    //                         node: node_arc_lock.clone(),
    //                     },
    //                     false,
    //                 );
    //                 mining_stage.run(&db_back).await;
    //             };
    //         })
    //     })?;

    // spawn fullsync thread.
    std::thread::Builder::new()
        .stack_size(128 * 1024 * 1024)
        .spawn(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(128 * 1024 * 1024)
                .build()?;
            rt.block_on(async move {
                info!("Starting Akula ({})", version_string());

                info!(
                    "Current network: {}",
                    chainspec_arc_stage.lock().unwrap().name
                );

                let opt: Opt = Opt::parse();
                let jwt_secret_path = opt
                    .jwt_secret_path
                    .map(|v| v.0)
                    .unwrap_or_else(|| opt.datadir.0.join("jwt.hex"));
                if let Ok(mut file) = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(jwt_secret_path)
                {
                    file.write_all(
                        hex::encode(
                            std::iter::repeat_with(rand::random)
                                .take(32)
                                .collect::<Vec<_>>(),
                        )
                        .as_bytes(),
                    )?;
                    file.flush()?;
                }

                let akula_chain_data_dir_full = opt.datadir.clone().chain_data_dir();

                let db_full = Arc::new(
                    akula::kv::new_database(&CHAINDATA_TABLES, &akula_chain_data_dir_full.clone())
                        .unwrap(),
                );

                let db_full_back = db_full.clone();
                let chainspec_arc_stage_lock = chainspec_arc_stage.lock().unwrap();
                let network_id = chainspec_arc_stage_lock.params.network_id;

                if !opt.no_rpc {
                    tokio::spawn({
                        let db = db_full.clone();
                        async move {
                            let http_server = HttpServerBuilder::default()
                                .build(&opt.rpc_listen_address)
                                .await
                                .unwrap();

                            let websocket_server = WsServerBuilder::default()
                                .build(&opt.websocket_listen_address)
                                .await
                                .unwrap();

                            let mut api = Methods::new();

                            let api_options = opt
                                .enable_api
                                .map(|v| {
                                    v.split(',')
                                        .into_iter()
                                        .map(|s| s.to_lowercase())
                                        .collect::<HashSet<String>>()
                                })
                                .unwrap_or_default();

                            if api_options.is_empty() || api_options.contains("eth") {
                                api.merge(
                                    EthApiServerImpl {
                                        db: db.clone(),
                                        call_gas_limit: 100_000_000,
                                    }
                                    .into_rpc(),
                                )
                                .unwrap();
                            }

                            if api_options.is_empty() || api_options.contains("net") {
                                api.merge(NetApiServerImpl { network_id }.into_rpc())
                                    .unwrap();
                            }

                            if api_options.is_empty() || api_options.contains("erigon") {
                                api.merge(ErigonApiServerImpl { db: db.clone() }.into_rpc())
                                    .unwrap();
                            }

                            if api_options.is_empty() || api_options.contains("otterscan") {
                                api.merge(OtterscanApiServerImpl { db: db.clone() }.into_rpc())
                                    .unwrap();
                            }

                            if api_options.is_empty() || api_options.contains("parity") {
                                api.merge(ParityApiServerImpl { db: db.clone() }.into_rpc())
                                    .unwrap();
                            }

                            if api_options.is_empty() || api_options.contains("trace") {
                                api.merge(
                                    TraceApiServerImpl {
                                        db: db.clone(),
                                        call_gas_limit: 100_000_000,
                                    }
                                    .into_rpc(),
                                )
                                .unwrap();
                            }

                            if api_options.is_empty() || api_options.contains("web3") {
                                api.merge(Web3ApiServerImpl.into_rpc()).unwrap();
                            }

                            let _http_server_handle = http_server.start(api.clone()).unwrap();
                            info!("HTTP server listening on {}", opt.rpc_listen_address);

                            let _websocket_server_handle = websocket_server.start(api).unwrap();
                            info!(
                                "WebSocket server listening on {}",
                                opt.websocket_listen_address
                            );

                            pending::<()>().await
                        }
                    });

                    tokio::spawn({
                        async move {
                            info!("Starting gRPC server on {}", opt.grpc_listen_address);
                            let mut builder = tonic::transport::Server::builder();

                            #[cfg(feature = "grpc-reflection")]
                            builder.add_service(
                                tonic_reflection::server::Builder::configure()
                                    .register_encoded_file_descriptor_set(
                                        ethereum_interfaces::FILE_DESCRIPTOR_SET,
                                    )
                                    .build()
                                    .unwrap(),
                            );

                            builder.add_service(
                                ethereum_interfaces::web3::debug_api_server::DebugApiServer::new(
                                    DebugApiServerImpl {
                                        db: db_full.clone(),
                                    }
                                )
                            )
                            .add_service(
                                ethereum_interfaces::web3::trace_api_server::TraceApiServer::new(
                                    TraceApiServerImpl {
                                        db: db_full.clone(),
                                        call_gas_limit: 100_000_000,
                                    },
                                ),
                            )
                            .serve(opt.grpc_listen_address)
                            .await
                            .unwrap();
                        }
                    });
                }

                let increment = opt.increment.or({
                    if opt.prune {
                        Some(BlockNumber(90_000))
                    } else {
                        None
                    }
                });

                let mut staged_sync = stagedsync::StagedSync::new();
                staged_sync.set_min_progress_to_commit_after_stage(if opt.prune {
                    u64::MAX
                } else {
                    1024
                });
                if opt.prune {
                    staged_sync.set_pruning_interval(90_000);
                }
                staged_sync.set_max_block(opt.max_block);
                staged_sync.start_with_unwind(opt.start_with_unwind);
                staged_sync.set_exit_after_sync(opt.exit_after_sync);

                if opt.delay_after_sync > 0 {
                    staged_sync
                        .set_delay_after_sync(Some(Duration::from_millis(opt.delay_after_sync)));
                }

                // init consensus init params
                let params = match chainspec_arc_stage_lock.consensus.seal_verification {
                    SealVerificationParams::Parlia { .. } => {
                        if !can_mine_arc_stage.lock().unwrap().clone() {
                            InitialParams::Useless
                        } else {
                            InitialParams::Parlia(ParliaInitialParams {
                                bls_prv_key: opt.bls_secret_key,
                                bls_pub_key: opt.bls_public_key,
                                node: Some(Arc::clone(&node_stage.lock().unwrap())),
                                sync_stage: Some(staged_sync.current_stage()),
                            })
                        }
                    }
                    _ => InitialParams::Useless,
                };

                let consensus: Arc<dyn Consensus> = engine_factory(
                    Some(db_full_back.clone()),
                    chainspec_arc_stage_lock.clone(),
                    Some(opt.engine_listen_address),
                    params.clone(),
                )?
                .into();

                let tip_discovery =
                    !matches!(consensus.fork_choice_mode(), ForkChoiceMode::External(_));

                tokio::spawn({
                    let node = node_stage.lock().unwrap().clone();
                    async move {
                        node.start_sync(tip_discovery).await.unwrap();
                    }
                });

                let node_stage_lock = node_stage.lock().unwrap();
                staged_sync.push(
                    HeaderDownload {
                        node: node_stage_lock.clone(),
                        consensus: consensus.clone(),
                        max_block: opt.max_block.unwrap_or_else(|| u64::MAX.into()),
                        increment,
                    },
                    false,
                );
                staged_sync.push(TotalGasIndex, false);

                let etl_dir_full_arc_lock = etl_dir_full_arc.lock().unwrap();
                staged_sync.push(
                    BlockHashes {
                        temp_dir: etl_dir_full_arc_lock.clone(),
                    },
                    false,
                );
                staged_sync.push(
                    BodyDownload {
                        node: node_stage_lock.clone(),
                        consensus,
                    },
                    false,
                );
                staged_sync.push(TotalTxIndex, false);
                staged_sync.push(
                    SenderRecovery {
                        batch_size: opt.sender_recovery_batch_size.try_into().unwrap(),
                    },
                    false,
                );
                staged_sync.push(
                    Execution {
                        max_block: opt.max_block,
                        batch_size: opt.execution_batch_size.saturating_mul(1_000_000_000_u64),
                        history_batch_size: opt
                            .execution_history_batch_size
                            .saturating_mul(1_000_000_000_u64),
                        exit_after_batch: opt.execution_exit_after_batch,
                        batch_until: None,
                        commit_every: None,
                    },
                    false,
                );
                if !opt.skip_commitment {
                    staged_sync.push(
                        HashState::new(etl_dir_full_arc_lock.clone(), None),
                        !opt.prune,
                    );
                    staged_sync.push_with_unwind_priority(
                        Interhashes::new(etl_dir_full_arc_lock.clone(), None),
                        !opt.prune,
                        1,
                    );
                }
                staged_sync.push(
                    AccountHistoryIndex {
                        temp_dir: etl_dir_full_arc_lock.clone(),
                        flush_interval: 50_000,
                    },
                    !opt.prune,
                );
                staged_sync.push(
                    StorageHistoryIndex {
                        temp_dir: etl_dir_full_arc_lock.clone(),
                        flush_interval: 50_000,
                    },
                    !opt.prune,
                );
                staged_sync.push(
                    TxLookup {
                        temp_dir: etl_dir_full_arc_lock.clone(),
                    },
                    !opt.prune,
                );

                staged_sync.push(
                    CallTraceIndex {
                        temp_dir: etl_dir_full_arc_lock.clone(),
                        flush_interval: 50_000,
                    },
                    !opt.prune,
                );

                if can_mine_arc_stage.lock().unwrap().clone() {
                    staged_sync.is_mining = true;
                }

                info!("Running staged sync");
                staged_sync.run(&db_full_back).await?;

                if opt.exit_after_sync {
                    Ok(())
                } else {
                    pending().await
                }
            })
        })?
        .join()
        .unwrap_or_else(|e| panic::resume_unwind(e))
}
