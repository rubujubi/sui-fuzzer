use bichannel::Channel;
#[cfg(feature = "aptos")]
use move_package::BuildConfig;
#[cfg(feature = "sui")]
use sui_move_build::BuildConfig;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;
use time::Duration;
use crate::fuzzer::config::Config;
use crate::fuzzer::coverage::Coverage;
use crate::fuzzer::stats::Stats;
use crate::mutator::types::Parameters;
use crate::mutator::types::Type;
use crate::runner::runner::Runner;
use crate::ui::ui::{Ui, UiEvent, UiEventData};
use crate::worker::stateful_worker::StatefulWorker;
use crate::AvailableDetector;
// Sui specific imports
use crate::mutator::sui_mutator::SuiMutator;
use crate::worker::worker::Worker;
use crate::worker::worker::WorkerEvent;
use crate::worker::stateless_worker::StatelessWorker;
#[cfg(feature = "sui")]
use crate::runner::stateful_runner::sui_runner::SuiRunner as StatefulSuiRunner;
#[cfg(feature = "sui")]
use crate::runner::stateless_runner::sui_runner::SuiRunner as StatelessSuiRunner;
#[cfg(feature = "aptos")]
use crate::runner::stateful_runner::aptos_runner::AptosRunner as StatefulAptosRunner;
#[cfg(feature = "aptos")]
use crate::runner::stateless_runner::aptos_runner::StatelessAptosRunner;
use crate::runner::chain::Chain;
use super::crash::Crash;
use super::fuzzer_utils::load_corpus;
use super::fuzzer_utils::load_crashes;
use super::fuzzer_utils::write_corpusfile;
use super::fuzzer_utils::write_crashfile;
use move_package::compilation::compiled_package::CompiledPackage;
use move_package::compilation::compiled_package::CompiledUnitWithSource;

pub struct Fuzzer {
    // Fuzzer configuration
    config: Config,
    // Thread specific stats
    threads_stats: Vec<Arc<RwLock<Stats>>>,
    // Channel to communicate with each threads
    channels: Vec<Channel<WorkerEvent, WorkerEvent>>,
    // Global stats mostly for ui
    global_stats: Stats,
    // Global coverage
    coverage_set: HashSet<Coverage>,
    // Unique crashes set
    unique_crashes_set: HashSet<Crash>,
    // The user interface
    ui: Option<Ui>,
    // The function to target in the contract
    target_module: String,
    // The function to target in the contract (stateless)
    target_function: Option<String>,
    // The functions to target in the contract (stateful)
    target_functions: Option<Vec<String>>,
    // Parameters of the target function
    target_parameters: Vec<Type>,
    // Max coverage
    max_coverage: usize,
    // Activated detectors
    detectors: Option<Vec<AvailableDetector>>,
    // Whether the fuzzer should use stateful fuzzing or not
    use_state: bool,
}

impl Fuzzer {
    pub fn new_stateless(
        config: Config,
        target_module: &str,
        target_function: &str,
        detectors: Option<&Vec<AvailableDetector>>,
    ) -> Self {
        let nb_threads = config.nb_threads;
        let ui = if config.use_ui {
            Some(Ui::new(nb_threads, config.seed.unwrap()))
        } else {
            None
        };
        let coverage_set = load_corpus(&config.corpus_dir).unwrap_or_default();
        let unique_crashes_set = load_crashes(&config.crashes_dir).unwrap_or_default();
        Fuzzer {
            config,
            threads_stats: vec![],
            channels: vec![],
            global_stats: Stats::new(),
            coverage_set,
            unique_crashes_set,
            ui,
            target_module: String::from(target_module),
            target_function: Some(String::from(target_function)),
            target_functions:None,
            target_parameters: vec![],
            max_coverage: 0,
            detectors: detectors.cloned(),
            use_state: false,
        }
    }

    pub fn new_stateful(
        config: Config,
        target_module: &str,
        target_functions: &Vec<String>,
        detectors: Option<&Vec<AvailableDetector>>,
    ) -> Self {
        let nb_threads = config.nb_threads;
        let ui = if config.use_ui {
            Some(Ui::new(nb_threads, config.seed.unwrap()))
        } else {
            None
        };
        // corpus - A set of interesting test inputs (Not used in the context of sui stateful fuzzer)
        let coverage_set = load_corpus(&config.corpus_dir).unwrap_or_default();
        let unique_crashes_set = load_crashes(&config.crashes_dir).unwrap_or_default();
        Fuzzer {
            config,
            threads_stats: vec![],
            channels: vec![],
            global_stats: Stats::new(),
            coverage_set,
            unique_crashes_set,
            ui,
            target_module: String::from(target_module),
            target_function: None,
            target_functions: Some(target_functions.clone()),
            target_parameters: vec![],
            max_coverage: 0,
            detectors: detectors.cloned(),
            use_state: true,
        }
    }

    fn start_stateless_threads(&mut self) {
        for i in 0..self.config.nb_threads {
            // Creates the communication channel for the fuzzer and worker sides
            let (fuzzer, worker) = bichannel::channel::<WorkerEvent, WorkerEvent>();
            self.channels.push(fuzzer);
            let stats = Arc::new(RwLock::new(Stats::new()));
            self.threads_stats.push(stats.clone());
            // Change here the runner you want to create
            if let Some(parameter) = &self.config.contract {
                // Chain is determined at compile time
                #[cfg(feature = "sui")]
                let chain = Chain::Sui;
                #[cfg(feature = "aptos")]
                let chain = Chain::Aptos;
                let runner: Box<dyn Runner> = match chain {
                    #[cfg(feature = "sui")]
                    Chain::Sui => Box::new(StatelessSuiRunner::new(
                        &parameter.clone(),
                        &self.target_module,
                        &self.target_function.clone().unwrap(),
                    )),
                    #[cfg(feature = "aptos")]
                    Chain::Aptos => {
                        let modules = Self::build_test_modules(
                            self.config.contract.as_ref().unwrap()
                        );

                        Box::new(StatelessAptosRunner::new(
                            self.config.contract.as_ref().unwrap(),
                            &self.target_module,
                            &self.target_function.clone().unwrap(),
                            modules,
                        ))
                    },
                    #[cfg(not(feature = "sui"))]
                    Chain::Sui => unreachable!("Sui feature not enabled"),
                    #[cfg(not(feature = "aptos"))]
                    Chain::Aptos => unreachable!("Aptos feature not enabled"),
                };
                self.target_parameters = runner.get_target_parameters();
                self.max_coverage = runner.get_max_coverage();
                // Increment seed so that each worker doesn't do the same thing
                let seed = self.config.seed.unwrap() + (i as u64);
                let execs_before_cov_update = self.config.execs_before_cov_update;
                let mutator = Box::new(SuiMutator::new(seed, 12));
                let detectors = self.detectors.clone();
                let coverage_set = self.coverage_set.clone();
                let _ = std::thread::Builder::new()
                    .name(format!("Worker {}", i).to_string())
                    .spawn(move || {
                        // Install panic hook for this thread
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            // Creates generic worker and starts it
                            let mut w = Box::new(StatelessWorker::new(
                                    worker,
                                    stats,
                                    coverage_set,
                                    runner,
                                    mutator,
                                    seed,
                                    execs_before_cov_update,
                                    detectors,
                                ));
                            w.run();
                        }));
                        if let Err(e) = result {
                            eprintln!("Worker thread panicked: {:?}", e);
                        }
                    });
            }
        }
    }

    #[cfg(feature = "sui")]
    fn build_test_modules(test_dir: &str) -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.extend([test_dir]);
        let with_unpublished_deps = false;
        let config = BuildConfig::new_for_testing();
        let package = config.build(path).unwrap();
        (
            package.get_package_digest(with_unpublished_deps).to_vec(),
            package.get_package_bytes(with_unpublished_deps),
        )
    }
    #[cfg(feature = "aptos")]
    fn build_test_modules(test_dir: &str) -> Vec<Vec<u8>> {
        // Locate to contract source files
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(test_dir);

        println!("Attempting to compile package at: {:?}", path);

        // Check if path exists
        if !path.exists() {
            eprintln!("ERROR: Contract path does not exist: {:?}", path);
            eprintln!("Please check your config file's 'contract' field");
            std::process::exit(1);
        }

        // Set up config for resolution graph (will be consumed)
        // Use Move 2.1 to support l1-migration framework features like += and -=
        let mut resolution_config = BuildConfig {
            test_mode: true,
            install_dir: None,
            generate_docs: false,
            ..Default::default()
        };
        resolution_config.compiler_config.compiler_version = Some(move_model::metadata::CompilerVersion::V2_1);
        resolution_config.compiler_config.language_version = Some(move_model::metadata::LanguageVersion::V2_1);

        // Set up config for compilation (will be consumed separately)
        let mut compile_config = BuildConfig {
            test_mode: true,
            install_dir: None,
            generate_docs: false,
            ..Default::default()
        };
        compile_config.compiler_config.compiler_version = Some(move_model::metadata::CompilerVersion::V2_1);
        compile_config.compiler_config.language_version = Some(move_model::metadata::LanguageVersion::V2_1);

        println!("Starting compilation...");
        let mut error_buffer = Vec::new();

        // First create resolution graph (consumes resolution_config)
        let resolution_graph = resolution_config
            .resolution_graph_for_package(&path, &mut std::io::stderr())
            .expect("Failed to create resolution graph");

        // Then compile with resolution graph (consumes compile_config)
        let compilation_result = compile_config.compile_package_no_exit(
            resolution_graph,
            vec![], // No external checks
            &mut error_buffer
        );

        match &compilation_result {
            Ok(_) => println!("Compilation successful!"),
            Err(e) => {
                eprintln!("\n=== COMPILATION FAILED ===");
                eprintln!("Error: {:?}", e);
                if !error_buffer.is_empty() {
                    eprintln!("\nDetailed error output:");
                    eprintln!("{}", String::from_utf8_lossy(&error_buffer));
                }
                eprintln!("\nPlease fix the compilation errors in your Move package before fuzzing.");
                std::process::exit(1);
            }
        }

        #[cfg(feature= "sui")]
        let compiled_pkg: CompiledPackage= compilation_result.unwrap();

        #[cfg(feature= "aptos")]
        let (compiled_pkg, _global_env) = compilation_result.unwrap();
        let modules: Vec<Vec<u8>> = compiled_pkg
            .root_modules()
            .map(|unit: &CompiledUnitWithSource| {
                unit.unit.serialize(None)
            })
            .collect();

        modules
    }
    fn start_stateful_threads(&mut self) {

        #[cfg(feature = "sui")]
        let (_, modules) = Self::build_test_modules(self.config.contract.as_ref().unwrap());
        /*
          compiles Move contracts from source code and returns bytecode in modules
         */
        #[cfg(feature = "aptos")]
        let modules = Self::build_test_modules(self.config.contract.as_ref().unwrap());

        for i in 0..self.config.nb_threads {
            // Creates the communication channel for the fuzzer and worker sides
            let (fuzzer, worker) = bichannel::channel::<WorkerEvent, WorkerEvent>();
            self.channels.push(fuzzer);
            let stats = Arc::new(RwLock::new(Stats::new()));
            self.threads_stats.push(stats.clone());
            // Change here the runner you want to create
            // Chain is determined at compile time
            #[cfg(feature = "sui")]
            let chain = Chain::Sui;
            #[cfg(feature = "aptos")]
            let chain = Chain::Aptos;
            let runner: Box<dyn crate::runner::runner::StatefulRunner> = match chain {
                #[cfg(feature = "sui")]
                Chain::Sui => Box::new(StatefulSuiRunner::new(
                    &self.target_module,
                    modules.clone(),
                )),
                #[cfg(feature = "aptos")]
                Chain::Aptos => {
                    Box::new(StatefulAptosRunner::new(
                        &self.target_module,
                        modules.clone(),
                    ))
                },
                #[cfg(not(feature = "sui"))]
                Chain::Sui => unreachable!("Sui feature not enabled"),
                #[cfg(not(feature = "aptos"))]
                Chain::Aptos => unreachable!("Aptos feature not enabled"),
            };
            self.max_coverage = runner.get_max_coverage();
            // Increment seed so that each worker doesn't do the same thing
            let seed = self.config.seed.unwrap() + (i as u64);
            let execs_before_cov_update = self.config.execs_before_cov_update;
            /* TODO:
            Currently addded gas based logic inside SuiMutator. In the future it should be separated into AptosMutator instead of reusing SuiMutator
             */
            let mutator = Box::new(SuiMutator::new(seed, 12));
            let detectors = self.detectors.clone();
            let coverage_set = self.coverage_set.clone();
            let target_module = self.target_module.clone();
            let target_functions = self.target_functions.clone().unwrap();
            let fuzz_prefix = self.config.fuzz_functions_prefix .clone();
            let contract = self.config.contract.clone().unwrap();
            let max_call_sequence_size = self.config.max_call_sequence_size;
            let _ = std::thread::Builder::new()
                .name(format!("Worker {}", i).to_string())
                .spawn(move || {
                    // Creates generic worker and starts it
                    let mut w = Box::new(StatefulWorker::new(
                            &contract,
                            worker,
                            stats,
                            coverage_set,
                            runner,
                            mutator,
                            execs_before_cov_update,
                            seed,
                            detectors,
                            &target_module,
                            target_functions,
                            fuzz_prefix,
                            max_call_sequence_size
                        ));
                    w.run();
                });
            }
    }

    fn get_global_execs(&self) -> u64 {
        let mut sum: u64 = 0;
        for i in 0..self.config.nb_threads {
            sum += self.threads_stats[i as usize].read().unwrap().execs;
        }
        sum
    }

    fn get_global_crashes(&self) -> u64 {
        let mut sum: u64 = 0;
        for i in 0..self.config.nb_threads {
            sum += self.threads_stats[i as usize].read().unwrap().crashes;
        }
        sum
    }

    fn broadcast(&self, event: &WorkerEvent) {
        for chan in &self.channels {
            chan.send(event.to_owned()).unwrap();
        }
    }

    fn update_ui(&mut self) {
        if let Some(ui) = &mut self.ui {
            if self.use_state {
                ui.set_target_infos(
                    &self.target_module,
                    &self.target_functions.clone().unwrap().join(", "),
                    &self.target_parameters,
                    self.max_coverage,
                );
            } else {
                ui.set_target_infos(
                    &self.target_module,
                    &self.target_function.clone().unwrap(),
                    &self.target_parameters,
                    self.max_coverage,
                );
            }
        }
    }

    pub fn run(&mut self) {
        // Init workers
        if self.use_state {
            self.start_stateful_threads();
        } else {
            self.start_stateless_threads();
        }

        // Utils for execs per sec
        let mut execs_per_sec_timer = Instant::now();
        // Timer for status line printing (print every 2 seconds)
        let mut status_print_timer = Instant::now();

        let mut events = VecDeque::new();

        let mut new_crash: Option<Crash> = None;

        // Create events for loaded corpus
        for c in self.coverage_set.iter() {
            events.push_front(UiEvent::NewCoverage(UiEventData {
                time: Duration::new(0, 0),
                message: format!("{} - loaded from corpus directory", Parameters(c.inputs.clone())),
                error: None,
            }));
        }

        loop {

            // Update ui infos
            self.update_ui();

            // Sum execs
            self.global_stats.execs = self.get_global_execs();
            self.global_stats.crashes = self.get_global_crashes();

            // Calculate execs_per_sec
            if execs_per_sec_timer.elapsed().as_secs() >= 1 {
                execs_per_sec_timer = Instant::now();
                self.global_stats.execs_per_sec = self.global_stats.execs;
                self.global_stats.time_running += 1;
                self.global_stats.secs_since_last_cov += 1;
                self.global_stats.execs_per_sec =
                    self.global_stats.execs_per_sec / self.global_stats.time_running;
            }

            // Checks channels for new data
            for chan in &self.channels {
                if let Ok(event) = chan.try_recv() {
                    // Creates duration used for the ui
                    let duration =
                        Duration::seconds(self.global_stats.time_running.try_into().unwrap());
                    match event {
                        WorkerEvent::CoverageUpdateRequest(coverage_set) => {
                            // Gets diffrences between the two coverage sets
                            let binding = self.coverage_set.clone();
                            let differences_with_main_thread: HashSet<_> =
                                self.coverage_set.difference(&coverage_set).collect();
                            let differences_with_worker: HashSet<_> =
                                coverage_set.difference(&binding).collect();
                            let mut tmp = HashSet::new();
                            for diff in &differences_with_main_thread.clone() {
                                tmp.insert(diff.to_owned().clone());
                            }
                            // Updates sets
                            if differences_with_main_thread.len() > 0 {
                                chan.send(WorkerEvent::CoverageUpdateResponse(tmp)).unwrap();
                            }
                            // Adds all the coverage to the main coverage_set
                            for diff in &differences_with_worker {
                                if !self.coverage_set.contains(diff) {
                                    write_corpusfile(&self.config.corpus_dir, &diff);
                                    self.coverage_set.insert(diff.to_owned().clone());
                                    self.global_stats.secs_since_last_cov = 0;
                                    self.global_stats.coverage_size += 1;
                                    events.push_front(UiEvent::NewCoverage(UiEventData {
                                        time: duration,
                                        message: format!("{}", Parameters(diff.inputs.clone())),
                                        error: None,
                                    }));
                                }
                            }
                        }
                        WorkerEvent::NewCrash(target_function, inputs, error) => {
                            let crash = Crash::new(&self.target_module, &target_function, &inputs, &error);
                            let mut message = format!("{} - already exists, skipping", Parameters(inputs.clone()));
                            if !self.unique_crashes_set.contains(&crash) {
                                write_crashfile(&self.config.crashes_dir, crash.clone());
                                self.global_stats.unique_crashes += 1;
                                self.unique_crashes_set.insert(crash.clone());
                                message = format!("{} - NEW", Parameters(inputs));
                                new_crash = Some(crash);
                            }
                            if self.use_state == false || !message.ends_with("skipping") {
                                events.push_front(UiEvent::NewCrash(UiEventData {
                                    time: duration,
                                    message,
                                    error: Some(error),
                                }));
                            }
                        }
                        WorkerEvent::DetectorTriggered(detector, message) => {
                            let mut final_message = format!("{:?}", detector);
                            if let Some(m) = message {
                                final_message = format!("{:?} -> {}", detector, m);
                            }
                            events.push_front(UiEvent::DetectorTriggered(UiEventData {
                                time: duration,
                                message: final_message,
                                error: None,
                            }));
                        }
                        _ => unimplemented!(),
                    }
                }
            }

            // Broadcasting unique crash to all threads
            if let Some(crash) = &new_crash {
                self.broadcast(&WorkerEvent::NewUniqueCrash(crash.clone()));
                new_crash = None;
            }

            // Run ui
            if self.config.use_ui {
                if self.ui.as_mut().unwrap().render(
                    &self.global_stats,
                    &mut events,
                    &self.threads_stats,
                    &self.detectors,
                    self.use_state
                ) {
                    self.ui.as_mut().unwrap().restore_terminal();
                    eprintln!("Quitting...");
                    break;
                }
            } else {
                for event in events.clone().into_iter() {
                    match event {
                        UiEvent::NewCoverage(data) => println!("New coverage: {}", data.message),
                        UiEvent::NewCrash(data) => {
                            println!("New crash: {} {}", data.error.unwrap(), data.message)
                        }
                        UiEvent::DetectorTriggered(data) => {
                            println!("Detector triggered: {}", data.message)
                        }
                    }
                }
                // Print status every 2 seconds
                if status_print_timer.elapsed().as_secs() >= 2 {
                    status_print_timer = Instant::now();
                    println!("{}s running time | {} execs/s | total execs: {} | crashes: {} | unique crashes: {} | coverage: {}",
                    self.global_stats.time_running,
                    self.global_stats.execs_per_sec,
                    self.global_stats.execs,
                    self.global_stats.crashes,
                    self.global_stats.unique_crashes,
                    self.coverage_set.len());
                }
                events.clear();
            }
        }
    }
}
