#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;

use std::sync::mpsc;

use ceviche::controller::*;
use ceviche::{Service, ServiceEvent};
use clap::App;
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;

static SERVICE_NAME: &str = "foobar";
static DISPLAY_NAME: &str = "FooBar Service";
static DESCRIPTION: &str = "This is the FooBar service";

#[cfg(windows)]
const LOG_PATH: &str = "C:\\Windows\\Temp\\foobar.log";
#[cfg(any(unix, target_os = "macos"))]
const LOG_PATH: &'static str = "/tmp/foobar.log";

enum CustomServiceEvent {}

fn init_logging(standalone_mode: bool) -> Option<()> {
    if standalone_mode {
        let stdout = ConsoleAppender::builder().build();

        let config = Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(LevelFilter::Info))
            .ok()?;

        log4rs::init_config(config).ok()?;
    } else {
        let file_appender = FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new(
                "{d(%Y-%m-%d %H:%M:%S)} {M} [{h({l})}] - {m}{n}",
            )))
            .build(LOG_PATH)
            .ok()?;

        let config = Config::builder()
            .appender(Appender::builder().build("file_appender", Box::new(file_appender)))
            .build(
                Root::builder()
                    .appender("file_appender")
                    .build(LevelFilter::Info),
            )
            .ok()?;

        log4rs::init_config(config).ok()?;
    }
    Some(())
}

fn my_service_main(
    rx: mpsc::Receiver<ServiceEvent<CustomServiceEvent>>,
    _tx: mpsc::Sender<ServiceEvent<CustomServiceEvent>>,
    args: Vec<String>,
    standalone_mode: bool,
) -> u32 {
    init_logging(standalone_mode);
    info!("foobar service started");
    info!("args: {:?}", args);

    loop {
        if let Ok(control_code) = rx.recv() {
            info!("Received control code: {}", control_code);
            if let ServiceEvent::Stop = control_code { break }
        }
    }

    info!("foobar service stopping");
    0
}

Service!("Foobar", my_service_main);

fn main() {
    let yaml = load_yaml!("cli.yml");
    let app = App::from_yaml(yaml);
    let matches = app.version(crate_version!()).get_matches();
    let cmd = matches.value_of("cmd").unwrap_or("").to_string();

    let mut controller = Controller::new(SERVICE_NAME, DISPLAY_NAME, DESCRIPTION);

    match cmd.as_str() {
        "create" => {
            if let Err(e) = controller.create() {
                println!("{}", e);
            }
        }
        "delete" => {
            if let Err(e) = controller.delete() {
                println!("{}", e);
            }
        }
        "start" => {
            if let Err(e) = controller.start() {
                println!("{}", e);
            }
        }
        "stop" => {
            if let Err(e) = controller.stop() {
                println!("{}", e);
            }
        }
        "standalone" => {
            let (tx, rx) = mpsc::channel();
            let _tx = tx.clone();

            ctrlc::set_handler(move || {
                let _ = tx.send(ServiceEvent::Stop);
            }).expect("Failed to register Ctrl-C handler");

            my_service_main(rx, _tx, vec![], true);
        }
        _ => {
            let _result = controller.register(service_main_wrapper);
        }
    }
}
