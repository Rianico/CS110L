use crate::debugger_command::DebuggerCommand;
use crate::dwarf_data::{self, DwarfData};
use crate::inferior::{Inferior, Status};
use nix::sys::signal::Signal;
use rustyline::error::ReadlineError;
use rustyline::Editor;

use std::collections::HashMap;

pub struct Debugger {
    target: String,
    history_path: String,
    readline: Editor<()>,
    debug_data: DwarfData,
    inferior: Option<Inferior>,
    break_points: HashMap<usize, BreakPoint>,
}

#[derive(Debug)]
pub struct BreakPoint {
    origin_byte: u8,
}

impl BreakPoint {
    pub fn store_origin_byte<T: Into<u8>>(&mut self, value: T) {
        self.origin_byte = value.into();
    }
}

type DwarfError = dwarf_data::Error;
const MAIN_FUNC: &str = "main";

impl Debugger {
    /// Initializes the debugger.
    pub fn new(target: &str) -> Debugger {
        // TODO (milestone 3): initialize the DwarfData

        let history_path = format!("{}/.deet_history", std::env::var("HOME").unwrap());
        let mut readline = Editor::<()>::new();
        let debug_data = match DwarfData::from_file(target) {
            Ok(val) => val,
            Err(DwarfError::ErrorOpeningFile) => {
                println!("Could not open file {}", target);
                std::process::exit(1);
            }
            Err(DwarfError::DwarfFormatError(err)) => {
                println!("Could not debugging symbols from {}: {:?}", target, err);
                std::process::exit(1);
            }
        };
        // Attempt to load history from ~/.deet_history if it exists
        let _ = readline.load_history(&history_path);
        let break_points = HashMap::new();

        Debugger {
            target: target.to_string(),
            history_path,
            readline,
            debug_data,
            inferior: None,
            break_points,
        }
    }

    pub fn run(&mut self) {
        self.debug_data.print();
        loop {
            match self.get_next_command() {
                DebuggerCommand::Run(args) => {
                    if self.inferior.is_some() {
                        let _ = self.inferior.as_ref().unwrap().kill();
                    }
                    let Some(inferior) = Inferior::new(&self.target, &args) else {
                        println!("Error starting subprocess");
                        continue;
                    };
                    self.inferior = Some(inferior);
                    let inferior = self.inferior.as_mut().unwrap();
                    inferior.setup_break_points(&mut self.break_points);
                    match inferior.cont() {
                        Ok(Status::Stopped(_, addr)) => {
                            self.print_stop_location(addr - 1);
                        }
                        _ => continue,
                    }
                }
                DebuggerCommand::CONT => {
                    let Some(ref mut inferior_mut) = self.inferior else {
                        println!("No running process.");
                        continue;
                    };
                    match inferior_mut.cont() {
                        Ok(Status::Stopped(Signal::SIGTRAP, addr)) => {
                            let int_inst_addr = addr - 1;
                            let Some(break_point) = self.break_points.get(&int_inst_addr) else {
                                panic!(
                                    "Can't find the break point info by address key: {:#0x}'",
                                    int_inst_addr
                                );
                            };
                            let _ = inferior_mut
                                .recover_origin_byte(int_inst_addr, break_point.origin_byte);
                            let _ = inferior_mut.rewind_intr_rip();
                            let Ok(Status::Stopped(Signal::SIGTRAP, _)) =
                                inferior_mut.single_step()
                            else {
                                panic!("Run single step fail for break point {:?}", break_point);
                            };
                            let _ = inferior_mut.setup_int_inst(int_inst_addr);
                            self.print_stop_location(int_inst_addr);
                        }
                        _ => {}
                    }
                }
                DebuggerCommand::BACKSTRACE => {
                    let inferior_ref = self.inferior.as_ref().unwrap();
                    let mut frame_rip = inferior_ref.rip().unwrap();
                    let mut frame_rbp = inferior_ref.rbp().unwrap();
                    loop {
                        if self.print_func_name_line(frame_rip) == MAIN_FUNC {
                            break;
                        }
                        frame_rip = inferior_ref
                            .read_mem_content(unsafe { (frame_rbp as *mut usize).add(1) } as usize)
                            .unwrap();
                        frame_rbp = inferior_ref.read_mem_content(frame_rbp).unwrap();
                    }
                }
                DebuggerCommand::BREAKPOINT(point) => {
                    let Some(hex_addr) = self.parse_address(&point) else {
                        eprintln!("Set up break point {} failed.", point);
                        continue;
                    };
                    println!(
                        "Set breakpoint {} at {:#0x}",
                        self.break_points.len(),
                        hex_addr
                    );
                    self.break_points.insert(
                        hex_addr,
                        BreakPoint {
                            origin_byte: u8::default(),
                        },
                    );
                }

                DebuggerCommand::Quit => {
                    return;
                }
            }
        }
    }
    /// This function prompts the user to enter a command, and continues re-prompting until the user
    /// enters a valid command. It uses DebuggerCommand::from_tokens to do the command parsing.
    ///
    /// You don't need to read, understand, or modify this function.
    fn get_next_command(&mut self) -> DebuggerCommand {
        loop {
            // Print prompt and get next line of user input
            match self.readline.readline("(deet) ") {
                Err(ReadlineError::Interrupted) => {
                    // User pressed ctrl+c. We're going to ignore it
                    println!("Type \"quit\" to exit");
                }
                Err(ReadlineError::Eof) => {
                    // User pressed ctrl+d, which is the equivalent of "quit" for our purposes
                    return DebuggerCommand::Quit;
                }
                Err(err) => {
                    panic!("Unexpected I/O error: {:?}", err);
                }
                Ok(line) => {
                    if line.trim().len() == 0 {
                        continue;
                    }
                    self.readline.add_history_entry(line.as_str());
                    if let Err(err) = self.readline.save_history(&self.history_path) {
                        println!(
                            "Warning: failed to save history file at {}: {}",
                            self.history_path, err
                        );
                    }
                    let tokens: Vec<&str> = line.split_whitespace().collect();
                    if let Some(cmd) = DebuggerCommand::from_tokens(&tokens) {
                        return cmd;
                    } else {
                        println!("Unrecognized command.");
                    }
                }
            }
        }
    }

    fn print_func_name_line(&self, addr: usize) -> String {
        let func = self
            .debug_data
            .get_function_from_addr(addr)
            .expect("get func name error.");
        let line = self
            .debug_data
            .get_line_from_addr(addr)
            .expect("get line number error.");
        println!("{} ({})", func, line);
        func
    }

    fn parse_address(&self, addr: &str) -> Option<usize> {
        let addr_without_0x = if addr.to_lowercase().starts_with("0x") {
            &addr[2..]
        } else if addr.to_lowercase().starts_with("*0x") {
            &addr[3..]
        } else {
            println!("line: {}", addr);
            return self
                .debug_data
                .get_addr_for_line(None, addr.parse::<usize>().ok()?);
        };
        usize::from_str_radix(addr_without_0x, 16).ok()
    }

    fn print_stop_location(&self, addr: usize) {
        let line = self.debug_data.get_line_from_addr(addr).unwrap();
        println!(
            "Stopped at file {}:{} address: {:#0x}",
            line.file, line.number, line.address
        );
    }
}
