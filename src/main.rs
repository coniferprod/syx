use std::path::{
    Path, 
    PathBuf
};
use std::fs;
use std::io::Write;
use std::fmt;
use std::time::{
    SystemTime, 
    UNIX_EPOCH
};
use syxpack::{
    Message, 
    message_count, 
    split_messages, 
    read_file, 
    Manufacturer, 
    find_manufacturer
};
use clap::{
    Parser, 
    Subcommand
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // Identifies the messages in the SysEx file.
    Identify {
        #[arg(short, long)]
        file: PathBuf,
    },

    // Extracts the payload from the SysEx file.
    Extract {
        #[arg(short, long)]
        infile: PathBuf,

        #[arg(short, long)]
        outfile: PathBuf,
    },

    // Splits the SysEx messages in the input file into multiple files.
    Split {
        #[arg(short, long)]
        file: PathBuf,

        #[arg(short, long)]
        verbose: bool,
    },

    // Generates information about sections in the SysEx file.
    Sections {
        #[arg(short, long)]
        file: PathBuf,

    },

    // Receive SysEx messages from stdin in the ReceiveMIDI format.
    Receive {
    },

    // Makes a manufacturer-specific SysEx message for the given manufacturer,
    // with the specified payload.
    Make {
        #[arg(short, long)]
        manufacturer: String,  // either hex ID or name

        #[arg(short, long)]
        payload: String, // hex string (or maybe later @filename)

        #[arg(short, long)]
        outfile: PathBuf,  // name of output file
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Identify { file } => run_identify(file),
        Commands::Extract { infile, outfile } => run_extract(infile, outfile),
        Commands::Split { file, verbose } => run_split(file, *verbose),
        Commands::Sections { file } => run_sections(file),
        Commands::Receive { } => run_receive(),
        Commands::Make { manufacturer, payload, outfile } => run_make(manufacturer, payload, outfile)
    }
}

fn run_identify(file: &PathBuf) {
    if let Some(buffer) = read_file(file) {
        let mut all_messages: Vec<Message> = Vec::new();
        let count = message_count(&buffer);
        if count >= 1 {
            if count == 1 {
                all_messages.push(Message::new(&buffer).ok().unwrap());
            }
            else {
                let messages = split_messages(buffer.to_vec());
                for message in messages {
                    all_messages.push(Message::new(&message).ok().unwrap());
                }
            }
        };

        let mut number = 1;
        for message in all_messages {
            if count > 1 {
                println!("Message {} of {}", number, count);
            }
            identify(&message);
            println!("MD5 digest: {:x}", message.digest());
            println!();
            number += 1;
        }
    }
}

fn identify(message: &Message) {
    match message {
        Message::ManufacturerSpecific { manufacturer, payload } => {
            println!("Manufacturer\n  Identifier: {}\n  Name: {}\n  Group: {}\nPayload: {} bytes",
                hex::encode(manufacturer.to_bytes()),
                manufacturer, manufacturer.group(), payload.len());
        },
        Message::Universal { kind, target, sub_id1, sub_id2, payload } => {
            println!("Universal, kind: {}, target: {}, Sub ID1: {:X} Sub ID2: {:X} Payload: {} bytes",
                kind, target, sub_id1, sub_id2, payload.len());
        },
    }
}

fn run_extract(infile: &PathBuf, outfile: &PathBuf) {
    if let Some(buffer) = read_file(infile) {
        if message_count(&buffer) > 1 {
            println!("More than one System Exclusive message found in file. Please use `syx split` to separate them.");
        }
        else {
            match Message::new(&buffer) {
                // At this point, the SysEx delimiters and the manufacturer byte(s)
                // have already been stripped off. What's left is the payload.
                // For example, if the original message was "F0 42 30 28 54 02 ... 5C F7",
                // then the payload is "30 28 54 02 ... 5C".
                Ok(Message::ManufacturerSpecific { payload, .. })
                | Ok(Message::Universal { payload, .. }) => {
                    let mut f = fs::File::create(&outfile).expect("create file");
                    f.write_all(&payload).expect("write to output file");
                },
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                }
            };
        }
    }
}

fn run_split(file: &PathBuf, verbose: bool) {
    if let Some(buffer) = read_file(file) {
        let count = message_count(&buffer);

        if verbose {
            if count == 1 {
                println!("Found one message");
            }
            else {
                println!("Found {} messages", count);
            }
        }

        if count > 1 {
            let messages = split_messages(buffer.to_vec());
            for (i, message) in messages.iter().enumerate() {
                let output_filename = format!(
                    "{}-{:0>3}.{}",
                    file.file_stem().unwrap().to_str().unwrap(),
                    i + 1,
                    file.extension().unwrap().to_str().unwrap());
                if verbose {
                    println!("Writing {}", output_filename);
                }
                let mut file = fs::File::create(output_filename)
                    .expect("unable to create file");
                file.write_all(message).expect("unable to write file");
            }
        }
    }
}

enum SectionKind {
    Initiator,
    Manufacturer,
    Universal,
    Payload,
    Terminator,
}

impl fmt::Display for SectionKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match self {
            SectionKind::Initiator => "Message initiator",
            SectionKind::Manufacturer => "Manufacturer identifier",
            SectionKind::Universal => "Universal message identifier",
            SectionKind::Payload => "Message payload",
            SectionKind::Terminator => "Message terminator"
        })
    }
}

struct MessageSection {
    kind: SectionKind,
    name: String,
    offset: usize,  // offset from message start
    length: usize,  // length of section in bytes
}

fn run_sections(file: &PathBuf) {
    if let Some(buffer) = read_file(file) {
        if message_count(&buffer) > 1 {
            println!("More than one System Exclusive message found in file. Please use `syx split` to separate them.");
            std::process::exit(1);
        }

        let message = Message::new(&buffer);
        let mut offset = 0;

        let mut sections: Vec<MessageSection> = Vec::new();

        sections.push(
            MessageSection {
                kind: SectionKind::Initiator,
                name: "System Exclusive Initiator".to_string(),
                offset: offset,
                length: 1,
            }
        );

        offset += 1;

        match message {
            Ok(Message::ManufacturerSpecific { manufacturer, payload }) => {
                sections.push(
                    MessageSection {
                        kind: SectionKind::Manufacturer,
                        name: "Manufacturer".to_string(),
                        offset: offset,
                        length: manufacturer.to_bytes().len(),
                    }
                );
                offset += manufacturer.to_bytes().len();
                sections.push(
                    MessageSection {
                        kind: SectionKind::Payload,
                        name: "Message Payload".to_string(),
                        offset: offset,
                        length: payload.len(),
                    }
                )
            },
            Ok(Message::Universal { kind, target, sub_id1, sub_id2, payload }) => {
                sections.push(
                    MessageSection {
                        kind: SectionKind::Universal,
                        name: "Universal".to_string(),
                        offset: offset,
                        length: 3,
                    }
                );

                println!("Universal, kind: {}, target: {}, {:X} {:X}, payload = {} bytes",
                    kind,
                    target,
                    sub_id1, sub_id2, payload.len());
            },
            Err(e) => {
                println!("Error in message: {:?}", e);
            }
        }

        sections.push(
            MessageSection {
                kind: SectionKind::Terminator,
                name: "System Exclusive Terminator".to_string(),
                offset: buffer.len() - 1,
                length: 1,
            }
        );

        for section in sections {
            println!("{:06X}: {} ({}, {} {})", 
                section.offset, 
                section.name, 
                section.kind, 
                section.length,
                if section.length == 1 { "byte" } else { "bytes" });
        }
    }
}

fn run_receive() {
    loop {
        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(len) => if len == 0 {
                return;
            }
            else {
                let parts: Vec<&str> = input.split_whitespace().collect();

                // We want at least "system-exclusive", "hex" or "dec", and one byte
                if parts.len() < 3 {
                    continue;
                }

                // Only deal with SysEx:
                if parts[0] == "system-exclusive" {
                    // Get the base of the byte strings.
                    let base = if parts[1] == "hex" { 16 } else { 10 };

                    let mut data: Vec<u8> = Vec::new();

                    for part in &parts[2..] {
                        match u8::from_str_radix(part, base) {
                            Ok(b) => data.push(b),
                            Err(_) => {
                                //eprintln!("Error in byte string '{}': {}", part, e);
                                continue;
                            }
                        }
                    }

                    // Add the MIDI System Exclusive delimiters:
                    data.insert(0, 0xf0);
                    data.push(0xf7);

                    println!("Received {} bytes of System Exclusive data", data.len());

                    // Write the data into a file named by the current timestamp.
                    let now = SystemTime::now();
                    let epoch_now = now
                        .duration_since(UNIX_EPOCH)
                        .expect("System time should be after Unix epoch");
                    let filename = format!("{:?}.syx", epoch_now.as_secs());
                    let path = Path::new(&filename);
                    let display = path.display();
                    let mut file = match fs::File::create(&path) {
                        Err(why) => panic!("couldn't create {}: {}", display, why),
                        Ok(file) => file,
                    };

                    match file.write_all(&data) {
                        Err(why) => panic!("couldn't write to {}: {}", display, why),
                        Ok(_) => { },
                    }
                }
            },
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    }
}

fn run_make(manufacturer: &String, payload: &String, outfile: &PathBuf) {
    match manufacturer.chars().nth(0).unwrap() {
        '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' => {
            if manufacturer.starts_with("00") {  // must be an extended identifier
                if manufacturer.len() != 6 {
                    eprintln!("Extended manufacturer ID must have six digits, like '002109'");
                    std::process::exit(1);
                }
            }
            else {
                if manufacturer.len() != 2 {
                    eprintln!("Standard manufacturer ID must have two digits, like '42'");
                    std::process::exit(1);
                }
            }

            // Now we have a string of potential hex digits, length 2 or 6.
            // Try to split it into a vector, so that we can make a SysEx message.
            match hex::decode(manufacturer) {
                Ok(manuf_bytes) => {
                    let manuf = Manufacturer::new(manuf_bytes).unwrap();

                    match hex::decode(payload) {
                        Ok(payload_bytes) => {
                            let message = Message::ManufacturerSpecific { manufacturer: manuf, payload: payload_bytes };
                            let mut f = fs::File::create(&outfile).expect("create file");
                            f.write_all(&message.to_bytes()).expect("write to output file");
                        }
                        Err(e) => {
                            eprintln!("{}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }

        }
        _ => {  // ordinary text string, possibly a manufacturer name (or the start of one)
            match find_manufacturer(&manufacturer) {
                Ok(manuf) => {
                    match hex::decode(payload) {
                        Ok(payload_bytes) => {
                            let message = Message::ManufacturerSpecific { manufacturer: manuf, payload: payload_bytes };
                            let mut f = fs::File::create(&outfile).expect("create file");
                            f.write_all(&message.to_bytes()).expect("write to output file");
                        }
                        Err(e) => {
                            eprintln!("{}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{:?}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}