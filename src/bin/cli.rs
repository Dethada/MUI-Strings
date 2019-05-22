use clap::{Arg, App, crate_version};
use std::fs::File;
use std::io::Read;
use mui_strings::get_strings;

fn main() {
    let matches = App::new("MUI Strings")
                        .version(crate_version!())
                        .author("David Z. <david@dzhy.dev>")
                        .about("Get strings from the resource section of MUI files.")
                        .arg(Arg::with_name("file")
                            .short("f")
                            .long("file")
                            .required(true)
                            .help("The target file")
                            .takes_value(true))
                        .get_matches();

    let file_path = matches.value_of("file").unwrap();

    let mut fd = File::open(file_path).unwrap();
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer).unwrap();
    let text = get_strings(&buffer).unwrap();
    println!("{}", text);
}
